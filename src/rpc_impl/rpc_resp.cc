#include <isa-l_crypto/aes_gcm.h>
#include "rpc.h"

namespace erpc {

// For both foreground and background request handlers, enqueue_response() may
// be called before or after the request handler returns to the event loop, at
// which point the event loop buries the request MsgBuffer.
//
// So sslot->rx_msgbuf may or may not be valid at this point.
template <class TTr>
void Rpc<TTr>::enqueue_response(ReqHandle *req_handle, MsgBuffer *resp_msgbuf) {
  SSlot *sslot = static_cast<SSlot *>(req_handle);
  Session *session = sslot->session;

  // When called from a background thread, enqueue to the foreground thread
  if (unlikely(!in_dispatch())) {
    bg_queues._enqueue_response.unlocked_push(
        enq_resp_args_t(req_handle, resp_msgbuf));
    return;
  }

  // If we're here, we're in the dispatch thread
  sslot->server_info.sav_num_req_pkts = sslot->server_info.req_msgbuf.num_pkts;
  bury_req_msgbuf_server_st(sslot);  // Bury the possibly-dynamic req MsgBuffer

  if (unlikely(!session->is_connected())) {
    // A session reset could be waiting for this enqueue_response()
    assert(session->state == SessionState::kResetInProgress);

    ERPC_WARN("Rpc %u, lsn %u: enqueue_response() while reset in progress.\n",
              rpc_id, session->local_session_num);

    // Mark enqueue_response() as completed
    assert(sslot->server_info.req_type != kInvalidReqType);
    sslot->server_info.req_type = kInvalidReqType;

    return;  // During session reset, don't add packets to TX burst
  }

  // Fill in packet 0's header
  pkthdr_t *resp_pkthdr_0 = resp_msgbuf->get_pkthdr_0();
  resp_pkthdr_0->req_type = sslot->server_info.req_type;
  resp_pkthdr_0->msg_size = resp_msgbuf->data_size;
  resp_pkthdr_0->dest_session_num = session->remote_session_num;
  resp_pkthdr_0->pkt_type = kPktTypeResp;
  resp_pkthdr_0->pkt_num = sslot->server_info.sav_num_req_pkts - 1;
  resp_pkthdr_0->req_num = sslot->cur_req_num;

  // Fill in non-zeroth packet headers, if any
  if (resp_msgbuf->num_pkts > 1) {
    // Headers for non-zeroth packets are created by copying the 0th header, and
    // changing only the required fields.
    for (size_t i = 1; i < resp_msgbuf->num_pkts; i++) {
      pkthdr_t *resp_pkthdr_i = resp_msgbuf->get_pkthdr_n(i);
      *resp_pkthdr_i = *resp_pkthdr_0;
      resp_pkthdr_i->pkt_num = resp_pkthdr_0->pkt_num + i;
    }
  }
#ifdef SECURE
  // After zeroing out the MAC/TAG field in the added pkthdr field,
  // Encrypt the request msgbuffer application data, and copy over
  // the computed MAC into the field
  memset(resp_msgbuf->get_pkthdr_0()->authentication_tag, 0, kMaxTagLen);
  uint8_t *AAD = reinterpret_cast<uint8_t *>(resp_msgbuf->get_last_pkthdr());
  /******* TIMING *******/
  struct timespec tput;
  clock_gettime(CLOCK_REALTIME, &tput);
  aesni_gcm128_enc(&(session->gdata), resp_msgbuf->encrypted_buf,
                   resp_msgbuf->buf, resp_msgbuf->data_size, session->gcm_IV,
                   AAD, resp_msgbuf->num_pkts * sizeof(pkthdr_t),
                   resp_msgbuf->get_pkthdr_0()->authentication_tag, kMaxTagLen);
  ERPC_INFO("     Time for encryption took %lf ns\n", erpc::ns_since(tput));
/******* TIMING *******/
#endif
  // Fill in the slot and reset queueing progress
  assert(sslot->tx_msgbuf == nullptr);  // Buried before calling request handler
  sslot->tx_msgbuf = resp_msgbuf;       // Mark response as valid

  // Mark enqueue_response() as completed
  assert(sslot->server_info.req_type != kInvalidReqType);
  sslot->server_info.req_type = kInvalidReqType;
  enqueue_pkt_tx_burst_st(sslot, 0, nullptr);  // 0 = packet index, not pkt_num
}

template <class TTr>
void Rpc<TTr>::process_resp_one_st(SSlot *sslot, const pkthdr_t *pkthdr,
                                   size_t rx_tsc) {
  assert(in_dispatch());
  assert(pkthdr->req_num <= sslot->cur_req_num);

  // Handle reordering
  if (unlikely(!in_order_client(sslot, pkthdr))) {
    ERPC_REORDER(
        "Rpc %u, lsn %u (%s): Received out-of-order response. "
        "Packet %zu/%zu, sslot %zu/%s. Dropping.\n",
        rpc_id, sslot->session->local_session_num,
        sslot->session->get_remote_hostname().c_str(), pkthdr->req_num,
        pkthdr->pkt_num, sslot->cur_req_num, sslot->progress_str().c_str());
    return;
  }

  auto &ci = sslot->client_info;
  MsgBuffer *resp_msgbuf = ci.resp_msgbuf;

  // Update client tracking metadata
  if (kCcRateComp) update_timely_rate(sslot, pkthdr->pkt_num, rx_tsc);
  bump_credits(sslot->session);
  ci.num_rx++;
  ci.progress_tsc = ev_loop_tsc;

  // Special handling for single-packet responses
  if (likely(pkthdr->msg_size <= TTr::kMaxDataPerPkt)) {
    resize_msg_buffer(resp_msgbuf, pkthdr->msg_size);

#ifdef SECURE
    // Copy eRPC header (but not Transport headroom).
    memcpy(resp_msgbuf->get_pkthdr_0()->ehdrptr(), pkthdr->ehdrptr(),
           sizeof(pkthdr_t) - kHeadroom);
    // Upon receiving the 0th packet, first save the MAC/TAG. Then
    // zero out the MAC/TAG field in the 0th pkthdr, and finally decrypt
    // the encrypted packet into the public buf
    uint8_t received_tag[kMaxTagLen];
    memcpy(received_tag, pkthdr->authentication_tag, kMaxTagLen);
    // Temporarily cast away constantness of pkthdr to reset MAC field
    memset(const_cast<pkthdr_t *>(pkthdr)->authentication_tag, 0, kMaxTagLen);
    uint8_t current_tag[kMaxTagLen];
    uint8_t *AAD = reinterpret_cast<uint8_t *>(const_cast<pkthdr_t *>(pkthdr));
    /******* TIMING *******/
    struct timespec tput;
    clock_gettime(CLOCK_REALTIME, &tput);
    aesni_gcm128_dec(&(sslot->session->gdata), resp_msgbuf->buf,
                     reinterpret_cast<const uint8_t *>(pkthdr + 1),
                     pkthdr->msg_size, sslot->session->gcm_IV, AAD,
                     sizeof(pkthdr_t), current_tag, kMaxTagLen);
    ERPC_INFO("     Time for decryption took %lf ns\n", erpc::ns_since(tput));
    /******* TIMING *******/
    // Reset constantness
    memcpy(const_cast<pkthdr_t *>(pkthdr)->authentication_tag, received_tag,
           kMaxTagLen);
    // Compare the received tag to the current tag to authenticate app data
    assert(memcmp(received_tag, current_tag, kMaxTagLen) == 0);

#else
    // Copy eRPC header and data (but not Transport headroom). The eRPC header
    // will be needed (e.g., to determine the request type) if the continuation
    // runs in a background thread.
    memcpy(resp_msgbuf->get_pkthdr_0()->ehdrptr(), pkthdr->ehdrptr(),
           pkthdr->msg_size + sizeof(pkthdr_t) - kHeadroom);
#endif
    // Fall through to invoke continuation
  } else {
    // This is an in-order response packet. So, we still have the request.
    MsgBuffer *req_msgbuf = sslot->tx_msgbuf;

    if (pkthdr->pkt_num == req_msgbuf->num_pkts - 1) {
      // This is the first response packet. Size the response and copy header.
      resize_msg_buffer(resp_msgbuf, pkthdr->msg_size);
      memcpy(resp_msgbuf->get_pkthdr_0()->ehdrptr(), pkthdr->ehdrptr(),
             sizeof(pkthdr_t) - kHeadroom);
    }

    // Transmit remaining RFRs before response memcpy. We have credits.
    if (ci.num_tx != wire_pkts(req_msgbuf, resp_msgbuf)) kick_rfr_st(sslot);

    // Hdr 0 was copied earlier, other headers are unneeded, so copy just data.
    const size_t pkt_idx = resp_ntoi(pkthdr->pkt_num, req_msgbuf->num_pkts);
#ifdef SECURE
    // Per packet, first save the MAC/TAG. Then zero out the MAC/TAG
    // field in the given pkthdr, and finally decrypt the encrypted
    // pkt into the public buf
    uint8_t received_tag[kMaxTagLen];
    memcpy(received_tag, pkthdr->authentication_tag, kMaxTagLen);
    // Temporarily cast away constantness of pkthdr to reset MAC field
    memset(const_cast<pkthdr_t *>(pkthdr)->authentication_tag, 0, kMaxTagLen);
    uint8_t current_tag[kMaxTagLen];
    uint8_t *AAD = reinterpret_cast<uint8_t *>(const_cast<pkthdr_t *>(pkthdr));
    size_t offset = pkt_idx * TTr::kMaxDataPerPkt;
    size_t length = std::min(TTr::kMaxDataPerPkt, pkthdr->msg_size - offset);
    /******* TIMING *******/
    struct timespec tput;
    clock_gettime(CLOCK_REALTIME, &tput);
    aesni_gcm128_dec(&(sslot->session->gdata), &resp_msgbuf->buf[offset],
                     reinterpret_cast<const uint8_t *>(pkthdr + 1), length,
                     sslot->session->gcm_IV, AAD, sizeof(pkthdr_t), current_tag,
                     kMaxTagLen);
    ERPC_INFO("     Time for decryption took %lf ns\n", erpc::ns_since(tput));
    /******* TIMING *******/
    // Reset constantness
    memcpy(const_cast<pkthdr_t *>(pkthdr)->authentication_tag, received_tag,
           kMaxTagLen);
    // Compare the received tag to the current tag to authenticate app data
    assert(memcmp(received_tag, current_tag, kMaxTagLen) == 0);

#else
    copy_data_to_msgbuf(resp_msgbuf, pkt_idx, pkthdr);
#endif
    if (ci.num_rx != wire_pkts(req_msgbuf, resp_msgbuf)) return;
    // Else fall through to invoke continuation
  }

  // Here, the complete response has been received. All references to sslot must
  // be removed before invalidating it.
  // 1. The TX batch or DMA queue cannot contain a reference because we drain
  //    it after retransmission.
  // 2. The wheel cannot contain a reference because we (a) wait for sslot to
  //    drain from the wheel before retransmitting, and (b) discard spurious
  //    corresponding packets received for packets in the wheel.
  assert(ci.wheel_count == 0);

  sslot->tx_msgbuf = nullptr;  // Mark response as received
  delete_from_active_rpc_list(*sslot);

  // Free-up this sslot, and clear up one request from the backlog if needed.
  // The sslot may get re-used immediately if there's backlog, or later from a
  // request enqueued by a background thread. So, copy-out needed fields.
  const erpc_cont_func_t _cont_func = ci.cont_func;
  void *_tag = ci.tag;
  const size_t _cont_etid = ci.cont_etid;

  Session *session = sslot->session;
  session->client_info.sslot_free_vec.push_back(sslot->index);

  if (!session->client_info.enq_req_backlog.empty()) {
    // We just got a new sslot, and we should have no more if there's backlog
    assert(session->client_info.sslot_free_vec.size() == 1);
    enq_req_args_t &args = session->client_info.enq_req_backlog.front();
    enqueue_request(args.session_num, args.req_type, args.req_msgbuf,
                    args.resp_msgbuf, args.cont_func, args.tag, args.cont_etid);
    session->client_info.enq_req_backlog.pop();
  }

  if (likely(_cont_etid == kInvalidBgETid)) {
    _cont_func(context, _tag);
  } else {
    submit_bg_resp_st(_cont_func, _tag, _cont_etid);
  }
  return;
}

FORCE_COMPILE_TRANSPORTS

}  // namespace erpc
