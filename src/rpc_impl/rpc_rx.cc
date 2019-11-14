#include "rpc.h"

namespace erpc {

#ifdef SECURE
void decrypt_as_batch(int num_pkts) {
  int rounds = (num_pkts / kBatchCryptoSize) + 1;
  struct gcm_data *gdata[kBatchCryptoSize];
  uint8_t *out[kBatchCryptoSize];
  uint8_t const *in[kBatchCryptoSize];
  uint64_t plaintext_len[kBatchCryptoSize];
  uint8_t *iv[kBatchCryptoSize];
  uint8_t const *aad[kBatchCryptoSize];
  uint64_t aad_len[kBatchCryptoSize];
  uint8_t *auth_tag[kBatchCryptoSize];
  uint64_t auth_tag_len[kBatchCryptoSize];
  pkthdr_t encrypted_pkthdr;
  pkthdr_t pkthdr;
  Session *session;
  size_t batch_rx_ring_head = rx_ring_head;
  for (int i = 0; i < rounds; i++) {
    for (int j = 0;
         (j < kBatchCryptoSize) && (j + i * kBatchCryptoSize < num_pkts); j++) {
      encrypted_pkthdr =
          reinterpret_cast<pkthdr_t *>(rx_ring[batch_rx_ring_head]);
      pkthdr =
          reinterpret_cast<pkthdr_t *>(rx_ring_decrypt[batch_rx_ring_head]);
      uint8_t received_tag[kMaxTagLen];
      memcpy(received_tag, encrypted_pkthdr->authentication_tag, kMaxTagLen);
      memset(encrypted_pkthdr->authentication_tag, 0, kMaxTagLen);
      uint8_t current_tag[kMaxTagLen];
      uint8_t *AAD = reinterpret_cast<uint8_t *>(encrypted_pkthdr);
      session = session_vec[encrypted_pkthdr->dest_session_num];
      // Fill in the batched array parameters
      gcm_data[j] = &(session->gdata);
      out[j] = pkthdr;
      in[j] = encrypted_pkthdr;
      batch_rx_ring_head =
          (batch_rx_ring_head + 1) % Transport::kNumRxRingEntries;
      plaintext_len[j] = encrypted_pkthdr->msg_size;
      iv[j] = session->gcm_IV;
      aad[j] = AAD;
      aad_len[j] = sizeof(pkthdr_t);
      auth_tag[j] = current_tag;
      auth_tag_len[j] = kMaxTagLen;
    }
    anja_aesni_gcm128_dec_batch(gcm_data, out, in, plaintext_len, iv, aad,
                                aad_len, auth_tag, auth_tag_len, j);
  }
}
#endif

template <class TTr>
void Rpc<TTr>::process_comps_st() {
  assert(in_dispatch());
  size_t num_pkts = transport->rx_burst();
  if (num_pkts == 0) return;

  // Measure RX burst size
  dpath_stat_inc(dpath_stats.rx_burst_calls, 1);
  dpath_stat_inc(dpath_stats.pkts_rx, num_pkts);

  // ev_loop_tsc was taken just before calling the packet RX code
  const size_t &batch_rx_tsc = ev_loop_tsc;

#ifdef SECURE
  // Batch Decrypt all the packets
  decrypt_as_batch(num_pkts);
#endif
  for (size_t i = 0; i < num_pkts; i++) {
#ifdef SECURE
    auto *pkthdr = reinterpret_cast<pkthdr_t *>(rx_ring_decrypt[rx_ring_head]);
#else
    auto *pkthdr = reinterpret_cast<pkthdr_t *>(rx_ring[rx_ring_head]);
#endif
    rx_ring_head = (rx_ring_head + 1) % Transport::kNumRxRingEntries;

    assert(pkthdr->check_magic());
    assert(pkthdr->msg_size <= kMaxMsgSize);  // msg_size can be 0 here

    Session *session = session_vec[pkthdr->dest_session_num];
    if (unlikely(session == nullptr)) {
      ERPC_WARN("Rpc %u: Received %s for buried session. Dropping.\n", rpc_id,
                pkthdr->to_string().c_str());
      continue;
    }

    if (unlikely(!session->is_connected())) {
      ERPC_WARN(
          "Rpc %u: Received %s for unconnected session (state %s). Dropping.\n",
          rpc_id, pkthdr->to_string().c_str(),
          session_state_str(session->state).c_str());
      continue;
    }

    // If we are here, we have a valid packet for a connected session
    ERPC_TRACE(
        "Rpc %u, lsn %u (%s): RX %s.\n", rpc_id, session->local_session_num,
        session->get_remote_hostname().c_str(), pkthdr->to_string().c_str());

    size_t sslot_i = pkthdr->req_num % kSessionReqWindow;  // Bit shift
    SSlot *sslot = &session->sslot_arr[sslot_i];

    switch (pkthdr->pkt_type) {
      case PktType::kPktTypeReq:
        pkthdr->msg_size <= TTr::kMaxDataPerPkt
            ? process_small_req_st(sslot, pkthdr)
            : process_large_req_one_st(sslot, pkthdr);
        break;
      case PktType::kPktTypeResp: {
        size_t rx_tsc = kCcOptBatchTsc ? batch_rx_tsc : dpath_rdtsc();
        process_resp_one_st(sslot, pkthdr, rx_tsc);
        break;
      }
      case PktType::kPktTypeRFR: process_rfr_st(sslot, pkthdr); break;
      case PktType::kPktTypeExplCR: {
        size_t rx_tsc = kCcOptBatchTsc ? batch_rx_tsc : dpath_rdtsc();
        process_expl_cr_st(sslot, pkthdr, rx_tsc);
        break;
      }
    }
  }

  // Technically, these RECVs can be posted immediately after rx_burst(), or
  // even in the rx_burst() code.
  transport->post_recvs(num_pkts);
}

template <class TTr>
void Rpc<TTr>::submit_bg_req_st(SSlot *sslot) {
  assert(in_dispatch());
  assert(nexus->num_bg_threads > 0);

  const size_t bg_etid = fast_rand.next_u32() % nexus->num_bg_threads;
  auto *req_queue = nexus_hook.bg_req_queue_arr[bg_etid];

  req_queue->unlocked_push(Nexus::BgWorkItem::make_req_item(context, sslot));
}

template <class TTr>
void Rpc<TTr>::submit_bg_resp_st(erpc_cont_func_t cont_func, void *tag,
                                 size_t bg_etid) {
  assert(in_dispatch());
  assert(nexus->num_bg_threads > 0);
  assert(bg_etid < nexus->num_bg_threads);

  auto *req_queue = nexus_hook.bg_req_queue_arr[bg_etid];
  req_queue->unlocked_push(
      Nexus::BgWorkItem::make_resp_item(context, cont_func, tag));
}

FORCE_COMPILE_TRANSPORTS

}  // namespace erpc
