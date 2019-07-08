#pragma once

#ifndef __CRYPTO__
#define __CRYPTO__

#include <assert.h>
#include <isa-l_crypto/aes_gcm.h>

namespace erpc {
// Shared key for each eRPC session. This should _eventually_ be negotiated
// using a secure handshake

static const unsigned char gcm_key[] = {
    0xee, 0xbc, 0x1f, 0x57, 0x48, 0x7f, 0x51, 0x92, 0x1c, 0x04, 0x65,
    0x66, 0x5f, 0x8a, 0xe6, 0xd1};

struct gcm_data gdata;
//aesni_gcm128_pre(gcm_key, &gdata);
uint8_t gcm_IV[GCM_IV_LEN] = {0xb3, 0xd8, 0xcc, 0x01, 0x7c, 0xbb,
                              0x89, 0xb3, 0x9e, 0x0f, 0x67, 0xe2,
                              0x0,  0x0,  0x0,  0x1};

}  // namespace erpc

#endif /* ___CRYPTO__ */
