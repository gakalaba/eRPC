#pragma once

#ifndef __CRYPTO__
#define __CRYPTO__

#include <assert.h>
#include <isa-l_crypto/aes_gcm.h>
#include <common.h>

namespace erpc {

// Forward declarations for friendship
class Session;

template <typename T>
class Rpc;

class crypto {
  friend class CTransport;
  friend class Rpc<CTransport>;
  friend class Session;

 public:
  uint8_t gcm_key[GCM_128_KEY_LEN] = {};
  struct gcm_data gdata;
  uint8_t gcm_IV[GCM_IV_LEN] = {};
 private:
  inline int tags_equal(uint8_t *received, uint8_t *current) const {
    for (size_t i = 0; i < MAX_TAG_LEN; i++) {
      if (received[i] != current[i]) return -1;
    }
    return 0;
  }
};

}  // namespace erpc

#endif /* ___CRYPTO__ */
