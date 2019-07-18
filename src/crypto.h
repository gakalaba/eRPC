#pragma once

#ifndef __CRYPTO__
#define __CRYPTO__

/*
#include <openssl/bio.h>
#include <openssl/evp.h>

#include <openssl/ssl.h>
#include <openssl/dh.h>
#include <openssl/bn.h>
#include <openssl/engine.h>

*/
#include <assert.h>
#include <isa-l_crypto/aes_gcm.h>


#define CRYPTO_IV_LEN 12u
#define CRYPTO_TAG_LEN 16u
#define CRYPTO_GCM_KEY_LEN 32u
#define CRYPTO_GCM_HEX_KEY_LEN 66u


namespace erpc {
// Shared key for each eRPC session. This should _eventually_ be negotiated
// using a secure handshake

static const size_t CRYPTO_HDR_LEN { CRYPTO_IV_LEN + CRYPTO_TAG_LEN  };

}  // namespace erpc

#endif /* ___CRYPTO__ */
