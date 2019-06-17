#include "crypto.h"
#include "common.h"
#ifdef CRYPTO_VERBOSE
#include <iostream>
#endif

/* Changing this will break a number of assumptions re: padding and
 * block size made elsewhere in the code, highly recommend not changing
 */
#define _CRYPTO_CIPHER EVP_aes_256_gcm()

/**
 * @brief
 *
 * @param data_buf The buffer storing the user's data
 * @param data_len length of data including the SECURE header
 * @param key The gcm key
 * @param iv_ptr Pointer to the AES-GCM IV (Initialisation Vector)
 * @param tag_buf
 *
 * @return Error Code (0)
 */
namespace erpc {
int aes_gcm_encrypt_internal(unsigned char *data_buf, int data_len,
                             const unsigned char *key,
                             const unsigned char *iv_ptr,
                             unsigned char *tag_ptr) {
  int ct_len = 0;
  int tmplen = 0;

  EVP_CIPHER_CTX *ctx;
  ctx = EVP_CIPHER_CTX_new();

#ifdef CRYPTO_VERBOSE
  std::cout << "Plaintext: " << std::endl;
  BIO_dump_fp(stdout, reinterpret_cast<const char *>(data_buf), data_len);
#endif

  // TODO: replace gcm_key with negotiated key
  EVP_EncryptInit_ex(ctx, _CRYPTO_CIPHER, NULL, key, iv_ptr);

  EVP_EncryptUpdate(ctx, data_buf, &tmplen,
                    reinterpret_cast<const unsigned char *>(data_buf),
                    data_len);
  ct_len += tmplen;

  EVP_EncryptFinal_ex(ctx, data_buf + ct_len, &tmplen);
  ct_len += tmplen;

#ifdef CRYPTO_VERBOSE
  std::cout << "Ciphertext: " << std::endl;
  BIO_dump_fp(stdout, reinterpret_cast<const char *>(data_buf), data_len);
#endif

  EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, CRYPTO_TAG_LEN, tag_ptr);

#ifdef CRYPTO_VERBOSE
  std::cout << "Tag: " << std::endl;
  BIO_dump_fp(
      stdout,
      reinterpret_cast<const char *>(data_buf) + data_len + CRYPTO_IV_LEN,
      CRYPTO_TAG_LEN);
#endif

  EVP_CIPHER_CTX_free(ctx);

  // We don't return ciphertext_len, as in GCM it's ideally the same as
  // plaintext_len. Somethign is broken if that's not the case.
  assert(data_len == ct_len);

  return 0;
}

/**
 * @brief Function for performing encryption for messages
 *
 * @param void* data_buf
 * @param int data_len
 * @param key The gcm key
 *
 * @return Error Code (0)
 */
int aes_gcm_encrypt(unsigned char *data_buf, int data_len,
                    const unsigned char *key) {
  // We assume 28-byte headroom at the end of databuf[data_len]
  unsigned char *iv_ptr = data_buf + data_len;
  unsigned char *tag_ptr = data_buf + data_len + CRYPTO_IV_LEN;

  int ret = aes_gcm_encrypt_internal(data_buf, data_len, key, iv_ptr, tag_ptr);

  return ret;
}

/**
 * @brief
 *
 * @param data_buf The buffer storing the user's data
 * @param data_len length of data including the SECURE header
 * @param key The gcm key
 * @param iv_ptr Pointer to the initialisation vector
 * @param tag_ptr
 * @return 0 if successful, < 0 otherwise
 */

int aes_gcm_decrypt_internal(unsigned char *data_buf, int data_len,
                             const unsigned char *key,
                             const unsigned char *iv_ptr,
                             unsigned char *tag_ptr) {
  EVP_CIPHER_CTX *ctx;
  int pt_len = 0, tmplen = 0, rv;

  ctx = EVP_CIPHER_CTX_new();
  EVP_DecryptInit_ex(ctx, _CRYPTO_CIPHER, NULL, key, iv_ptr);

  EVP_DecryptUpdate(ctx, data_buf, &tmplen, data_buf, data_len);
  pt_len += tmplen;

  EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, CRYPTO_TAG_LEN, tag_ptr);

  rv = EVP_DecryptFinal_ex(ctx, data_buf + pt_len, &tmplen);
  pt_len += tmplen;

  if (rv > 0) rv = 0;  // normalize EVP error code to our scheme

  EVP_CIPHER_CTX_free(ctx);

  assert(data_len == pt_len);

  return rv;
}

/**
 * @brief
 *
 * @param data_buf The pointer to the buffer with the user usable buffer first
 *  then the secure header
 * @param data_len length of data INCLUDING the SECURE header
 * @param key The gcm key
 *
 * @return int Error Codes
 */
int aes_gcm_decrypt(unsigned char *data_buf, int data_len,
                    const unsigned char *key) {
  unsigned char *iv_ptr = data_buf + data_len;
  unsigned char *tag_ptr = data_buf + data_len + CRYPTO_IV_LEN;

  int ret = aes_gcm_decrypt_internal(data_buf, data_len, key, iv_ptr, tag_ptr);

  return ret;
}

}  // namespace erpc
