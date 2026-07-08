///
/// File: dummy_lib.h
///       Public API of the stand-in "external library". A real harness would
///       include the headers of the library under test (e.g. SymCrypt, OpenSSL)
///       here; the reference harness instead calls its own implementation.
///

#ifndef DUMMY_LIB_H
#define DUMMY_LIB_H

#include <stddef.h>
#include <stdint.h>

/// @brief One-time initialization of the library (analogous to, e.g.,
///        SymCryptInit). Must be called before dummy_cipher_encrypt.
void dummy_lib_init(void);

/// @brief Encrypt @p len bytes with a toy stream cipher.
///
/// This function is deliberately **not constant-time**: it contains a
/// key-dependent branch and a key-indexed table lookup. When the key is
/// classified as secret, both are non-interference violations that MCFuzz
/// should report.
///
/// @param key      Cipher key.
/// @param key_len  Length of @p key in bytes (must be > 0).
/// @param iv       Initialization vector.
/// @param iv_len   Length of @p iv in bytes (must be > 0).
/// @param in       Plaintext of @p len bytes.
/// @param out      Buffer of @p len bytes to receive the ciphertext.
/// @param len      Number of bytes to process.
void dummy_cipher_encrypt(const uint8_t *key, size_t key_len, const uint8_t *iv, size_t iv_len,
                          const uint8_t *in, uint8_t *out, size_t len);

#endif // DUMMY_LIB_H
