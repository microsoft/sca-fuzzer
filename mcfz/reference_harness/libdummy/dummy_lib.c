///
/// File: dummy_lib.c
///       A tiny stand-in for an "external" cryptographic library. Instead of
///       linking against a real library, the reference harness calls this
///       self-contained implementation, which purposely leaks its (secret) key
///       through microarchitecturally observable behavior.
///
///       Two independent constant-time violations are demonstrated:
///         1. A key-dependent branch          -> control-flow (I-type) leak.
///         2. A key-indexed table lookup      -> data-access  (D-type) leak.
///
///       The whole file is compiled at -O0 (see the Makefile) so the compiler
///       does not turn the key-dependent branch into a branchless sequence,
///       which would hide the control-flow leak.
///

#include "dummy_lib.h"

#define SBOX_SIZE (256)

/// @brief A substitution table indexed by a key byte. Stands in for an S-box in
///        a real cipher. Its contents are public; only the *index* is secret.
static uint8_t g_sbox[SBOX_SIZE];

void dummy_lib_init(void)
{
    // Fill the table with a fixed, input-independent pattern. This runs before
    // tracing begins and touches the same addresses on every run, so it does
    // not itself produce any leak.
    for (unsigned i = 0; i < SBOX_SIZE; i++)
        g_sbox[i] = (uint8_t)((i * 167u + 13u) & 0xFFu);
}

void dummy_cipher_encrypt(const uint8_t *key, size_t key_len, const uint8_t *iv, size_t iv_len,
                          const uint8_t *in, uint8_t *out, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        uint8_t k = key[i % key_len];
        uint8_t x = (uint8_t)(in[i] ^ iv[i % iv_len]);

        // --- Non-constant-time #1: key-dependent branch (control-flow leak) ---
        // The direction of the rotation depends on a secret key bit, so the
        // sequence of executed instructions differs between two keys.
        if (k & 0x01u)
            x = (uint8_t)((x << 1) | (x >> 7)); // rotate left by 1
        else
            x = (uint8_t)((x >> 1) | (x << 7)); // rotate right by 1

        // --- Non-constant-time #2: key-indexed lookup (data-access leak) ---
        // The load address g_sbox + k depends on a secret key byte.
        x ^= g_sbox[k];

        out[i] = x;
    }
}
