#include <stdint.h>
#include <openssl/ecdsa.h>
#include <openssl/curve25519.h>
#include <openssl/sha.h>
#include <openssl/digest.h>
#include <openssl/hkdf.h>
#include "../crypto/fipsmodule/rand/internal.h"

#include <openssl/bn.h>
#include "randwrap.h"

#define NONCE_SIZE 128

// TODO: Must be device and protocol bound
static const uint8_t tag1[] = "00:e1:8c:9f:89:9f-TLS_v1.3";
// TODO: This isn't thread safe
static uint8_t nonce[NONCE_SIZE] = {0};

// Used for testing only: enabling RANDOMNESS_IMPROVEMENTS_CALCULATE_SIGNATURE
// causes calculating EdDSA over input each time rand_wrap() is invoked.
#ifdef RANDOMNESS_IMPROVEMENTS_CALCULATE_SIGNATURE
static const uint8_t kPrvKey[64] = {
    0xDF, 0x45, 0x02, 0xB3, 0x32, 0x38, 0x1F, 0xE6, 0x52, 0x3E,
    0xBB, 0x4D, 0x1F, 0xF0, 0x6C, 0x5F, 0x04, 0x1A, 0x4D, 0xA8,
    0xCA, 0x41, 0xD7, 0x4F, 0x1E, 0xAE, 0x49, 0x5B, 0x71, 0xA2,
    0x08, 0xFF, 0xBF, 0x30, 0x34, 0x1C, 0x91, 0xA0, 0x51, 0xA9,
    0x54, 0xAD, 0xA6, 0x17, 0xFA, 0xBB, 0x70, 0xBB, 0xF9, 0x6C,
    0x7E, 0x85, 0xBD, 0x4B, 0x1A, 0xDB, 0xEE, 0x6F, 0xE8, 0x71,
    0x8E, 0xD0, 0x34, 0x47};

static void sign(uint8_t sig[64], const uint8_t *msg, size_t msg_len) {
    // can't fail
    ED25519_sign(sig, msg, msg_len, kPrvKey);
}
#else
// Use hardcoded one
static const uint8_t kSignature[64] = {
    0x95, 0xC3, 0x75, 0x2B, 0x24, 0x91, 0xC3, 0x1E, 0x79, 0xA4,
    0x50, 0x61, 0x52, 0xEC, 0xC4, 0xD6, 0x3E, 0xC0, 0x35, 0xE1,
    0x69, 0x75, 0x61, 0x42, 0x00, 0x5D, 0xF3, 0x0B, 0x4D, 0xE7,
    0x52, 0x6B, 0x0A, 0x14, 0xE1, 0x26, 0x58, 0x07, 0x21, 0x13,
    0x61, 0x18, 0x5B, 0x0C, 0x12, 0xF1, 0x44, 0x7B, 0x6B, 0xB1,
    0x0A, 0x6F, 0x06, 0x15, 0x74, 0x17, 0xDF, 0xE4, 0xCF, 0xE7,
    0x2B, 0x8C, 0x28, 0x03
};
static void sign(uint8_t sig[64], const uint8_t *msg, size_t msg_len) {
    // can't fail
    (void)msg, (void)msg_len;
    memcpy(sig, kSignature, sizeof(kSignature));
}
#endif

static void inc_nonce(uint8_t tag[NONCE_SIZE]){
    for (int i = NONCE_SIZE - 1; i >= 0; i--) {
        tag[i]++;
        if (tag[i]) {
            break;
        }
    }
}

/* -----------------------------------------------------------------------------
 * @brief Implements randomness wrapper (G') as described in
 *        draft-cfrg-randomness-improvements-07. Function expands out_len random
 *        bytes from a key derived from the CSPRNG output and signature over
 *        a fixed string.
 *
 * @param out:      buffer holding a result. Caller must make sure buffer
 *                  is big enough to hold out_len bytes.
 *        out_len:  requested length
 *        g:        buffer keeps result from CSPRNG (G(n))
 *        g_len:    length of the buffer g
 *
 * @remarks This is an instantiation of a draft-irtf-randomness-improvements-07.
 *          Values from the specification are fixed as follows:
 *          * Sig = EdDSA signature (64 bytes output, deterministic scheme)
 *          * H = SHA-256
 *          * M = 32 bytes
 *          * L = 32 bytes
 *          * TAG1: hardcoded string
 *          * TAG2: a 1024-bit counter, incremented with each invocation of the
 *                  function.
 *
 * @result function returns 1 on success otherwise 0.
-------------------------------------------------------------------------------- */
int rand_wrap(uint8_t *out, const size_t out_len, uint8_t *g, size_t g_len) {
    uint8_t sig[64];
    uint8_t hash[SHA256_DIGEST_LENGTH];
    uint8_t prk[SHA256_DIGEST_LENGTH];
    size_t prk_len = sizeof(prk) - 1;
    int ret = 0;

    // H(Sig(sk, tag1))
    sign(sig, tag1, sizeof(tag1));
    SHA256(sig, sizeof(sig), hash);

    // Extract. prk_len is set to hash size
    ret = HKDF_extract(
        prk, &prk_len,
        EVP_sha256(), hash, SHA256_DIGEST_LENGTH,
        g, g_len);
    if (!ret) {
        goto end;
    }

    // Expand
    inc_nonce(nonce);
    ret = HKDF_expand(out, out_len,
        EVP_sha256(),
        prk, prk_len,
        nonce, NONCE_SIZE);
    if (!ret) {
        goto end;
    }

 end:
    return ret;
}
