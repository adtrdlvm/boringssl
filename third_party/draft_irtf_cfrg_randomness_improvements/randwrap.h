#ifndef OPENSSL_HEADER_RAND_IMPRV_H
#define OPENSSL_HEADER_RAND_IMPRV_H
#include <openssl/base.h>

#if defined(__cplusplus)
extern "C" {
#endif

OPENSSL_EXPORT int rand_wrap(
	uint8_t *buf, const size_t len,
	uint8_t *g, size_t g_len);


#if defined(__cplusplus)
} // extern C
#endif

#endif // OPENSSL_HEADER_RAND_IMPRV_H