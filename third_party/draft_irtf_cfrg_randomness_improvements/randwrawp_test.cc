#include <gtest/gtest.h>
#include <stdint.h>
#include <stdio.h>

#include "randwrap.h"
#include "../../crypto/test/test_util.h"
#include "../crypto/fipsmodule/rand/internal.h"


#define MAX_BUF_SZ 1024
const static uint8_t kZeros[MAX_BUF_SZ] = {};
static const uint8_t* user_additional_data = (uint8_t*) "draft-irtf-cfrg-randomness-improvements";

// These tests are, strictly speaking, flaky, but we use large enough buffers
// that the probability of failing when we should pass is negligible.

TEST(RandWrap, CheckNonZeroNonEuqal) {
	uint8_t buf1[MAX_BUF_SZ] = {};
	uint8_t buf2[MAX_BUF_SZ] = {};
	uint8_t g1[MAX_BUF_SZ] = {};
	uint8_t g2[MAX_BUF_SZ] = {};

	for(size_t i=8; i<MAX_BUF_SZ; i++) {
		RAND_bytes_with_additional_data(g2, i, user_additional_data);
		RAND_bytes_with_additional_data(g1, i, user_additional_data);
		EXPECT_EQ(rand_wrap(buf1, i, g2, i), 1);
		EXPECT_EQ(rand_wrap(buf2, i, g1, i), 1);
		EXPECT_NE(Bytes(buf1), Bytes(buf2));
		EXPECT_NE(Bytes(buf1), Bytes(kZeros));
		EXPECT_NE(Bytes(buf2), Bytes(kZeros));
	}
}


// TODO:
// - input g 0 length
// - output 0 length
// - what if output == NULL