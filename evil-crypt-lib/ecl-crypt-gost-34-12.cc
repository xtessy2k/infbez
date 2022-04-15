#include "ecl-crypt.h"
#include <cstring>
namespace ecl {
namespace crypt {

static const uint8_t PI_TABLE[8][16] {
	{ 12,  4,  6,  2, 10,  5, 11,  9, 14,  8, 13,  7,  0,  3, 15,  1 },
	{  6,  8,  2,  3,  9, 10,  5, 12,  1, 14,  4,  7, 11, 13,  0, 15 },
	{ 11,  3,  5,  8,  2, 15, 10, 13, 14,  1,  7,  4, 12,  9,  6,  0 },
	{ 12,  8,  2,  1, 13,  4, 15,  6,  7,  0, 10,  5,  3, 14,  9, 11 },
	{  7, 15,  5, 10,  8,  1,  6, 13,  0,  9,  3, 14, 11,  4,  2, 12 },
	{  5, 13, 15,  6,  9,  2, 12, 10, 11,  7,  8,  1,  4,  3, 14,  0 },
	{  8, 14,  2,  5,  6,  9,  1, 12, 15,  4, 11,  0, 13, 10,  3,  7 },
	{  1,  7, 14, 13,  0,  5,  8,  3,  4, 15, 10,  6,  9, 12, 11,  2 },
};


static void gost_34_12_2018_64_t_transform(
		const uint8_t *src_block,
		uint8_t *dst_block)
{
	for (unsigned i = 0; i < 4; ++i){
		uint8_t lsn = src_block[i] & 0x0f;
		uint8_t msn = (src_block[i] >> 4) & 0x0f;
		lsn = PI_TABLE[i*2+0][lsn];
		msn = PI_TABLE[i*2+1][msn];
		dst_block[i] = (msn << 4) | lsn;
	}
}

static void gost_34_12_2018_64_g_transform(
		const uint8_t *a,
		const uint8_t *k,
		uint8_t *result)
{
	auto a32 = reinterpret_cast<const uint32_t*>(a);
	auto k32 = reinterpret_cast<const uint32_t*>(k);
	auto result32 = reinterpret_cast<uint32_t*>(result);
	uint32_t sum = (*a32) + (*k32);
	gost_34_12_2018_64_t_transform(reinterpret_cast<const uint8_t*>(sum),
									result);
	*result32 = ((*result32) << 11) | ((*result32) >> 21);

}

static void gost_34_12_2018_64_G0(
		const uint8_t *a0,
		const uint8_t *a1,
		const uint8_t *k,
		uint8_t *b0,
		uint8_t *b1)
{
	auto a0_32 = reinterpret_cast<const uint32_t*>(a0);
	auto a1_32 = reinterpret_cast<const uint32_t*>(a1);
	auto b0_32 = reinterpret_cast<uint32_t*>(b0);
	auto b1_32 = reinterpret_cast<uint32_t*>(b1);
	*b1_32 = *a0_32;
	gost_34_12_2018_64_g_transform(a0, k, b0);
	*b0_32 ^= *a1_32;
}

static void gost_34_12_2018_64_G1(
		const uint8_t *a0,
		const uint8_t *a1,
		const uint8_t *k,
		uint8_t *b)
{
	auto a0_32 = reinterpret_cast<const uint32_t*>(a0);
	auto a1_32 = reinterpret_cast<const uint32_t*>(a1);
	auto b0_32 = reinterpret_cast<uint32_t*>(b);
	auto b1_32 = reinterpret_cast<uint32_t*>(&b[4]);
	*b0_32 = *a0_32;
	gost_34_12_2018_64_g_transform(a0, k , &b[4]);
	*b1_32 ^= *a1_32;
}

static void gost_34_12_2018_64_feistel(
		const uint8_t *src_block,
		const uint8_t *key_data,
		uint8_t *dst_block)
{
	union {
		uint64_t u64;
		uint32_t u32[2];
		uint8_t u8[8];
	} src_block64;
	memcpy(&src_block64, &src_block[0], sizeof(uint64_t));

	unsigned r = 0;
	for (; r < 31; ++r) {
		gost_34_12_2018_64_G0(
				&src_block64.u8[0],
				&src_block64.u8[4],
				&key_data[r * 4],
				&dst_block[0], &dst_block[4]);
		memcpy(&src_block64, dst_block, sizeof(uint64_t));
	}
	gost_34_12_2018_64_G1(
			&src_block64.u8[0],
			&src_block64.u8[4],
			&key_data[r * 4],
			&dst_block[0]);
}

void gost_34_12_2018_64_expand_key_encrypt(
		const uint8_t *src_key,
		uint8_t *dst_key)
{
	auto src_key32 = reinterpret_cast<const uint32_t*>(src_key);
	auto dst_key32 = reinterpret_cast<uint32_t*>(dst_key);
	for (unsigned i = 0; i < 8; ++i) {
		dst_key32[i] = src_key[7-i];
		dst_key32[i+8] = src_key32[7-i];
		dst_key32[i+16] = src_key32[7-i];
		dst_key32[i+24] = src_key32[i];
	}
}

void gost_34_12_2018_64_expand_key_decrypt(
		const uint8_t *src_key,
		uint8_t *dst_key)
{
	auto src_key32 = reinterpret_cast<const uint32_t*>(src_key);
	auto dst_key32 = reinterpret_cast<uint32_t*>(dst_key);
	for (unsigned i = 0; i < 8; ++i) {
		dst_key32[31 - i] = src_key[7-i];
		dst_key32[31 - (i+8)] = src_key32[7-i];
		dst_key32[31 - (i+16)] = src_key32[7-i];
		dst_key32[31 - (i+24)] = src_key32[i];
	}
}

void gost_34_12_2018_64_crypt(
		const uint8_t *src_block,
		const uint8_t *key_data,
		uint8_t *dst_block,
		bool decrypt)
{
	uint8_t expended_key[32*4];
	if (decrypt)
		gost_34_12_2018_64_expand_key_decrypt(key_data, expended_key);
	else
		gost_34_12_2018_64_expand_key_encrypt(key_data, expended_key);

	gost_34_12_2018_64_feistel(src_block, expended_key, dst_block);

}

} /* namespace crypt */
} /* namespace ecl */
