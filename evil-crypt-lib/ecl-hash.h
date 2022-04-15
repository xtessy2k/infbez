#ifndef ECL_HASH_H_
#define ECL_HASH_H_

#include <cstdint>

namespace ecl {
namespace hash {

union uint512_t
{
	uint64_t v64[8];
	uint32_t v32[16];
	uint16_t v16[32];
	uint8_t v8[64];
};

constexpr uint32_t CRC32_POLY = 0xedb88320;


// CRC32
void generate_crc32_lut(uint32_t *table, uint32_t poly);
uint32_t update_crc32(uint32_t * lut, uint8_t b, uint32_t crc);


// √Œ—“ 34.11-2018 256 ·ËÚ
void gost_34_11_2018_256_init(uint512_t &h, uint512_t &N, uint512_t &sigma);

// √Œ—“ 34.11-2018 512 ·ËÚ
void gost_34_11_2018_512_init(uint512_t &h, uint512_t &N, uint512_t &sigma);
void gost_34_11_2018_update(uint512_t &h,
							uint512_t &N,
							uint512_t &sigma,
							const uint8_t *M,
							uint32_t size);
void gost_34_11_2018_finish(uint512_t &h,
							uint512_t &N,
							uint512_t &sigma,
							const uint8_t *M,
							uint32_t size);

} /* namespace hash */
} /* namespace ecl */



#endif /* ECL_HASH_H_ */
