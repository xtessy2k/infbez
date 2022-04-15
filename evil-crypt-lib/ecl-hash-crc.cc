#include "ecl-hash.h"

namespace ecl {
namespace hash {

void generate_crc32_lut(uint32_t *table, uint32_t poly)
{
	for (unsigned byte = 0; byte < 256; ++byte){
		uint32_t b = byte;
		for (unsigned bit = 0; bit < 8; ++bit) {
			if (b & 1) b = (b >> 1) ^ poly;
			else	   b = (b >> 1);
		}
		table[byte] = b;
	}
}

uint32_t update_crc32(uint32_t * lut, uint8_t b, uint32_t crc)
{
	return lut[(crc ^ b) & 0xff];
}


} /* namespace hash */
} /* namespace ecl */
