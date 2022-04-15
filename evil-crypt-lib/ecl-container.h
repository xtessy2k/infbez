#ifndef ECL_CONTAINER_H_
#define ECL_CONTAINER_H_

#include <cstdint>

namespace ecl{
namespace container{

constexpr uint32_t MAGIC =
		0x00000001 * 'E' +
		0x00000100 * 'C' +
		0x00010000 * 'L' +
		0x01000000 * '!';

enum payload_type_t
{
	RAW = 0,
	KEY_DATA,
	PRIVATE_KEY,
	PUBLIC_KEY,
	ENCRYPTED_DATA
};

constexpr uint32_t HEADER_SIZE_V1 = 20;


#pragma pack(push, 1)
struct header_t
{
	uint32_t magic;
	uint32_t version;
	uint32_t header_size;

	union {
		struct {
			uint8_t payload;
			uint8_t padding[3];
			uint32_t payload_size;
		} v1;
	};
};

struct encrypted_data_payload_metadata_v1_t
{
	uint32_t metadata_size;
	uint32_t original_size;
	uint32_t payload_size;


};
#pragma pack(pop)
} /* namespace container */
} /* namespace ecl */



#endif /* ECL_CONTAINER_H_ */
