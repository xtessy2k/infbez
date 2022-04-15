#ifndef ECL_CRYPT_H_
#define ECL_CRYPT_H_

#include <cstdint>
#include <functional>

namespace ecl {
namespace crypt {

typedef
		void(*crypt_function_t)(
				const uint8_t *, const uint8_t *, uint8_t *, bool);
using
		CryptFunction = std::function<void(
				const uint8_t *, const uint8_t *, uint8_t *, bool)>;


void gost_34_12_2018_64_crypt(
		const uint8_t *src_block,
		const uint8_t *key_data,
		uint8_t *dst_block,
		bool decrypt = false);

void gost_34_12_2018_128_crypt();


void encrypt_ecb(
		const uint8_t *src_block,
		const uint8_t *key_data,
		uint8_t *dst_block,
		crypt_function_t crypt_function);
void encrypt_ecb(
		const uint8_t *src_block,
		const uint8_t *key_data,
		uint8_t *dst_block,
		CryptFunction crypt_function);
void decrypt_ecb(
		const uint8_t *src_block,
		const uint8_t *key_data,
		uint8_t *dst_block,
		crypt_function_t crypt_function);
void decrypt_ecb(
		const uint8_t *src_block,
		const uint8_t *key_data,
		uint8_t *dst_block,
		CryptFunction crypt_function);


} /* namespace crypt */
} /* namespace ecl */

#endif /* ECL_CRYPT_H_ */
