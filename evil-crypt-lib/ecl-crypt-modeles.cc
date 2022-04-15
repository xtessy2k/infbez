#include "ecl-crypt.h"

namespace ecl {
namespace crypt {

void encrypt_ecb(
		const uint8_t *src_block,
		const uint8_t *key_data,
		uint8_t *dst_block,
		crypt_function_t crypt_function)
{
	encrypt_ecb(src_block, key_data, dst_block,
			[&crypt_function](
						const uint8_t *src,
						const uint8_t *key,
						uint8_t *dst,
						bool mode){
		crypt_function(src, key, dst, mode);
	});
}
void encrypt_ecb(
		const uint8_t *src_block,
		const uint8_t *key_data,
		uint8_t *dst_block,
		CryptFunction crypt_function)
{
	crypt_function(src_block, key_data, dst_block, false);
}
void decrypt_ecb(
		const uint8_t *src_block,
		const uint8_t *key_data,
		uint8_t *dst_block,
		crypt_function_t crypt_function)
{
	encrypt_ecb(src_block, key_data, dst_block,
			[&crypt_function](
						const uint8_t *src,
						const uint8_t *key,
						uint8_t *dst,
						bool mode){
		crypt_function(src, key, dst, mode);
	});
}
void decrypt_ecb(
		const uint8_t *src_block,
		const uint8_t *key_data,
		uint8_t *dst_block,
		CryptFunction crypt_function)
{
	crypt_function(src_block, key_data, dst_block, true);
}
} /* namespace crypt */
} /* namespace ecl */




