/*
 * main.cc
 *
 *  Created on: 11 апр. 2022 г.
 *      Author: xtessy
 */

#include <iostream>
#include <iomanip>
#include <fstream>
#include <cstdio>
#include <cstring>
#include <vector>
#include <array>
#include <random>
#include <algorithm>
#include <unistd.h>

#include <ecl-container.h>
#include <ecl-crypt.h>

template<typename T = std::mt19937,
	std::size_t S = T::state_size * sizeof(typename T::result_type)>
auto create_prng()
{
	std::random_device rand_dev;
	std::random_device::result_type seed_data[(S-1) /
											  sizeof(rand_dev()) + 1];

	std::generate(std::begin(seed_data), std::end(seed_data),
			std::ref(rand_dev));

	std::seed_seq seed_sequence(std::begin(seed_data), std::end(seed_data));
	return T(seed_sequence);


}

void generate_random_key(int length, const char *filename)
{
	int length_bytes = length / 8;
	if (length % 8 > 0)
		length_bytes++;

	std::cout << "Генерация ключа\n";
	std::cout << "Имя файла : " << filename << std::endl;
	std::cout << "Длина ключа :" << length_bytes * 8 << "бит" << std::endl;

	std::vector<uint8_t> key_data(length_bytes);

	auto prng = create_prng();

	std::generate(std::begin(key_data), std::end(key_data), std::ref(prng));

	std::ofstream file { filename, std::ios::binary };

	ecl::container::header_t header {};
	header.magic = ecl::container::MAGIC;
	header.version = 1;
	header.header_size = ecl::container::HEADER_SIZE_V1;
	header.v1.payload = ecl::container::KEY_DATA;
	header.v1.payload_size = key_data.size();

	file.write(reinterpret_cast<const char *>(&header),
			ecl::container::HEADER_SIZE_V1);
	file.write(reinterpret_cast<const char *>(&key_data[0]),
			key_data.size());
	file.close();

	std::cout << "Ключ сгенерирован.\n";

	exit(0);
}

void encrypt_gost_34_12_64_ecb(const char *key_filename,
							const char *src_filename,
							const char *cnt_filename)
{
	constexpr uint32_t BLOCK_SIZE = 8;
	uint32_t block_count;
	std::cout << "Зашифрование файла" << src_filename << " алгоритмом ГОСТ 34.12-64 в режиме CBC\n";
	std::ifstream key_file { key_filename, std::ios::binary };
	if (not key_file) {
		std::cerr << "Не удалось открыть файл ключа!" << std::endl;
		exit(1);
	}
	ecl::container::header_t key_header;
	key_file.read(reinterpret_cast<char*>(&key_header), sizeof(key_header));
	if (key_header.magic != ecl::container::MAGIC) {
		std::cerr << "Неверный формат файла ключа!" << std::endl;
		exit(1);
	}
	if (key_header.version > 1) {
		std::cerr << "Не поддерживаемая версия файла ключа!" << std::endl;
		exit(1);
	}
	if (key_header.v1.payload != ecl::container::KEY_DATA) {
		std::cerr << "Указаный файл не содержит ключa!" << std::endl;
		exit(1);
	}
	if (key_header.v1.payload_size < 32) {
		std::cerr << "Указаный ключ имеет недостаточную длину для "
				"данного алгоритма шифрования!" << std::endl;
		exit(1);
	}
	std::vector<uint8_t> key_data(key_header.v1.payload_size);
	key_file.read(reinterpret_cast<char*>(&key_data[0]),
				  key_header.v1.payload_size);
	key_file.close();

	std::ifstream src_file { src_filename, std::ios::binary | std::ios::ate };
	if (not src_file){
		std::cerr << "Не удалось открыть исходный файл!" << std::endl;
		exit(1);
	}

	ecl::container::header_t cnt_header {};
	ecl::container::encrypted_data_payload_metadata_v1_t cnt_payload {};
	cnt_header.magic = ecl::container::MAGIC;
	cnt_header.header_size = ecl::container::HEADER_SIZE_V1;
	cnt_header.version = 1;
	cnt_header.v1.payload = ecl::container::ENCRYPTED_DATA;

	auto orig_filename = basename(src_filename);
	cnt_payload.original_size = src_file.tellg();
	cnt_payload.metadata_size = sizeof(cnt_payload) + strlen(orig_filename) + 1;

	block_count = cnt_payload.original_size / BLOCK_SIZE;
	if (cnt_payload.original_size % BLOCK_SIZE > 0)
		++block_count;

	cnt_payload.payload_size = block_count * BLOCK_SIZE;
	cnt_header.v1.payload_size = cnt_payload.metadata_size +
								 cnt_payload.payload_size;
	src_file.seekg(0);

	std::ofstream cnt_file { cnt_filename, std::ios::binary };
	if (not cnt_file) {
		std::cerr << "Не могу открыть файл-контейнер для записи!" << std::endl;
		exit(1);
	}
	cnt_file.write(reinterpret_cast<const char*>(&cnt_header), sizeof(cnt_header));
	cnt_file.write(reinterpret_cast<const char*>(&cnt_payload), sizeof(cnt_payload));
	cnt_file.write(orig_filename, strlen(orig_filename) + 1);



	for (uint32_t block_index = 0; block_index < block_count; ++block_index) {
		uint8_t src_block[BLOCK_SIZE] {};
		uint8_t dst_block[BLOCK_SIZE];

		src_file.read(reinterpret_cast<char*>(&src_block[0]), BLOCK_SIZE);

		ecl::crypt::encrypt_ecb(src_block, &key_data[0], dst_block,
								ecl::crypt::gost_34_12_2018_64_crypt);

		cnt_file.write(reinterpret_cast<const char*>(&dst_block[0]), BLOCK_SIZE);
	}

	src_file.close();
	cnt_file.close();



}

void decrypt_gost_34_12_64_ecb(const char *key_filename,
							const char *cnt_filename,
							const char *dst_filename)
{
	constexpr uint32_t BLOCK_SIZE = 8;
	uint32_t block_count;
	std::cout << "Раcшифрование файла" << cnt_filename << " алгоритмом ГОСТ 34.12-64 в режиме CBC\n";
	std::ifstream key_file { key_filename, std::ios::binary };
	if (not key_file) {
		std::cerr << "Не удалось открыть файл ключа!" << std::endl;
		exit(1);
	}
	ecl::container::header_t key_header;
	key_file.read(reinterpret_cast<char*>(&key_header), sizeof(key_header));
	if (key_header.magic != ecl::container::MAGIC) {
		std::cerr << "Неверный формат файла ключа!" << std::endl;
		exit(1);
	}
	if (key_header.version > 1) {
		std::cerr << "Не поддерживаемая версия файла ключа!" << std::endl;
		exit(1);
	}
	if (key_header.v1.payload != ecl::container::KEY_DATA) {
		std::cerr << "Указаный файл не содержит ключa!" << std::endl;
		exit(1);
	}
	if (key_header.v1.payload_size < 32) {
		std::cerr << "Указаный ключ имеет недостаточную длину для "
				"данного алгоритма шифрования!" << std::endl;
		exit(1);
	}
	std::vector<uint8_t> key_data(key_header.v1.payload_size);
	key_file.read(reinterpret_cast<char*>(&key_data[0]),
				  key_header.v1.payload_size);
	key_file.close();

	std::ifstream cnt_file { cnt_filename, std::ios::binary };
	ecl::container::header_t header;
	ecl::container::encrypted_data_payload_metadata_v1_t metadata;
	std::vector<char> orig_filename;

	cnt_file.read(reinterpret_cast<char*>(&header), ecl::container::HEADER_SIZE_V1);
	cnt_file.read(reinterpret_cast<char*>(&metadata), sizeof(metadata));
	size_t orig_filename_size = metadata.metadata_size - sizeof(metadata);
	orig_filename.resize(orig_filename_size);
	cnt_file.read(&orig_filename[0], orig_filename_size);

	const char *real_dst_filename;
	if (dst_filename == nullptr) {
		real_dst_filename = const_cast<const char*>(orig_filename);
	} else {
		real_dst_filename = dst_filename;
	}

	std::ofstream dst_file { real_dst_filename, std::ios::binary };
	uint32_t remaining_data = metadata.original_size;
	block_count = metadata.payload_size / BLOCK_SIZE;
	for (uint32_t block_index = 0; block_index < block_count; ++block_index) {
		uint8_t src_block[BLOCK_SIZE] {};
		uint8_t dst_block[BLOCK_SIZE] {};

		cnt_file.read(reinterpret_cast<char*>(&src_block[0]), BLOCK_SIZE);


		ecl::crypt::decrypt_ecb(src_block, &key_data[0], dst_block,
								ecl::crypt::gost_34_12_2018_64_crypt);

		if(remaining_data >= BLOCK_SIZE) {
			dst_file.write(reinterpret_cast<const char*>(&dst_block[0]), BLOCK_SIZE);
			remaining_data -= BLOCK_SIZE;
		} else {
			dst_file.write(reinterpret_cast<const char*>(&dst_block[0]), remaining_data);
		}
}

}

void help(const char *basename)
{
	std::cout << "Как пользоваться программой:" <<
			"\t" << basename << " <режим> ...\n" <<
			"где <режим>:\n" <<
			"\th - вывести подсказку по указанной следующим параметром команде\n" <<
			"\tg - сгенерировать ключ заданной длины\n" <<
			"\te - зашифрование файла\n" <<
			"\tg - расшифрование файла\n" <<
			"" <<
			std::endl;
	exit(1);
}

void help_command(char command)
{
	switch (command){
	case 'g':
		std::cout <<
			"g - генерация ключей. \n"
			"Доступны следующие варианты команды:\n"
			"\tgs - генерация ключа для симметричного шифра\n"
			"\t\tgs <длина ключа> <имя файла>" <<
			std::endl;
		break;
	case 'e':
		std::cout <<
			"e - зашифрование файла.\n"
			"Возможно зашифрование в следующих режимах:\n"
			"\tee = GOST-34.12-64-ECB\n"
			"\teb = GOST-34.12-64-CBC\n"
			"\tec = GOST-34.12-64-CTR\n"
			"\t\te? <файл ключа> <файл-источник> <файл-контейнер>" <<
			std::endl;
		break;
	case 'd':
		std::cout <<
			"d - расшифрование файла.\n"
			"Возможно расшифрование в следующих режимах:\n"
			"\tde = GOST-34.12-64-ECB\n"
			"\tdb = GOST-34.12-64-CBC\n"
			"\tdc = GOST-34.12-64-CTR\n"
			"\t\td? <файл ключа> <файл-контейнер> <файл-приёмник>" <<
			std::endl;
		break;
	default:
		std::cerr << "Неправильно указана команда!" << std::endl;
	}
	exit(1);
}

void die_param_count(int need, int provided)
{
	std::cerr << "Неверное количество параметров! Ожидалось " << need-1 <<
			", указано " << provided-1 << std::endl;
	exit(1);
}

int main(int argc, char **argv)
{
	if (argc < 2)
		help(basename(argv[0]));

	char mode = argv[1][0];
	char mode2 = argv[1][1];
	switch(mode) {
	case 'h':
		if (argc < 3)
			help(basename(argv[0]));
		help_command(argv[2][0]);
		break;
	case 'g':
		switch (mode2){
		case 's':
			if (argc < 4)
				die_param_count(4, argc);
			generate_random_key(atoi(argv[2]), argv[3]);
			break;
		default:
			std::cerr << "Неверно задан режим генерации ключа!" << std::endl;
			exit(1);
		}
		break;
	case 'e':
		switch (mode2) {
		case 'e': //Зашифрование ГОСТ-34.12-ECB
			if (argc < 5)
				die_param_count(5, argc);
			encrypt_gost_34_12_64_ecb(argv[2], argv[3], argv[4]);
			break;
		case 'b': //Зашифрование ГОСТ-34.12-CBC
			break;
		case 'c': //Зашифрование ГОСТ-34.12-CTR
			break;
		default:
			std::cerr << "Неверно указан режим шифрования!" <<
			std::endl;
		}
		break;
	case 'd':
		switch (mode2) {
		case 'e': //Расшифрование ГОСТ-34.12-ECB
			if (argc < 5)
				die_param_count(5, argc);
			decrypt_gost_34_12_64_ecb(argv[2], argv[3], argv[4]);
			break;
		case 'b': //Расшифрование ГОСТ-34.12-CBC
			break;
		case 'c': //Расшифрование ГОСТ-34.12-CTR
			break;
		default:
			std::cerr << "Неверно указан режим шифрования!" <<
			std::endl;
		}
		break;
	default:
		help(basename(argv[0]));
	}
	return 0;


}



