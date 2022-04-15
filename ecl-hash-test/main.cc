/*
 * main.cc
 *
 *  Created on: 13 апр. 2022 г.
 *      Author: xtessy
 */
#include <iostream>
#include <cstdint>
#include <array>


#include <ecl-hash.h>
#include <ecl-misc.h>

namespace ecl {
namespace hash {
void X(const uint512_t &k, const uint512_t &a, uint512_t &x);
uint512_t operator ^(const uint512_t &lhs, const uint512_t &rhs);
uint512_t S(const uint512_t a);
uint512_t P(const uint512_t a);
uint512_t L(const uint512_t &a);

extern const uint512_t C_TABLE[12];


}
}

const std::array<uint8_t, 63> M1 {
	0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
	0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35,
	0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33,
	0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31,
	0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39,
	0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
	0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35,
	0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32
};



int main()
{
	using namespace ecl::hash;
	uint512_t h, N, sigma;

	std::cout << "Инициализация" << std::endl;
	gost_34_11_2018_512_init(h, N, sigma);
	std::cout << "h:\n" << h << std::endl;
	std::cout << "N:\n" << N << std::endl;
	std::cout << "sigma:\n" << sigma << std::endl;

	std::cout << "\n\nБерем блок и дополняем:" << std::endl;
	uint512_t m;
	int mptr = 0;
	int size = M1.size();
	for (; mptr < size; ++mptr)
		m.v8[mptr] = M1[mptr];
	//Дополняем блок до 64 байт / 512 бит
	if (mptr < 64) {
		m.v8[mptr] = 0x01;
		while (mptr < 64)
			m.v8[mptr++] == 0x00;
	}

	std::cout << m << std::endl;

	std::cout << "Вычисляем К:" << std::endl;
	uint512_t K;
	K = h ^ N;
	std::cout << "  После Х:\n" << K << std::endl;

	K = S(K);
	std::cout << "  После S:\n" << K << std::endl;

	K = P(K);
	std::cout << "  После P:\n" << K << std::endl;

	K = L(K);
	std::cout << "  После L:\n" << K << std::endl;

	auto K1 = K;
	auto XK1m = K1 ^ m;
	std::cout << "X[K1](m):\n" << XK1m << std::endl;
	auto SXK1m = S(XK1m);
	std::cout << "SX[K1](m):\n" << SXK1m << std::endl;
	auto PSXK1m = P(SXK1m);
	std::cout << "PSX[K1](m):\n" << PSXK1m << std::endl;
	auto LPSXK1m = L(PSXK1m);
	std::cout << "LPSX[K1](m):\n" << LPSXK1m << std::endl;

	auto K2 = L(P(S(K1 ^ C_TABLE[0])));
	std::cout << "K2:\n" << K2 << std::endl;

	auto res2 = L(P(S(K2 ^ LPSXK1m)));
	std::cout << "res2:\n" << res2 << std::endl;

	auto K3 = L(P(S(K2 ^ C_TABLE[1])));
	std::cout << "K3:\n" << K3 << std::endl;

	auto res3 = L(P(S(K3 ^ res2)));
	std::cout << "res3:\n" << res3 << std::endl;

	auto K4 = L(P(S(K3 ^ C_TABLE[1])));
	std::cout << "K4:\n" << K4 << std::endl;

	auto res4 = L(P(S(K4 ^ res3)));
	std::cout << "res4:\n" << res4 << std::endl;

	return 0;
}



