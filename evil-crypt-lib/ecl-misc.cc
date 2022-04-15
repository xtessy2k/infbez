#include "ecl-misc.h"
std::ostream &operator <<(std::ostream &out, const ecl::hash::uint512_t &v)
{
	auto old_flags = out.flags();
	out << std::hex << std::setfill('0');
	for (unsigned i = 0; i < 64; i++) {
		out << std::setw(2) << int(v.v8[i]);
		if (i % 16 == 15) out << '\n'; else out << ' ';
	}

	out.setf(old_flags);
	return out;
}




