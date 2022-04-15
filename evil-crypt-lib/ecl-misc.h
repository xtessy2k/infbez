#ifndef ECL_MISC_H_
#define ECL_MISC_H_

#include <iostream>
#include <iomanip>
#include "ecl-hash.h"

//namespace ecl {
//namespace hash {


//} /* namespace hash */
//} /* namespace ecl */

std::ostream &operator <<(std::ostream &out, const ecl::hash::uint512_t &v);

#endif /* ECL_MISC_H_ */
