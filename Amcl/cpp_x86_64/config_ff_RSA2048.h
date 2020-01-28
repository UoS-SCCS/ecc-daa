#ifndef CONFIG_RSA_RSA2048_H
#define CONFIG_RSA_RSA2048_H

#include "amcl.h"
#include "config_big_B1024_58.h"

// FF stuff

#define FFLEN_RSA2048 2 /**< 2^n multiplier of BIGBITS to specify supported Finite Field size, e.g 2048=256*2^3 where BIGBITS=256 */

namespace RSA2048_BIG=B1024_58;

#endif