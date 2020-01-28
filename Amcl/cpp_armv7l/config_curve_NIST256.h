#ifndef CONFIG_CURVE_NIST256_H
#define CONFIG_CURVE_NIST256_H

#include"amcl.h"
#include"config_field_NIST256.h"

// ECP stuff

#define CURVETYPE_NIST256 WEIERSTRASS  
#define PAIRING_FRIENDLY_NIST256 NOT
#define CURVE_SECURITY_NIST256 128

#if PAIRING_FRIENDLY_NIST256 != NOT
#define USE_GLV_NIST256	  /**< Note this method is patented (GLV), so maybe you want to comment this out */
#define USE_GS_G2_NIST256 /**< Well we didn't patent it :) But may be covered by GLV patent :( */
#define USE_GS_GT_NIST256 /**< Not patented, so probably safe to always use this */

#define POSITIVEX 0
#define NEGATIVEX 1

#define SEXTIC_TWIST_NIST256 
#define SIGN_OF_X_NIST256  

#endif


#if CURVE_SECURITY_NIST256 == 128
#define AESKEY_NIST256 16 /**< Symmetric Key size - 128 bits */
#define HASH_TYPE_NIST256 SHA256  /**< Hash type */
#endif

#if CURVE_SECURITY_NIST256 == 192
#define AESKEY_NIST256 24 /**< Symmetric Key size - 192 bits */
#define HASH_TYPE_NIST256 SHA384  /**< Hash type */
#endif

#if CURVE_SECURITY_NIST256 == 256
#define AESKEY_NIST256 32 /**< Symmetric Key size - 256 bits */
#define HASH_TYPE_NIST256 SHA512  /**< Hash type */
#endif



namespace NIST256_BIG=B256_28;
namespace NIST256_FP=NIST256;

#endif