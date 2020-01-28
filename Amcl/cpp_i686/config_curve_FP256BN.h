#ifndef CONFIG_CURVE_FP256BN_H
#define CONFIG_CURVE_FP256BN_H

#include"amcl.h"
#include"config_field_FP256BN.h"

// ECP stuff

#define CURVETYPE_FP256BN WEIERSTRASS  
#define PAIRING_FRIENDLY_FP256BN BN
#define CURVE_SECURITY_FP256BN 128

#if PAIRING_FRIENDLY_FP256BN != NOT
#define USE_GLV_FP256BN	  /**< Note this method is patented (GLV), so maybe you want to comment this out */
#define USE_GS_G2_FP256BN /**< Well we didn't patent it :) But may be covered by GLV patent :( */
#define USE_GS_GT_FP256BN /**< Not patented, so probably safe to always use this */

#define POSITIVEX 0
#define NEGATIVEX 1

#define SEXTIC_TWIST_FP256BN M_TYPE
#define SIGN_OF_X_FP256BN NEGATIVEX 

#endif


#if CURVE_SECURITY_FP256BN == 128
#define AESKEY_FP256BN 16 /**< Symmetric Key size - 128 bits */
#define HASH_TYPE_FP256BN SHA256  /**< Hash type */
#endif

#if CURVE_SECURITY_FP256BN == 192
#define AESKEY_FP256BN 24 /**< Symmetric Key size - 192 bits */
#define HASH_TYPE_FP256BN SHA384  /**< Hash type */
#endif

#if CURVE_SECURITY_FP256BN == 256
#define AESKEY_FP256BN 32 /**< Symmetric Key size - 256 bits */
#define HASH_TYPE_FP256BN SHA512  /**< Hash type */
#endif



namespace FP256BN_BIG=B256_28;
namespace FP256BN_FP=FP256BN;

#endif