#ifndef PAIR_FP256BN_H
#define PAIR_FP256BN_H

#include "fp12_FP256BN.h"
#include "ecp2_FP256BN.h"
#include "ecp_FP256BN.h"

using namespace amcl;

namespace FP256BN {
/* Pairing constants */

extern const B256_28::BIG CURVE_Bnx; /**< BN curve x parameter */
extern const B256_28::BIG CURVE_Cru; /**< BN curve Cube Root of Unity */

extern const B256_28::BIG CURVE_W[2];	 /**< BN curve constant for GLV decomposition */
extern const B256_28::BIG CURVE_SB[2][2]; /**< BN curve constant for GLV decomposition */
extern const B256_28::BIG CURVE_WB[4];	 /**< BN curve constant for GS decomposition */
extern const B256_28::BIG CURVE_BB[4][4]; /**< BN curve constant for GS decomposition */

/* Pairing function prototypes */
/**	@brief Calculate Miller loop for Optimal ATE pairing e(P,Q)
 *
	@param r FP12 result of the pairing calculation e(P,Q)
	@param P ECP2 instance, an element of G2
	@param Q ECP instance, an element of G1

 */
extern void PAIR_ate(FP256BN::FP12 *r,ECP2 *P,ECP *Q);
/**	@brief Calculate Miller loop for Optimal ATE double-pairing e(P,Q).e(R,S)
 *
	Faster than calculating two separate pairings
	@param r FP12 result of the pairing calculation e(P,Q).e(R,S), an element of GT
	@param P ECP2 instance, an element of G2
	@param Q ECP instance, an element of G1
	@param R ECP2 instance, an element of G2
	@param S ECP instance, an element of G1
 */
extern void PAIR_double_ate(FP256BN::FP12 *r,ECP2 *P,ECP *Q,ECP2 *R,ECP *S);
/**	@brief Final exponentiation of pairing, converts output of Miller loop to element in GT
 *
	Here p is the internal modulus, and r is the group order
	@param x FP12, on exit = x^((p^12-1)/r)
 */
extern void PAIR_fexp(FP256BN::FP12 *x);
/**	@brief Fast point multiplication of a member of the group G1 by a BIG number
 *
	May exploit endomorphism for speed.
	@param Q ECP member of G1.
	@param b BIG multiplier

 */
extern void PAIR_G1mul(ECP *Q,B256_28::BIG b);
/**	@brief Fast point multiplication of a member of the group G2 by a BIG number
 *
	May exploit endomorphism for speed.
	@param P ECP2 member of G1.
	@param b BIG multiplier

 */
extern void PAIR_G2mul(ECP2 *P,B256_28::BIG b);
/**	@brief Fast raising of a member of GT to a BIG power
 *
	May exploit endomorphism for speed.
	@param x FP12 member of GT.
	@param b BIG exponent

 */
extern void PAIR_GTpow(FP256BN::FP12 *x,B256_28::BIG b);
/**	@brief Tests FP12 for membership of GT
 *
	@param x FP12 instance
	@return 1 if x is in GT, else return 0

 */
extern int PAIR_GTmember(FP256BN::FP12 *x);

}

#endif
