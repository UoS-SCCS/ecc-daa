/*
Licensed to the Apache Software Foundation (ASF) under one
or more contributor license agreements.  See the NOTICE file
distributed with this work for additional information
regarding copyright ownership.  The ASF licenses this file
to you under the Apache License, Version 2.0 (the
"License"); you may not use this file except in compliance
with the License.  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied.  See the License for the
specific language governing permissions and limitations
under the License.
*/

/* AMCL BN Curve pairing functions */

//#define HAS_MAIN

#include "pair_FP256BN.h"

using namespace B256_56;
using namespace FP256BN;

namespace FP256BN {
	static void PAIR_line(FP12 *,ECP2 *,ECP2 *,FP *,FP *);
	static void glv(BIG u[2],BIG);
	static void gs(BIG u[4],BIG);
}

/* Line function */
static void FP256BN::PAIR_line(FP12 *v,ECP2 *A,ECP2 *B,FP *Qx,FP *Qy)
{
	FP2 X1,Y1,T1,T2;
	FP2 XX,YY,ZZ,YZ;
    FP4 a,b,c;

	if (A==B)
    {
        /* doubling */
 		FP2_copy(&XX,&(A->x));	//FP2 XX=new FP2(A.getx());  //X
		FP2_copy(&YY,&(A->y));	//FP2 YY=new FP2(A.gety());  //Y
		FP2_copy(&ZZ,&(A->z));	//FP2 ZZ=new FP2(A.getz());  //Z


		FP2_copy(&YZ,&YY);		//FP2 YZ=new FP2(YY);        //Y 
		FP2_mul(&YZ,&YZ,&ZZ);		//YZ.mul(ZZ);                //YZ
		FP2_sqr(&XX,&XX);		//XX.sqr();	               //X^2
		FP2_sqr(&YY,&YY);		//YY.sqr();	               //Y^2
		FP2_sqr(&ZZ,&ZZ);		//ZZ.sqr();			       //Z^2
			
		FP2_imul(&YZ,&YZ,4);	//YZ.imul(4);
		FP2_neg(&YZ,&YZ);		//YZ.neg(); 
		FP2_norm(&YZ);			//YZ.norm();       //-4YZ

		FP2_imul(&XX,&XX,6);					//6X^2
		FP2_pmul(&XX,&XX,Qx);	               //6X^2.Xs

		FP2_imul(&ZZ,&ZZ,3*CURVE_B_I);	//3Bz^2 

		FP2_pmul(&YZ,&YZ,Qy);	//-4YZ.Ys

#if SEXTIC_TWIST_FP256BN==D_TYPE
		FP2_div_ip2(&ZZ);		//6(b/i)z^2
#endif
#if SEXTIC_TWIST_FP256BN==M_TYPE
		FP2_mul_ip(&ZZ);
		FP2_add(&ZZ,&ZZ,&ZZ);  // 6biz^2
		FP2_mul_ip(&YZ);
		FP2_norm(&YZ);	
#endif
		FP2_norm(&ZZ);			// 6bi.Z^2 

		FP2_add(&YY,&YY,&YY);	// 2y^2
		FP2_sub(&ZZ,&ZZ,&YY);	// 
		FP2_norm(&ZZ);			// 6b.Z^2-2Y^2

		FP4_from_FP2s(&a,&YZ,&ZZ); // -4YZ.Ys | 6b.Z^2-2Y^2 | 6X^2.Xs 
#if SEXTIC_TWIST_FP256BN==D_TYPE
		FP4_from_FP2(&b,&XX);	
		FP4_zero(&c);
#endif
#if SEXTIC_TWIST_FP256BN==M_TYPE
		FP4_zero(&b);
		FP4_from_FP2H(&c,&XX);
#endif

		ECP2_dbl(A);				//A.dbl();
    }
    else
    {
        /* addition */

		FP2_copy(&X1,&(A->x));		//FP2 X1=new FP2(A.getx());    // X1
		FP2_copy(&Y1,&(A->y));		//FP2 Y1=new FP2(A.gety());    // Y1
		FP2_copy(&T1,&(A->z));		//FP2 T1=new FP2(A.getz());    // Z1
			
		FP2_copy(&T2,&T1);		//FP2 T2=new FP2(A.getz());    // Z1

		FP2_mul(&T1,&T1,&(B->y));	//T1.mul(B.gety());    // T1=Z1.Y2 
		FP2_mul(&T2,&T2,&(B->x));	//T2.mul(B.getx());    // T2=Z1.X2

		FP2_sub(&X1,&X1,&T2);		//X1.sub(T2); 
		FP2_norm(&X1);				//X1.norm();  // X1=X1-Z1.X2
		FP2_sub(&Y1,&Y1,&T1);		//Y1.sub(T1); 
		FP2_norm(&Y1);				//Y1.norm();  // Y1=Y1-Z1.Y2

		FP2_copy(&T1,&X1);			//T1.copy(X1);            // T1=X1-Z1.X2

		FP2_pmul(&X1,&X1,Qy);		//X1.pmul(Qy);            // X1=(X1-Z1.X2).Ys
#if SEXTIC_TWIST_FP256BN==M_TYPE
		FP2_mul_ip(&X1);
		FP2_norm(&X1);
#endif

		FP2_mul(&T1,&T1,&(B->y));	//T1.mul(B.gety());       // T1=(X1-Z1.X2).Y2

		FP2_copy(&T2,&Y1);			//T2.copy(Y1);            // T2=Y1-Z1.Y2
		FP2_mul(&T2,&T2,&(B->x));	//T2.mul(B.getx());       // T2=(Y1-Z1.Y2).X2
		FP2_sub(&T2,&T2,&T1);		//T2.sub(T1); 
		FP2_norm(&T2);				//T2.norm();          // T2=(Y1-Z1.Y2).X2 - (X1-Z1.X2).Y2
		FP2_pmul(&Y1,&Y1,Qx);		//Y1.pmul(Qx);  
		FP2_neg(&Y1,&Y1);			//Y1.neg(); 
		FP2_norm(&Y1);				//Y1.norm(); // Y1=-(Y1-Z1.Y2).Xs

		FP4_from_FP2s(&a,&X1,&T2);	// (X1-Z1.X2).Ys  |  (Y1-Z1.Y2).X2 - (X1-Z1.X2).Y2  | - (Y1-Z1.Y2).Xs
#if SEXTIC_TWIST_FP256BN==D_TYPE
		FP4_from_FP2(&b,&Y1);		//b=new FP4(Y1);
		FP4_zero(&c);
#endif
#if SEXTIC_TWIST_FP256BN==M_TYPE
		FP4_zero(&b);
		FP4_from_FP2H(&c,&Y1);		//b=new FP4(Y1);
#endif
		ECP2_add(A,B);			//A.add(B);
    }

    FP12_from_FP4s(v,&a,&b,&c);
//	FP12_norm(v);
}

/* Optimal R-ate pairing r=e(P,Q) */
void FP256BN::PAIR_ate(FP12 *r,ECP2 *P1,ECP *Q1)
{
    BIG x,n,n3;
	FP Qx,Qy;
    int i,nb,bt;
    ECP2 A,NP,P;
	ECP Q;
    FP12 lv;
#if PAIRING_FRIENDLY_FP256BN==BN
    ECP2 KA;
    FP2 X;

    FP_rcopy(&Qx,Fra);
    FP_rcopy(&Qy,Frb);
    FP2_from_FPs(&X,&Qx,&Qy);

#if SEXTIC_TWIST_FP256BN==M_TYPE
	FP2_inv(&X,&X);
	FP2_norm(&X);
#endif

#endif

    BIG_rcopy(x,CURVE_Bnx);

#if PAIRING_FRIENDLY_FP256BN==BN
    BIG_pmul(n,x,6);
#if SIGN_OF_X_FP256BN==POSITIVEX
	BIG_inc(n,2);
#else
    BIG_dec(n,2);
#endif

#else
    BIG_copy(n,x);
#endif

    BIG_norm(n);
	BIG_pmul(n3,n,3);
	BIG_norm(n3);

//    ECP2_affine(P);
//    ECP_affine(Q);
	ECP2_copy(&P,P1);
	ECP_copy(&Q,Q1);

	ECP2_affine(&P);
	ECP_affine(&Q);


    FP_copy(&Qx,&(Q.x));
    FP_copy(&Qy,&(Q.y));

    ECP2_copy(&A,&P);

	ECP2_copy(&NP,&P); ECP2_neg(&NP);

    FP12_one(r);
    nb=BIG_nbits(n3);

    /* Main Miller Loop */
    for (i=nb-2; i>=1; i--)
    {
		FP12_sqr(r,r);
        PAIR_line(&lv,&A,&A,&Qx,&Qy);
        FP12_smul(r,&lv,SEXTIC_TWIST_FP256BN);

		bt=BIG_bit(n3,i)-BIG_bit(n,i); // bt=BIG_bit(n,i);
        if (bt==1)
        {
            PAIR_line(&lv,&A,&P,&Qx,&Qy);
            FP12_smul(r,&lv,SEXTIC_TWIST_FP256BN);
        }
		if (bt==-1)
		{
			//ECP2_neg(P);
            PAIR_line(&lv,&A,&NP,&Qx,&Qy);
            FP12_smul(r,&lv,SEXTIC_TWIST_FP256BN);
			//ECP2_neg(P);
		}

    }

#if SIGN_OF_X_FP256BN==NEGATIVEX
    FP12_conj(r,r);
#endif
    /* R-ate fixup required for BN curves */
#if PAIRING_FRIENDLY_FP256BN==BN
    ECP2_copy(&KA,&P);
    ECP2_frob(&KA,&X);
#if SIGN_OF_X_FP256BN==NEGATIVEX
    ECP2_neg(&A);
    //FP12_conj(r,r);
#endif
    PAIR_line(&lv,&A,&KA,&Qx,&Qy);
    FP12_smul(r,&lv,SEXTIC_TWIST_FP256BN);
    ECP2_frob(&KA,&X);
    ECP2_neg(&KA);
    PAIR_line(&lv,&A,&KA,&Qx,&Qy);
    FP12_smul(r,&lv,SEXTIC_TWIST_FP256BN);
#endif
}

/* Optimal R-ate double pairing e(P,Q).e(R,S) */
void FP256BN::PAIR_double_ate(FP12 *r,ECP2 *P1,ECP *Q1,ECP2 *R1,ECP *S1)
{

    BIG x,n,n3;
	FP Qx,Qy,Sx,Sy;
    int i,nb,bt;
    ECP2 A,B,NP,NR,P,R;
	ECP Q,S;
    FP12 lv;
#if PAIRING_FRIENDLY_FP256BN==BN
    ECP2 K;
    FP2 X;

    FP_rcopy(&Qx,Fra);
    FP_rcopy(&Qy,Frb);
    FP2_from_FPs(&X,&Qx,&Qy);

#if SEXTIC_TWIST_FP256BN==M_TYPE
	FP2_inv(&X,&X);
	FP2_norm(&X);
#endif

#endif
    BIG_rcopy(x,CURVE_Bnx);

#if PAIRING_FRIENDLY_FP256BN==BN
    BIG_pmul(n,x,6);
#if SIGN_OF_X_FP256BN==POSITIVEX
	BIG_inc(n,2);
#else
    BIG_dec(n,2);
#endif
#else
    BIG_copy(n,x);
#endif

    BIG_norm(n);
	BIG_pmul(n3,n,3);
	BIG_norm(n3);

	ECP2_copy(&P,P1);
	ECP_copy(&Q,Q1);

	ECP2_affine(&P);
	ECP_affine(&Q);

	ECP2_copy(&R,R1);
	ECP_copy(&S,S1);

	ECP2_affine(&R);
	ECP_affine(&S);



    FP_copy(&Qx,&(Q.x));
    FP_copy(&Qy,&(Q.y));

    FP_copy(&Sx,&(S.x));
    FP_copy(&Sy,&(S.y));

    ECP2_copy(&A,&P);
    ECP2_copy(&B,&R);

	ECP2_copy(&NP,&P); ECP2_neg(&NP);
	ECP2_copy(&NR,&R); ECP2_neg(&NR);

    FP12_one(r);
    nb=BIG_nbits(n3);

    /* Main Miller Loop */
    for (i=nb-2; i>=1; i--)
    {
        FP12_sqr(r,r);
        PAIR_line(&lv,&A,&A,&Qx,&Qy);
        FP12_smul(r,&lv,SEXTIC_TWIST_FP256BN);

        PAIR_line(&lv,&B,&B,&Sx,&Sy);
        FP12_smul(r,&lv,SEXTIC_TWIST_FP256BN);

		bt=BIG_bit(n3,i)-BIG_bit(n,i); // bt=BIG_bit(n,i);
        if (bt==1)
        {
            PAIR_line(&lv,&A,&P,&Qx,&Qy);
            FP12_smul(r,&lv,SEXTIC_TWIST_FP256BN);

            PAIR_line(&lv,&B,&R,&Sx,&Sy);
            FP12_smul(r,&lv,SEXTIC_TWIST_FP256BN);
        }
		if (bt==-1)
		{
			//ECP2_neg(P); 
            PAIR_line(&lv,&A,&NP,&Qx,&Qy);
            FP12_smul(r,&lv,SEXTIC_TWIST_FP256BN);
			//ECP2_neg(P); 
			//ECP2_neg(R);
            PAIR_line(&lv,&B,&NR,&Sx,&Sy);
            FP12_smul(r,&lv,SEXTIC_TWIST_FP256BN);
			//ECP2_neg(R);
		}
	}

#if SIGN_OF_X_FP256BN==NEGATIVEX
    FP12_conj(r,r);
#endif
    /* R-ate fixup required for BN curves */
#if PAIRING_FRIENDLY_FP256BN==BN

#if SIGN_OF_X_FP256BN==NEGATIVEX
//   FP12_conj(r,r);
    ECP2_neg(&A);
    ECP2_neg(&B);
#endif

    ECP2_copy(&K,&P);
    ECP2_frob(&K,&X);
    PAIR_line(&lv,&A,&K,&Qx,&Qy);
    FP12_smul(r,&lv,SEXTIC_TWIST_FP256BN);
    ECP2_frob(&K,&X);
    ECP2_neg(&K);
    PAIR_line(&lv,&A,&K,&Qx,&Qy);
    FP12_smul(r,&lv,SEXTIC_TWIST_FP256BN);
    ECP2_copy(&K,&R);
    ECP2_frob(&K,&X);

    PAIR_line(&lv,&B,&K,&Sx,&Sy);
    FP12_smul(r,&lv,SEXTIC_TWIST_FP256BN);
    ECP2_frob(&K,&X);
    ECP2_neg(&K);
    PAIR_line(&lv,&B,&K,&Sx,&Sy);
    FP12_smul(r,&lv,SEXTIC_TWIST_FP256BN);
#endif
}

/* final exponentiation - keep separate for multi-pairings and to avoid thrashing stack */
void FP256BN::PAIR_fexp(FP12 *r)
{
    FP2 X;
    BIG x;
	FP a,b;
    FP12 t0,y0,y1,y2,y3;

    BIG_rcopy(x,CURVE_Bnx);
    FP_rcopy(&a,Fra);
    FP_rcopy(&b,Frb);
    FP2_from_FPs(&X,&a,&b);

    /* Easy part of final exp */

    FP12_inv(&t0,r);
    FP12_conj(r,r);

    FP12_mul(r,&t0);
    FP12_copy(&t0,r);

    FP12_frob(r,&X);
    FP12_frob(r,&X);
    FP12_mul(r,&t0);

    /* Hard part of final exp - see Duquesne & Ghamman eprint 2015/192.pdf */
#if PAIRING_FRIENDLY_FP256BN==BN
    FP12_pow(&t0,r,x); // t0=f^-u
#if SIGN_OF_X_FP256BN==POSITIVEX
	FP12_conj(&t0,&t0);
#endif
    FP12_usqr(&y3,&t0); // y3=t0^2
    FP12_copy(&y0,&t0);
    FP12_mul(&y0,&y3); // y0=t0*y3
    FP12_copy(&y2,&y3);
    FP12_frob(&y2,&X); // y2=y3^p
    FP12_mul(&y2,&y3); //y2=y2*y3
    FP12_usqr(&y2,&y2); //y2=y2^2
    FP12_mul(&y2,&y3); // y2=y2*y3

    FP12_pow(&t0,&y0,x);  //t0=y0^-u
#if SIGN_OF_X_FP256BN==POSITIVEX
	FP12_conj(&t0,&t0);
#endif
    FP12_conj(&y0,r);     //y0=~r
    FP12_copy(&y1,&t0);
    FP12_frob(&y1,&X);
    FP12_frob(&y1,&X); //y1=t0^p^2
    FP12_mul(&y1,&y0); // y1=y0*y1
    FP12_conj(&t0,&t0); // t0=~t0
    FP12_copy(&y3,&t0);
    FP12_frob(&y3,&X); //y3=t0^p
    FP12_mul(&y3,&t0); // y3=t0*y3
    FP12_usqr(&t0,&t0); // t0=t0^2
    FP12_mul(&y1,&t0); // y1=t0*y1

    FP12_pow(&t0,&y3,x); // t0=y3^-u
#if SIGN_OF_X_FP256BN==POSITIVEX
	FP12_conj(&t0,&t0);
#endif
    FP12_usqr(&t0,&t0); //t0=t0^2
    FP12_conj(&t0,&t0); //t0=~t0
    FP12_mul(&y3,&t0); // y3=t0*y3

    FP12_frob(r,&X);
    FP12_copy(&y0,r);
    FP12_frob(r,&X);
    FP12_mul(&y0,r);
    FP12_frob(r,&X);
    FP12_mul(&y0,r);

    FP12_usqr(r,&y3);  //r=y3^2
    FP12_mul(r,&y2);   //r=y2*r
    FP12_copy(&y3,r);
    FP12_mul(&y3,&y0); // y3=r*y0
    FP12_mul(r,&y1); // r=r*y1
    FP12_usqr(r,r); // r=r^2
    FP12_mul(r,&y3); // r=r*y3
    FP12_reduce(r);
#else
// Ghamman & Fouotsa Method

    FP12_usqr(&y0,r);
    FP12_pow(&y1,&y0,x);
#if SIGN_OF_X_FP256BN==NEGATIVEX
	FP12_conj(&y1,&y1);
#endif

    BIG_fshr(x,1);
    FP12_pow(&y2,&y1,x);
#if SIGN_OF_X_FP256BN==NEGATIVEX
	FP12_conj(&y2,&y2);
#endif
    BIG_fshl(x,1); // x must be even
    FP12_conj(&y3,r);
    FP12_mul(&y1,&y3);

    FP12_conj(&y1,&y1);
    FP12_mul(&y1,&y2);

    FP12_pow(&y2,&y1,x);
#if SIGN_OF_X_FP256BN==NEGATIVEX
	FP12_conj(&y2,&y2);
#endif
    FP12_pow(&y3,&y2,x);
#if SIGN_OF_X_FP256BN==NEGATIVEX
	FP12_conj(&y3,&y3);
#endif
    FP12_conj(&y1,&y1);
    FP12_mul(&y3,&y1);

    FP12_conj(&y1,&y1);
    FP12_frob(&y1,&X);
    FP12_frob(&y1,&X);
    FP12_frob(&y1,&X);
    FP12_frob(&y2,&X);
    FP12_frob(&y2,&X);
    FP12_mul(&y1,&y2);

    FP12_pow(&y2,&y3,x);
#if SIGN_OF_X_FP256BN==NEGATIVEX
	FP12_conj(&y2,&y2);
#endif
    FP12_mul(&y2,&y0);
    FP12_mul(&y2,r);

    FP12_mul(&y1,&y2);
    FP12_copy(&y2,&y3);
    FP12_frob(&y2,&X);
    FP12_mul(&y1,&y2);
    FP12_copy(r,&y1);
    FP12_reduce(r);

// Aranha et al method as described by Ghamman & Fouotsa
    /*
    	FP12_usqr(&y0,r);  // t0=f^2
    	FP12_conj(&y3,&y0); // t0=f^-2
    	FP12_pow(&t0,r,x); // t5=f^u
    	FP12_usqr(&y1,&t0); // t1=t5^2
    	FP12_mul(&y3,&t0); // t3=t0*t5

    	FP12_pow(&y0,&y3,x);

    	FP12_pow(&y2,&y0,x);

    	FP12_pow(&y4,&y2,x);

    	FP12_mul(&y4,&y1);
    	FP12_pow(&y1,&y4,x);
    	FP12_conj(&y3,&y3);
    	FP12_mul(&y1,&y3);
    	FP12_mul(&y1,r);

    	FP12_conj(&y3,r);
    	FP12_mul(&y0,r);
    	FP12_frob(&y0,&X); FP12_frob(&y0,&X); FP12_frob(&y0,&X);

    	FP12_mul(&y4,&y3);
    	FP12_frob(&y4,&X);

    	FP12_mul(&t0,&y2);
    	FP12_frob(&t0,&X); FP12_frob(&t0,&X);

    	FP12_mul(&t0,&y0);
    	FP12_mul(&t0,&y4);
    	FP12_mul(&t0,&y1);
    	FP12_copy(r,&t0);
    	FP12_reduce(r);*/

//-----------------------------------
    /*
    	FP12_copy(&y0,r);						// y0=r;
    	FP12_copy(&y1,r);						// y1=r;
    	FP12_copy(&t0,r); FP12_frob(&t0,&X);	// t0=Frobenius(r,X,1);
    	FP12_conj(&y3,&t0); FP12_mul(&y1,&y3);	// y1*=inverse(t0);
    	FP12_frob(&t0,&X); FP12_frob(&t0,&X);	// t0=Frobenius(t0,X,2);
    	FP12_mul(&y1,&t0);						// y1*=t0;

    	FP12_pow(r,r,x);						// r=pow(r,x);
    	FP12_conj(&y3,r); FP12_mul(&y1,&y3);	// y1*=inverse(r);
    	FP12_copy(&t0,r); FP12_frob(&t0,&X);	// t0=Frobenius(r,X,1);
    	FP12_mul(&y0,&t0);						// y0*=t0;
    	FP12_frob(&t0,&X);						// t0=Frobenius(t0,X,1);
    	FP12_mul(&y1,&t0);						// y1*=t0;
    	FP12_frob(&t0,&X);						// t0=Frobenius(t0,X,1);
    	FP12_conj(&y3,&t0); FP12_mul(&y0,&y3);	// y0*=inverse(t0);

    	FP12_pow(r,r,x);						// r=pow(r,x);
    	FP12_mul(&y0,r);						// y0*=r;
    	FP12_copy(&t0,r); FP12_frob(&t0,&X); FP12_frob(&t0,&X); // t0=Frobenius(r,X,2);
    	FP12_conj(&y3,&t0); FP12_mul(&y0,&y3);	// y0*=inverse(t0);
    	FP12_frob(&t0,&X);						// t0=Frobenius(t0,X,1);
    	FP12_mul(&y1,&t0);						// y1*=t0;

    	FP12_pow(r,r,x);						// r=pow(r,x);			// r^x3
    	FP12_copy(&t0,r); FP12_frob(&t0,&X);	// t0=Frobenius(r,X,1);
    	FP12_conj(&y3,&t0); FP12_mul(&y0,&y3);	// y0*=inverse(t0);
    	FP12_frob(&t0,&X);						// t0=Frobenius(t0,X,1);
    	FP12_mul(&y1,&t0);						// y1*=t0;

    	FP12_pow(r,r,x);						// r=pow(r,x);			// r^x4
    	FP12_conj(&y3,r); FP12_mul(&y0,&y3);	// y0*=inverse(r);
    	FP12_copy(&t0,r); FP12_frob(&t0,&X);	// t0=Frobenius(r,X,1);
    	FP12_mul(&y1,&t0);						//y1*=t0;

    	FP12_pow(r,r,x);						// r=pow(r,x);			// r^x5
    	FP12_mul(&y1,r);						// y1*=r;

    	FP12_usqr(&y0,&y0);						// r=y0*y0*y1;
    	FP12_mul(&y0,&y1);
    	FP12_copy(r,&y0);
    	FP12_reduce(r); */
#endif
}

#ifdef USE_GLV_FP256BN
/* GLV method */
static void FP256BN::glv(BIG u[2],BIG e)
{
#if PAIRING_FRIENDLY_FP256BN==BN
    int i,j;
    BIG v[2],t,q;
    DBIG d;
    BIG_rcopy(q,CURVE_Order);
    for (i=0; i<2; i++)
    {
        BIG_rcopy(t,CURVE_W[i]);
//BIG_norm(t); BIG_norm(e);
        BIG_mul(d,t,e);
        BIG_ddiv(v[i],d,q);
        BIG_zero(u[i]);
    }
    BIG_copy(u[0],e);
    for (i=0; i<2; i++)
        for (j=0; j<2; j++)
        {
            BIG_rcopy(t,CURVE_SB[j][i]);
            BIG_modmul(t,v[j],t,q);
            BIG_add(u[i],u[i],q);
            BIG_sub(u[i],u[i],t);
            BIG_mod(u[i],q);
        }

#else
// -(x^2).P = (Beta.x,y)

    BIG x,x2,q;
    BIG_rcopy(x,CURVE_Bnx);
    BIG_smul(x2,x,x);
    BIG_copy(u[0],e);
    BIG_mod(u[0],x2);
    BIG_copy(u[1],e);
    BIG_sdiv(u[1],x2);

    BIG_rcopy(q,CURVE_Order);
    BIG_sub(u[1],q,u[1]);

#endif

    return;
}
#endif // USE_GLV

/* Galbraith & Scott Method */
static void FP256BN::gs(BIG u[4],BIG e)
{
    int i;
#if PAIRING_FRIENDLY_FP256BN==BN
    int j;
    BIG v[4],t,q;
    DBIG d;
    BIG_rcopy(q,CURVE_Order);
    for (i=0; i<4; i++)
    {
        BIG_rcopy(t,CURVE_WB[i]);
//BIG_norm(t); BIG_norm(e);
        BIG_mul(d,t,e);
        BIG_ddiv(v[i],d,q);
        BIG_zero(u[i]);
    }

    BIG_copy(u[0],e);
    for (i=0; i<4; i++)
        for (j=0; j<4; j++)
        {
            BIG_rcopy(t,CURVE_BB[j][i]);
            BIG_modmul(t,v[j],t,q);
            BIG_add(u[i],u[i],q);
            BIG_sub(u[i],u[i],t);
            BIG_mod(u[i],q);
        }

#else

    BIG x,w,q;
	BIG_rcopy(q,CURVE_Order);
    BIG_rcopy(x,CURVE_Bnx);
    BIG_copy(w,e);

    for (i=0; i<3; i++)
    {
        BIG_copy(u[i],w);
        BIG_mod(u[i],x);
        BIG_sdiv(w,x);
    }
	BIG_copy(u[3],w);

/*  */
#if SIGN_OF_X_FP256BN==NEGATIVEX
	BIG_modneg(u[1],u[1],q);
	BIG_modneg(u[3],u[3],q);
#endif

#endif
    return;
}

/* Multiply P by e in group G1 */
void FP256BN::PAIR_G1mul(ECP *P,BIG e)
{
#ifdef USE_GLV_FP256BN   /* Note this method is patented */
    int np,nn;
    ECP Q;
	FP cru;
    BIG t,q;
    BIG u[2];

    BIG_rcopy(q,CURVE_Order);
    glv(u,e);

    //ECP_affine(P);
    ECP_copy(&Q,P); ECP_affine(&Q);
    FP_rcopy(&cru,CURVE_Cru);
    FP_mul(&(Q.x),&(Q.x),&cru);

    /* note that -a.B = a.(-B). Use a or -a depending on which is smaller */

    np=BIG_nbits(u[0]);
    BIG_modneg(t,u[0],q);
    nn=BIG_nbits(t);
    if (nn<np)
    {
        BIG_copy(u[0],t);
        ECP_neg(P);
    }

    np=BIG_nbits(u[1]);
    BIG_modneg(t,u[1],q);
    nn=BIG_nbits(t);
    if (nn<np)
    {
        BIG_copy(u[1],t);
        ECP_neg(&Q);
    }
    BIG_norm(u[0]);
    BIG_norm(u[1]);
    ECP_mul2(P,&Q,u[0],u[1]);

#else
    ECP_mul(P,e);
#endif
}

/* Multiply P by e in group G2 */
void FP256BN::PAIR_G2mul(ECP2 *P,BIG e)
{
#ifdef USE_GS_G2_FP256BN   /* Well I didn't patent it :) */
    int i,np,nn;
    ECP2 Q[4];
    FP2 X;
    FP fx,fy;
    BIG x,y,u[4];

    FP_rcopy(&fx,Fra);
    FP_rcopy(&fy,Frb);
    FP2_from_FPs(&X,&fx,&fy);

#if SEXTIC_TWIST_FP256BN==M_TYPE
	FP2_inv(&X,&X);
	FP2_norm(&X);
#endif

    BIG_rcopy(y,CURVE_Order);
    gs(u,e);


    ECP2_copy(&Q[0],P);
    for (i=1; i<4; i++)
    {
        ECP2_copy(&Q[i],&Q[i-1]);
        ECP2_frob(&Q[i],&X);
    }


    for (i=0; i<4; i++)
    {
        np=BIG_nbits(u[i]);
        BIG_modneg(x,u[i],y);
        nn=BIG_nbits(x);
        if (nn<np)
        {
            BIG_copy(u[i],x);
            ECP2_neg(&Q[i]);
        }
        BIG_norm(u[i]);  
    }

    ECP2_mul4(P,Q,u);

#else
    ECP2_mul(P,e);
#endif
}

/* f=f^e */
void FP256BN::PAIR_GTpow(FP12 *f,BIG e)
{
#ifdef USE_GS_GT_FP256BN   /* Note that this option requires a lot of RAM! Maybe better to use compressed XTR method, see fp4.c */
    int i,np,nn;
    FP12 g[4];
    FP2 X;
    BIG t,q;
	FP fx,fy;
    BIG u[4];

    FP_rcopy(&fx,Fra);
    FP_rcopy(&fy,Frb);
    FP2_from_FPs(&X,&fx,&fy);

    BIG_rcopy(q,CURVE_Order);
    gs(u,e);

    FP12_copy(&g[0],f);
    for (i=1; i<4; i++)
    {
        FP12_copy(&g[i],&g[i-1]);
        FP12_frob(&g[i],&X);
    }

    for (i=0; i<4; i++)
    {
        np=BIG_nbits(u[i]);
        BIG_modneg(t,u[i],q);
        nn=BIG_nbits(t);
        if (nn<np)
        {
            BIG_copy(u[i],t);
            FP12_conj(&g[i],&g[i]);
        }
        BIG_norm(u[i]);        
    }
    FP12_pow4(f,g,u);

#else
    FP12_pow(f,f,e);
#endif
}

/* test group membership test - no longer needed */
/* with GT-Strong curve, now only check that m!=1, conj(m)*m==1, and m.m^{p^4}=m^{p^2} */

/*
int PAIR_GTmember(FP12 *m)
{
	BIG a,b;
	FP2 X;
	FP12 r,w;
	if (FP12_isunity(m)) return 0;
	FP12_conj(&r,m);
	FP12_mul(&r,m);
	if (!FP12_isunity(&r)) return 0;

	BIG_rcopy(a,CURVE_Fra);
	BIG_rcopy(b,CURVE_Frb);
	FP2_from_BIGs(&X,a,b);


	FP12_copy(&r,m); FP12_frob(&r,&X); FP12_frob(&r,&X);
	FP12_copy(&w,&r); FP12_frob(&w,&X); FP12_frob(&w,&X);
	FP12_mul(&w,m);


#ifndef GT_STRONG
	if (!FP12_equals(&w,&r)) return 0;

	BIG_rcopy(a,CURVE_Bnx);

	FP12_copy(&r,m); FP12_pow(&w,&r,a); FP12_pow(&w,&w,a);
	FP12_sqr(&r,&w); FP12_mul(&r,&w); FP12_sqr(&r,&r);

	FP12_copy(&w,m); FP12_frob(&w,&X);
 #endif

	return FP12_equals(&w,&r);
}

*/


#ifdef HAS_MAIN
/*
#if CHOICE==BN254_T

const BIG TEST_Gx={0x18AFF11A,0xF2EF406,0xAF68220,0x171F2E27,0x6BA0959,0x124C50E0,0x450BE27,0x7003EA8,0x8A914};
const BIG TEST_Gy={0x6E010F4,0xA71D07E,0x7ECADA8,0x8260E8E,0x1F79C328,0x17A09412,0xBFAE690,0x1C57CBD1,0x17DF54};

const BIG TEST_Pxa={0x1047D566,0xD83CD71,0x10322E9D,0x991FA93,0xA282C48,0x18AEBEC8,0xCB05850,0x13B4F669,0x21794A};
const BIG TEST_Pxb={0x1E305936,0x16885BF1,0x327060,0xE26F794,0x1547D870,0x1963E5B2,0x1BEBB96C,0x988A33C,0x1A9B47};
const BIG TEST_Pya={0x20FF876,0x4427E67,0x18732211,0xE88E45E,0x174D1A7E,0x17D877ED,0x343AB37,0x97EB453,0xB00D5};
const BIG TEST_Pyb={0x1D746B7B,0x732F4C2,0x122A49B0,0x16267985,0x235DF56,0x10B1E4D,0x14D8F210,0x17A05C3E,0x5ECF8};

#endif

#if CHOICE==BN254_T2

const BIG TEST_Gx={0x15488765,0x46790D7,0xD9900A,0x1DFB43F,0x9F2D307,0xC4724E8,0x5678E51,0x15C3E3A7,0x1BEC8E};
const BIG TEST_Gy={0x3D3273C,0x1AFA5FF,0x1880A139,0xACD34DF,0x17493067,0x10FA4103,0x1D4C9766,0x1A73F3DB,0x2D148};

const BIG TEST_Pxa={0xF8DC275,0xAC27FA,0x11815151,0x152691C8,0x5CDEBF1,0x7D5A965,0x1BF70CE3,0x679A1C8,0xD62CF};
const BIG TEST_Pxb={0x1D17D7A8,0x6B28DF4,0x174A0389,0xFE67E5F,0x1FA97A3C,0x7F5F473,0xFFB5146,0x4BC19A5,0x227010};
const BIG TEST_Pya={0x16CC1F90,0x5284627,0x171B91AB,0x11F843B9,0x1D468755,0x67E279C,0x19FE0EF8,0x1A0CAA6B,0x1CC6CB};
const BIG TEST_Pyb={0x1FF0CF2A,0xBC83255,0x6DD6EE8,0xB8B752F,0x13E484EC,0x1809BE81,0x1A648AA1,0x8CEF3F3,0x86EE};


#endif

#if CHOICE==BN254

const BIG TEST_Gx={0x14BEC4670E4EB7,0xEA2973860F6861,0x35C14B2FC3C28F,0x4402A0B63B9473,0x2074A81D};
const BIG TEST_Gy={0xC284846631CBEB,0x34A6E8D871B3B,0x89FB94A82B2006,0x87B20038771FC,0x6A41108};

const BIG TEST_Pxa={0xE4A00F52183C77,0x554E02DF4F8354,0xB65EB5CF1C2F89,0x8B71A87BFCFC9,0x49EEDB1};
const BIG TEST_Pxb={0xCFB8FA9AA8845D,0x8A9CC76D966697,0x185BA05BF5EC08,0x76140E87D97226,0x1FB93AB6};
const BIG TEST_Pya={0x3644CC1EDF208A,0xA637FB3FF8E257,0x4453DA2BB9E686,0xD14AD3CDF6A1FE,0xCD04A1E};
const BIG TEST_Pyb={0x71BD7630A43C14,0x1CAA9F14EA264E,0x3C3C2DFC765DEF,0xCF59D1A1A7D6EE,0x11FF7795};


#endif
*/
int main()
{
    int i;
    char byt[32];
    csprng rng;
    BIG xa,xb,ya,yb,w,a,b,t1,q,u[2],v[4],m,r;
    ECP2 P,G;
    ECP Q,R;
    FP12 g,gp;
    FP4 t,c,cp,cpm1,cpm2;
    FP2 x,y,X;


    BIG_rcopy(a,CURVE_Fra);
    BIG_rcopy(b,CURVE_Frb);
    FP2_from_BIGs(&X,a,b);

    BIG_rcopy(xa,CURVE_Gx);
    BIG_rcopy(ya,CURVE_Gy);

    ECP_set(&Q,xa,ya);
    if (Q.inf) printf("Failed to set - point not on curve\n");
    else printf("G1 set success\n");

    printf("Q= ");
    ECP_output(&Q);
    printf("\n");

//	BIG_rcopy(r,CURVE_Order); BIG_dec(r,7); BIG_norm(r);
    BIG_rcopy(xa,CURVE_Pxa);
    BIG_rcopy(xb,CURVE_Pxb);
    BIG_rcopy(ya,CURVE_Pya);
    BIG_rcopy(yb,CURVE_Pyb);

    FP2_from_BIGs(&x,xa,xb);
    FP2_from_BIGs(&y,ya,yb);

    ECP2_set(&P,&x,&y);
    if (P.inf) printf("Failed to set - point not on curve\n");
    else printf("G2 set success\n");

    printf("P= ");
    ECP2_output(&P);
    printf("\n");

    for (i=0; i<1000; i++ )
    {

        PAIR_ate(&g,&P,&Q);
        PAIR_fexp(&g);

//	PAIR_GTpow(&g,xa);

    }
    printf("g= ");
    FP12_output(&g);
    printf("\n");

}

#endif
