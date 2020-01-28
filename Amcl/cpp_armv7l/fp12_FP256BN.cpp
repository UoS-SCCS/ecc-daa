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

/* AMCL Fp^12 functions */
/* SU=m, m is Stack Usage (no lazy )*/
/* FP12 elements are of the form a+i.b+i^2.c */

#include "fp12_FP256BN.h"

using namespace B256_28;

/* return 1 if b==c, no branching */
static int teq(sign32 b,sign32 c)
{
    sign32 x=b^c;
    x-=1;  // if x=0, x now -1
    return (int)((x>>31)&1);
}


/* Constant time select from pre-computed table */
static void FP12_select(FP256BN::FP12 *f,FP256BN::FP12 g[],sign32 b)
{
    FP256BN::FP12 invf;
    sign32 m=b>>31;
    sign32 babs=(b^m)-m;

    babs=(babs-1)/2;

    FP12_cmove(f,&g[0],teq(babs,0));  // conditional move
    FP12_cmove(f,&g[1],teq(babs,1));
    FP12_cmove(f,&g[2],teq(babs,2));
    FP12_cmove(f,&g[3],teq(babs,3));
    FP12_cmove(f,&g[4],teq(babs,4));
    FP12_cmove(f,&g[5],teq(babs,5));
    FP12_cmove(f,&g[6],teq(babs,6));
    FP12_cmove(f,&g[7],teq(babs,7));

    FP12_copy(&invf,f);
    FP12_conj(&invf,&invf);  // 1/f
    FP12_cmove(f,&invf,(int)(m&1));
}

/* test x==0 ? */
/* SU= 8 */
int FP256BN::FP12_iszilch(FP12 *x)
{
    if (FP4_iszilch(&(x->a)) && FP4_iszilch(&(x->b)) && FP4_iszilch(&(x->c))) return 1;
    return 0;
}

/* test x==1 ? */
/* SU= 8 */
int FP256BN::FP12_isunity(FP12 *x)
{
    if (FP4_isunity(&(x->a)) && FP4_iszilch(&(x->b)) && FP4_iszilch(&(x->c))) return 1;
    return 0;
}

/* FP12 copy w=x */
/* SU= 16 */
void FP256BN::FP12_copy(FP12 *w,FP12 *x)
{
    if (x==w) return;
    FP4_copy(&(w->a),&(x->a));
    FP4_copy(&(w->b),&(x->b));
    FP4_copy(&(w->c),&(x->c));
}

/* FP12 w=1 */
/* SU= 8 */
void FP256BN::FP12_one(FP12 *w)
{
    FP4_one(&(w->a));
    FP4_zero(&(w->b));
    FP4_zero(&(w->c));
}

/* return 1 if x==y, else 0 */
/* SU= 16 */
int FP256BN::FP12_equals(FP12 *x,FP12 *y)
{
    if (FP4_equals(&(x->a),&(y->a)) && FP4_equals(&(x->b),&(y->b)) && FP4_equals(&(x->b),&(y->b)))
        return 1;
    return 0;
}

/* Set w=conj(x) */
/* SU= 8 */
void FP256BN::FP12_conj(FP12 *w,FP12 *x)
{
    FP12_copy(w,x);
    FP4_conj(&(w->a),&(w->a));
    FP4_nconj(&(w->b),&(w->b));
    FP4_conj(&(w->c),&(w->c));
}

/* Create FP12 from FP4 */
/* SU= 8 */
void FP256BN::FP12_from_FP4(FP12 *w,FP4 *a)
{
    FP4_copy(&(w->a),a);
    FP4_zero(&(w->b));
    FP4_zero(&(w->c));
}

/* Create FP12 from 3 FP4's */
/* SU= 16 */
void FP256BN::FP12_from_FP4s(FP12 *w,FP4 *a,FP4 *b,FP4 *c)
{
    FP4_copy(&(w->a),a);
    FP4_copy(&(w->b),b);
    FP4_copy(&(w->c),c);
}

/* Granger-Scott Unitary Squaring. This does not benefit from lazy reduction */
/* SU= 600 */
void FP256BN::FP12_usqr(FP12 *w,FP12 *x)
{
    FP4 A,B,C,D;

    FP4_copy(&A,&(x->a));   

    FP4_sqr(&(w->a),&(x->a));  // Wa XES=2
    FP4_add(&D,&(w->a),&(w->a)); // Wa XES=4
    FP4_add(&(w->a),&D,&(w->a)); // Wa XES=6

    FP4_norm(&(w->a));
    FP4_nconj(&A,&A);

    FP4_add(&A,&A,&A);
    FP4_add(&(w->a),&(w->a),&A); // Wa XES=8
    FP4_sqr(&B,&(x->c));
    FP4_times_i(&B);

    FP4_add(&D,&B,&B);
    FP4_add(&B,&B,&D);
    FP4_norm(&B);

    FP4_sqr(&C,&(x->b));

    FP4_add(&D,&C,&C);
    FP4_add(&C,&C,&D);

    FP4_norm(&C);
    FP4_conj(&(w->b),&(x->b));
    FP4_add(&(w->b),&(w->b),&(w->b));
    FP4_nconj(&(w->c),&(x->c));

    FP4_add(&(w->c),&(w->c),&(w->c));
    FP4_add(&(w->b),&B,&(w->b));
    FP4_add(&(w->c),&C,&(w->c));
/*
	FP n;
	FP_one(&n);
	FP4_qmul(&(w->a),&(w->a),&n);
	FP4_qmul(&(w->b),&(w->b),&n);
	FP4_qmul(&(w->c),&(w->c),&n);
*/

	//FP12_norm(w);
    FP12_reduce(w);	    /* reduce here as in pow function repeated squarings would trigger multiple reductions */
}

/* FP12 squaring w=x^2 */
/* SU= 600 */
void FP256BN::FP12_sqr(FP12 *w,FP12 *x)
{
    /* Use Chung-Hasan SQR2 method from http://cacr.uwaterloo.ca/techreports/2006/cacr2006-24.pdf */

    FP4 A,B,C,D;

    FP4_sqr(&A,&(x->a));
    FP4_mul(&B,&(x->b),&(x->c));
    FP4_add(&B,&B,&B);
FP4_norm(&B);
    FP4_sqr(&C,&(x->c));

    FP4_mul(&D,&(x->a),&(x->b));
    FP4_add(&D,&D,&D);
    FP4_add(&(w->c),&(x->a),&(x->c));
    FP4_add(&(w->c),&(x->b),&(w->c));
FP4_norm(&(w->c));	

    FP4_sqr(&(w->c),&(w->c));

    FP4_copy(&(w->a),&A);
    FP4_add(&A,&A,&B);

    FP4_norm(&A);

    FP4_add(&A,&A,&C);
    FP4_add(&A,&A,&D);

    FP4_norm(&A);
    FP4_neg(&A,&A);
    FP4_times_i(&B);
    FP4_times_i(&C);

    FP4_add(&(w->a),&(w->a),&B);
    FP4_add(&(w->b),&C,&D);
    FP4_add(&(w->c),&(w->c),&A);

    FP12_norm(w);
}

/* FP12 full multiplication w=w*y */


/* SU= 896 */
/* FP12 full multiplication w=w*y */
void FP256BN::FP12_mul(FP12 *w,FP12 *y)
{
    FP4 z0,z1,z2,z3,t0,t1;

    FP4_mul(&z0,&(w->a),&(y->a));
    FP4_mul(&z2,&(w->b),&(y->b));  //

    FP4_add(&t0,&(w->a),&(w->b));
    FP4_add(&t1,&(y->a),&(y->b));  //

FP4_norm(&t0);
FP4_norm(&t1);

    FP4_mul(&z1,&t0,&t1);
    FP4_add(&t0,&(w->b),&(w->c));
    FP4_add(&t1,&(y->b),&(y->c));  //

FP4_norm(&t0);
FP4_norm(&t1);

    FP4_mul(&z3,&t0,&t1);

    FP4_neg(&t0,&z0);
    FP4_neg(&t1,&z2);

    FP4_add(&z1,&z1,&t0);   // z1=z1-z0
//    FP4_norm(&z1);
    FP4_add(&(w->b),&z1,&t1);
// z1=z1-z2
    FP4_add(&z3,&z3,&t1);        // z3=z3-z2
    FP4_add(&z2,&z2,&t0);        // z2=z2-z0

    FP4_add(&t0,&(w->a),&(w->c));
    FP4_add(&t1,&(y->a),&(y->c));

FP4_norm(&t0);
FP4_norm(&t1);

    FP4_mul(&t0,&t1,&t0);
    FP4_add(&z2,&z2,&t0);

    FP4_mul(&t0,&(w->c),&(y->c));
    FP4_neg(&t1,&t0);

    FP4_add(&(w->c),&z2,&t1);
    FP4_add(&z3,&z3,&t1);
    FP4_times_i(&t0);
    FP4_add(&(w->b),&(w->b),&t0);
FP4_norm(&z3);
    FP4_times_i(&z3);
    FP4_add(&(w->a),&z0,&z3);

    FP12_norm(w);
}

/* FP12 multiplication w=w*y */
/* SU= 744 */
/* catering for special case that arises from special form of ATE pairing line function */
void FP256BN::FP12_smul(FP12 *w,FP12 *y,int type)
{
    FP4 z0,z1,z2,z3,t0,t1;

	if (type==D_TYPE)
	{ // y->c is 0

		FP4_copy(&z3,&(w->b));
		FP4_mul(&z0,&(w->a),&(y->a));

		FP4_pmul(&z2,&(w->b),&(y->b).a);
		FP4_add(&(w->b),&(w->a),&(w->b));
		FP4_copy(&t1,&(y->a));
		FP2_add(&t1.a,&t1.a,&(y->b).a);

		FP4_norm(&t1);
		FP4_norm(&(w->b));

		FP4_mul(&(w->b),&(w->b),&t1);
		FP4_add(&z3,&z3,&(w->c));
		FP4_norm(&z3);
		FP4_pmul(&z3,&z3,&(y->b).a);
		FP4_neg(&t0,&z0);
		FP4_neg(&t1,&z2);

		FP4_add(&(w->b),&(w->b),&t0);   // z1=z1-z0
//    FP4_norm(&(w->b));
		FP4_add(&(w->b),&(w->b),&t1);   // z1=z1-z2

		FP4_add(&z3,&z3,&t1);        // z3=z3-z2
		FP4_add(&z2,&z2,&t0);        // z2=z2-z0

		FP4_add(&t0,&(w->a),&(w->c));

		FP4_norm(&t0);
		FP4_norm(&z3);

		FP4_mul(&t0,&(y->a),&t0);
		FP4_add(&(w->c),&z2,&t0);

		FP4_times_i(&z3);
		FP4_add(&(w->a),&z0,&z3);
	}

	if (type==M_TYPE)
	{ // y->b is zero
		FP4_mul(&z0,&(w->a),&(y->a));
		FP4_add(&t0,&(w->a),&(w->b));
		FP4_norm(&t0);

		FP4_mul(&z1,&t0,&(y->a));
		FP4_add(&t0,&(w->b),&(w->c));
		FP4_norm(&t0);

		FP4_pmul(&z3,&t0,&(y->c).b);
		FP4_times_i(&z3);

		FP4_neg(&t0,&z0);
		FP4_add(&z1,&z1,&t0);   // z1=z1-z0

		FP4_copy(&(w->b),&z1);

		FP4_copy(&z2,&t0);

		FP4_add(&t0,&(w->a),&(w->c));
		FP4_add(&t1,&(y->a),&(y->c));

		FP4_norm(&t0);
		FP4_norm(&t1);

		FP4_mul(&t0,&t1,&t0);
		FP4_add(&z2,&z2,&t0);

		FP4_pmul(&t0,&(w->c),&(y->c).b);
		FP4_times_i(&t0);
		FP4_neg(&t1,&t0);
		FP4_times_i(&t0);

		FP4_add(&(w->c),&z2,&t1);
		FP4_add(&z3,&z3,&t1);

		FP4_add(&(w->b),&(w->b),&t0);
		FP4_norm(&z3);
		FP4_times_i(&z3);
		FP4_add(&(w->a),&z0,&z3);
	}
    FP12_norm(w);
}

/* Set w=1/x */
/* SU= 600 */
void FP256BN::FP12_inv(FP12 *w,FP12 *x)
{
    FP4 f0,f1,f2,f3;
//    FP12_norm(x);

    FP4_sqr(&f0,&(x->a));
    FP4_mul(&f1,&(x->b),&(x->c));
    FP4_times_i(&f1);
    FP4_sub(&f0,&f0,&f1);  /* y.a */
	FP4_norm(&f0); 		

    FP4_sqr(&f1,&(x->c));
    FP4_times_i(&f1);
    FP4_mul(&f2,&(x->a),&(x->b));
    FP4_sub(&f1,&f1,&f2);  /* y.b */
	FP4_norm(&f1); 

    FP4_sqr(&f2,&(x->b));
    FP4_mul(&f3,&(x->a),&(x->c));
    FP4_sub(&f2,&f2,&f3);  /* y.c */
	FP4_norm(&f2); 

    FP4_mul(&f3,&(x->b),&f2);
    FP4_times_i(&f3);
    FP4_mul(&(w->a),&f0,&(x->a));
    FP4_add(&f3,&(w->a),&f3);
    FP4_mul(&(w->c),&f1,&(x->c));
    FP4_times_i(&(w->c));

    FP4_add(&f3,&(w->c),&f3);
	FP4_norm(&f3);
	
    FP4_inv(&f3,&f3);

    FP4_mul(&(w->a),&f0,&f3);
    FP4_mul(&(w->b),&f1,&f3);
    FP4_mul(&(w->c),&f2,&f3);

}

/* constant time powering by small integer of max length bts */

void FP256BN::FP12_pinpow(FP12 *r,int e,int bts)
{
    int i,b;
    FP12 R[2];

    FP12_one(&R[0]);
    FP12_copy(&R[1],r);

    for (i=bts-1; i>=0; i--)
    {
        b=(e>>i)&1;
        FP12_mul(&R[1-b],&R[b]);
        FP12_usqr(&R[b],&R[b]);
    }
    FP12_copy(r,&R[0]);
}

/* Compressed powering of unitary elements y=x^(e mod r) */

void FP256BN::FP12_compow(FP4 *c,FP12 *x,BIG e,BIG r)
{
    FP12 g1,g2;
	FP4 cp,cpm1,cpm2;
    FP2 f;
	BIG q,a,b,m;

    BIG_rcopy(a,Fra);
    BIG_rcopy(b,Frb);
    FP2_from_BIGs(&f,a,b);

    BIG_rcopy(q,Modulus);

    FP12_copy(&g1,x);
	FP12_copy(&g2,x);

    BIG_copy(m,q);
    BIG_mod(m,r);

    BIG_copy(a,e);
    BIG_mod(a,m);

    BIG_copy(b,e);
    BIG_sdiv(b,m);

    FP12_trace(c,&g1);

	if (BIG_iszilch(b))
	{
		FP4_xtr_pow(c,c,e);
		return;
	}

    FP12_frob(&g2,&f);
    FP12_trace(&cp,&g2);

    FP12_conj(&g1,&g1);
    FP12_mul(&g2,&g1);
    FP12_trace(&cpm1,&g2);
    FP12_mul(&g2,&g1);
    FP12_trace(&cpm2,&g2);

    FP4_xtr_pow2(c,&cp,c,&cpm1,&cpm2,a,b);

}

/* Note this is simple square and multiply, so not side-channel safe */
/* But fast for final exponentiation where exponent is not a secret */

void FP256BN::FP12_pow(FP12 *r,FP12 *a,BIG b)
{
    FP12 w,sf;
    BIG b1,b3;
    int i,nb,bt;
	BIG_copy(b1,b);
	BIG_norm(b1);
    //BIG_norm(b);
	BIG_pmul(b3,b1,3);
	BIG_norm(b3);
	FP12_copy(&sf,a);
	FP12_norm(&sf);
    FP12_copy(&w,&sf);

	nb=BIG_nbits(b3);
	for (i=nb-2;i>=1;i--)
	{
		FP12_usqr(&w,&w);
		bt=BIG_bit(b3,i)-BIG_bit(b1,i);
		if (bt==1)
			FP12_mul(&w,&sf);
		if (bt==-1)
		{
			FP12_conj(&sf,&sf);
			FP12_mul(&w,&sf);
			FP12_conj(&sf,&sf);
		}
	}

	FP12_copy(r,&w);
	FP12_reduce(r);


}


/* SU= 528 */
/* set r=a^b */
/* Note this is simple square and multiply, so not side-channel safe

void FP256BN::FP12_pow(FP12 *r,FP12 *a,BIG b)
{
    FP12 w;
    BIG z,zilch;
    int bt;
    BIG_zero(zilch);
    BIG_norm(b);
    BIG_copy(z,b);
    FP12_copy(&w,a);
    FP12_one(r);

    while(1)
    {
        bt=BIG_parity(z);
        BIG_shr(z,1);
        if (bt)
            FP12_mul(r,&w);
        if (BIG_comp(z,zilch)==0) break;
        FP12_usqr(&w,&w);
    }

    FP12_reduce(r);
}  */


/* p=q0^u0.q1^u1.q2^u2.q3^u3 */
/* Side channel attack secure */
// Bos & Costello https://eprint.iacr.org/2013/458.pdf
// Faz-Hernandez & Longa & Sanchez  https://eprint.iacr.org/2013/158.pdf

void FP256BN::FP12_pow4(FP12 *p,FP12 *q,BIG u[4])
{
    int i,j,k,nb,pb,bt;
	FP12 g[8],r;
	BIG t[4],mt;
    sign8 w[NLEN_B256_28*BASEBITS_B256_28+1];
    sign8 s[NLEN_B256_28*BASEBITS_B256_28+1];

    for (i=0; i<4; i++)
        BIG_copy(t[i],u[i]);


// Precomputed table
    FP12_copy(&g[0],&q[0]); // q[0]
    FP12_copy(&g[1],&g[0]);
	FP12_mul(&g[1],&q[1]);	// q[0].q[1]
    FP12_copy(&g[2],&g[0]);
	FP12_mul(&g[2],&q[2]);	// q[0].q[2]
	FP12_copy(&g[3],&g[1]);
	FP12_mul(&g[3],&q[2]);	// q[0].q[1].q[2]
	FP12_copy(&g[4],&g[0]);
	FP12_mul(&g[4],&q[3]);  // q[0].q[3]
	FP12_copy(&g[5],&g[1]);
	FP12_mul(&g[5],&q[3]);	// q[0].q[1].q[3]
	FP12_copy(&g[6],&g[2]);
	FP12_mul(&g[6],&q[3]);	// q[0].q[2].q[3]
	FP12_copy(&g[7],&g[3]);
	FP12_mul(&g[7],&q[3]);	// q[0].q[1].q[2].q[3]

// Make it odd
	pb=1-BIG_parity(t[0]);
	BIG_inc(t[0],pb);
	BIG_norm(t[0]);

// Number of bits
    BIG_zero(mt);
    for (i=0; i<4; i++)
    {
        BIG_or(mt,mt,t[i]);
    }
    nb=1+BIG_nbits(mt);

// Sign pivot 
	s[nb-1]=1;
	for (i=0;i<nb-1;i++)
	{
        BIG_fshr(t[0],1);
		s[i]=2*BIG_parity(t[0])-1;
	}

// Recoded exponent
    for (i=0; i<nb; i++)
    {
		w[i]=0;
		k=1;
		for (j=1; j<4; j++)
		{
			bt=s[i]*BIG_parity(t[j]);
			BIG_fshr(t[j],1);

			BIG_dec(t[j],(bt>>1));
			BIG_norm(t[j]);
			w[i]+=bt*k;
			k*=2;
        }
    }		

// Main loop
	FP12_select(p,g,2*w[nb-1]+1);
    for (i=nb-2; i>=0; i--)
    {
        FP12_select(&r,g,2*w[i]+s[i]);
		FP12_usqr(p,p);
        FP12_mul(p,&r);
    }
// apply correction
	FP12_conj(&r,&q[0]);   
	FP12_mul(&r,p);
	FP12_cmove(p,&r,pb);

	FP12_reduce(p);
}

/* p=q0^u0.q1^u1.q2^u2.q3^u3 */
/* Side channel attack secure */
/*
void FP256BN::FP12_pow4(FP12 *p,FP12 *q,BIG u[4])
{
    int i,j,a[4],nb,m,pb;
    FP12 g[8],c,r,v;
    BIG t[4],mt;
    sign8 w[NLEN_B256_28*BASEBITS_B256_28+1];

    for (i=0; i<4; i++)
        BIG_copy(t[i],u[i]);

    FP12_copy(&g[0],&q[0]);
    FP12_conj(&r,&q[1]);
    FP12_mul(&g[0],&r);  // P/Q 
    FP12_copy(&g[1],&g[0]);
    FP12_copy(&g[2],&g[0]);
    FP12_copy(&g[3],&g[0]);
    FP12_copy(&g[4],&q[0]);
    FP12_mul(&g[4],&q[1]);  // P*Q 
    FP12_copy(&g[5],&g[4]);
    FP12_copy(&g[6],&g[4]);
    FP12_copy(&g[7],&g[4]);

    FP12_copy(&v,&q[2]);
    FP12_conj(&r,&q[3]);
    FP12_mul(&v,&r);       // R/S 
    FP12_conj(&r,&v);
    FP12_mul(&g[1],&r);
    FP12_mul(&g[2],&v);
    FP12_mul(&g[5],&r);
    FP12_mul(&g[6],&v);
    FP12_copy(&v,&q[2]);
    FP12_mul(&v,&q[3]);      // R*S 
    FP12_conj(&r,&v);
    FP12_mul(&g[0],&r);
    FP12_mul(&g[3],&v);
    FP12_mul(&g[4],&r);
    FP12_mul(&g[7],&v);

    // if power is even add 1 to power, and add q to correction 
    FP12_one(&c);

    BIG_zero(mt);
    for (i=0; i<4; i++)
    {

		pb=BIG_parity(t[i]);
		BIG_inc(t[i],1-pb);
		BIG_norm(t[i]);
		FP12_copy(&r,&c);
		FP12_mul(&r,&q[i]);
		FP12_cmove(&c,&r,1-pb);

        BIG_add(mt,mt,t[i]);
        BIG_norm(mt);
    }

    FP12_conj(&c,&c);
    nb=1+BIG_nbits(mt);

    // convert exponent to signed 1-bit window 
    for (j=0; j<nb; j++)
    {
        for (i=0; i<4; i++)
        {
            a[i]=BIG_lastbits(t[i],2)-2;
            BIG_dec(t[i],a[i]);
            BIG_norm(t[i]);
            BIG_fshr(t[i],1);
        }
        w[j]=8*a[0]+4*a[1]+2*a[2]+a[3];
    }
    w[nb]=8*BIG_lastbits(t[0],2)+4*BIG_lastbits(t[1],2)+2*BIG_lastbits(t[2],2)+BIG_lastbits(t[3],2);
    FP12_copy(p,&g[(w[nb]-1)/2]);

    for (i=nb-1; i>=0; i--)
    {
		FP12_select(&r,g,w[i]);
		FP12_usqr(p,p);
        FP12_mul(p,&r);
    }
    FP12_mul(p,&c); // apply correction 
    FP12_reduce(p);
}
*/

/* Set w=w^p using Frobenius */
/* SU= 160 */
void FP256BN::FP12_frob(FP12 *w,FP2 *f)
{
    FP2 f2,f3;
    FP2_sqr(&f2,f);     /* f2=f^2 */
    FP2_mul(&f3,&f2,f); /* f3=f^3 */

    FP4_frob(&(w->a),&f3);
    FP4_frob(&(w->b),&f3);
    FP4_frob(&(w->c),&f3);

    FP4_pmul(&(w->b),&(w->b),f);
    FP4_pmul(&(w->c),&(w->c),&f2);
}

/* SU= 8 */
/* normalise all components of w */
void FP256BN::FP12_norm(FP12 *w)
{
    FP4_norm(&(w->a));
    FP4_norm(&(w->b));
    FP4_norm(&(w->c));
}

/* SU= 8 */
/* reduce all components of w */
void FP256BN::FP12_reduce(FP12 *w)
{
    FP4_reduce(&(w->a));
    FP4_reduce(&(w->b));
    FP4_reduce(&(w->c));
}

/* trace function w=trace(x) */
/* SU= 8 */
void FP256BN::FP12_trace(FP4 *w,FP12 *x)
{
    FP4_imul(w,&(x->a),3);
    FP4_reduce(w);
}

/* SU= 8 */
/* Output w in hex */
void FP256BN::FP12_output(FP12 *w)
{
    printf("[");
    FP4_output(&(w->a));
    printf(",");
    FP4_output(&(w->b));
    printf(",");
    FP4_output(&(w->c));
    printf("]");
}

/* SU= 64 */
/* Convert g to octet string w */
void FP256BN::FP12_toOctet(octet *W,FP12 *g)
{
    BIG a;
    W->len=12*MODBYTES_B256_28;

    FP_redc(a,&(g->a.a.a));
    BIG_toBytes(&(W->val[0]),a);
    FP_redc(a,&(g->a.a.b));
    BIG_toBytes(&(W->val[MODBYTES_B256_28]),a);
    FP_redc(a,&(g->a.b.a));
    BIG_toBytes(&(W->val[2*MODBYTES_B256_28]),a);
    FP_redc(a,&(g->a.b.b));
    BIG_toBytes(&(W->val[3*MODBYTES_B256_28]),a);
    FP_redc(a,&(g->b.a.a));
    BIG_toBytes(&(W->val[4*MODBYTES_B256_28]),a);
    FP_redc(a,&(g->b.a.b));
    BIG_toBytes(&(W->val[5*MODBYTES_B256_28]),a);
    FP_redc(a,&(g->b.b.a));
    BIG_toBytes(&(W->val[6*MODBYTES_B256_28]),a);
    FP_redc(a,&(g->b.b.b));
    BIG_toBytes(&(W->val[7*MODBYTES_B256_28]),a);
    FP_redc(a,&(g->c.a.a));
    BIG_toBytes(&(W->val[8*MODBYTES_B256_28]),a);
    FP_redc(a,&(g->c.a.b));
    BIG_toBytes(&(W->val[9*MODBYTES_B256_28]),a);
    FP_redc(a,&(g->c.b.a));
    BIG_toBytes(&(W->val[10*MODBYTES_B256_28]),a);
    FP_redc(a,&(g->c.b.b));
    BIG_toBytes(&(W->val[11*MODBYTES_B256_28]),a);
}

/* SU= 24 */
/* Restore g from octet string w */
void FP256BN::FP12_fromOctet(FP12 *g,octet *W)
{
	BIG b;
    BIG_fromBytes(b,&W->val[0]);
    FP_nres(&(g->a.a.a),b);
    BIG_fromBytes(b,&W->val[MODBYTES_B256_28]);
    FP_nres(&(g->a.a.b),b);
    BIG_fromBytes(b,&W->val[2*MODBYTES_B256_28]);
    FP_nres(&(g->a.b.a),b);
    BIG_fromBytes(b,&W->val[3*MODBYTES_B256_28]);
    FP_nres(&(g->a.b.b),b);
    BIG_fromBytes(b,&W->val[4*MODBYTES_B256_28]);
    FP_nres(&(g->b.a.a),b);
    BIG_fromBytes(b,&W->val[5*MODBYTES_B256_28]);
    FP_nres(&(g->b.a.b),b);
    BIG_fromBytes(b,&W->val[6*MODBYTES_B256_28]);
    FP_nres(&(g->b.b.a),b);
    BIG_fromBytes(b,&W->val[7*MODBYTES_B256_28]);
    FP_nres(&(g->b.b.b),b);
    BIG_fromBytes(b,&W->val[8*MODBYTES_B256_28]);
    FP_nres(&(g->c.a.a),b);
    BIG_fromBytes(b,&W->val[9*MODBYTES_B256_28]);
    FP_nres(&(g->c.a.b),b);
    BIG_fromBytes(b,&W->val[10*MODBYTES_B256_28]);
    FP_nres(&(g->c.b.a),b);
    BIG_fromBytes(b,&W->val[11*MODBYTES_B256_28]);
    FP_nres(&(g->c.b.b),b);
}

/* Move b to a if d=1 */
void FP256BN::FP12_cmove(FP12 *f,FP12 *g,int d)
{
    FP4_cmove(&(f->a),&(g->a),d);
    FP4_cmove(&(f->b),&(g->b),d);
    FP4_cmove(&(f->c),&(g->c),d);
}



/*
int main(){
		FP2 f,w0,w1;
		FP4 t0,t1,t2;
		FP12 w,t,lv;
		BIG a,b;
		BIG p;

		//Test w^(P^4) = w mod p^2
//		BIG_randomnum(a);
//		BIG_randomnum(b);
//		BIG_mod(a,Modulus); BIG_mod(b,Modulus);
	BIG_zero(a); BIG_zero(b); BIG_inc(a,1); BIG_inc(b,2); FP_nres(a); FP_nres(b);
		FP2_from_zps(&w0,a,b);

//		BIG_randomnum(a); BIG_randomnum(b);
//		BIG_mod(a,Modulus); BIG_mod(b,Modulus);
	BIG_zero(a); BIG_zero(b); BIG_inc(a,3); BIG_inc(b,4); FP_nres(a); FP_nres(b);
		FP2_from_zps(&w1,a,b);

		FP4_from_FP2s(&t0,&w0,&w1);
		FP4_reduce(&t0);

//		BIG_randomnum(a);
//		BIG_randomnum(b);
//		BIG_mod(a,Modulus); BIG_mod(b,Modulus);
		BIG_zero(a); BIG_zero(b); BIG_inc(a,5); BIG_inc(b,6); FP_nres(a); FP_nres(b);
		FP2_from_zps(&w0,a,b);

//		BIG_randomnum(a); BIG_randomnum(b);
//		BIG_mod(a,Modulus); BIG_mod(b,Modulus);

		BIG_zero(a); BIG_zero(b); BIG_inc(a,7); BIG_inc(b,8); FP_nres(a); FP_nres(b);
		FP2_from_zps(&w1,a,b);

		FP4_from_FP2s(&t1,&w0,&w1);
		FP4_reduce(&t1);

//		BIG_randomnum(a);
//		BIG_randomnum(b);
//		BIG_mod(a,Modulus); BIG_mod(b,Modulus);
		BIG_zero(a); BIG_zero(b); BIG_inc(a,9); BIG_inc(b,10); FP_nres(a); FP_nres(b);
		FP2_from_zps(&w0,a,b);

//		BIG_randomnum(a); BIG_randomnum(b);
//		BIG_mod(a,Modulus); BIG_mod(b,Modulus);
		BIG_zero(a); BIG_zero(b); BIG_inc(a,11); BIG_inc(b,12); FP_nres(a); FP_nres(b);
		FP2_from_zps(&w1,a,b);

		FP4_from_FP2s(&t2,&w0,&w1);
		FP4_reduce(&t2);

		FP12_from_FP4s(&w,&t0,&t1,&t2);

		FP12_copy(&t,&w);

		printf("w= ");
		FP12_output(&w);
		printf("\n");

		BIG_rcopy(p,Modulus);
		//BIG_zero(p); BIG_inc(p,7);

		FP12_pow(&w,&w,p);

		printf("w^p= ");
		FP12_output(&w);
		printf("\n");

		FP2_gfc(&f,12);
		FP12_frob(&t,&f);
		printf("w^p= ");
		FP12_output(&t);
		printf("\n");

//exit(0);

		FP12_pow(&w,&w,p);
		//printf("w^p^2= ");
		//FP12_output(&w);
		//printf("\n");
		FP12_pow(&w,&w,p);
		//printf("w^p^3= ");
		//FP12_output(&w);
		//printf("\n");
		FP12_pow(&w,&w,p);
		FP12_pow(&w,&w,p);
		FP12_pow(&w,&w,p);
		printf("w^p^6= ");
		FP12_output(&w);
		printf("\n");
		FP12_pow(&w,&w,p);
		FP12_pow(&w,&w,p);
		printf("w^p^8= ");
		FP12_output(&w);
		printf("\n");
		FP12_pow(&w,&w,p);
		FP12_pow(&w,&w,p);
		FP12_pow(&w,&w,p);
		printf("w^p^11= ");
		FP12_output(&w);
		printf("\n");

	//	BIG_zero(p); BIG_inc(p,7); BIG_norm(p);
		FP12_pow(&w,&w,p);

		printf("w^p12= ");
		FP12_output(&w);
		printf("\n");
//exit(0);

		FP12_inv(&t,&w);
		printf("1/w mod p^4 = ");
		FP12_output(&t);
		printf("\n");

		FP12_inv(&w,&t);
		printf("1/(1/w) mod p^4 = ");
		FP12_output(&w);
		printf("\n");



	FP12_inv(&lv,&w);
//printf("w= "); FP12_output(&w); printf("\n");
	FP12_conj(&w,&w);
//printf("w= "); FP12_output(&w); printf("\n");
//exit(0);
	FP12_mul(&w,&w,&lv);
//printf("w= "); FP12_output(&w); printf("\n");
	FP12_copy(&lv,&w);
	FP12_frob(&w,&f);
	FP12_frob(&w,&f);
	FP12_mul(&w,&w,&lv);

//printf("w= "); FP12_output(&w); printf("\n");
//exit(0);

w.unitary=0;
FP12_conj(&lv,&w);
	printf("rx= "); FP12_output(&lv); printf("\n");
FP12_inv(&lv,&w);
	printf("ry= "); FP12_output(&lv); printf("\n");


		return 0;
}

*/
