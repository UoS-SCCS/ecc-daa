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

/* RSA Functions - see main program below */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#include "rsa_RSA2048.h"
#include "rsa_support.h"

using namespace B1024_28;

/* generate an RSA key pair */
void RSA2048::RSA_KEY_PAIR(csprng *RNG,sign32 e,rsa_private_key *PRIV,rsa_public_key *PUB,octet *P, octet* Q)
{
    /* IEEE1363 A16.11/A16.12 more or less */
    BIG t[HFLEN_RSA2048],p1[HFLEN_RSA2048],q1[HFLEN_RSA2048];

    if (RNG!=NULL)
    {

        for (;;)
        {

            FF_random(PRIV->p,RNG,HFLEN_RSA2048);
            while (FF_lastbits(PRIV->p,2)!=3) FF_inc(PRIV->p,1,HFLEN_RSA2048);
            while (!FF_prime(PRIV->p,RNG,HFLEN_RSA2048))
                FF_inc(PRIV->p,4,HFLEN_RSA2048);

            FF_copy(p1,PRIV->p,HFLEN_RSA2048);
            FF_dec(p1,1,HFLEN_RSA2048);

            if (FF_cfactor(p1,e,HFLEN_RSA2048)) continue;
            break;
        }

        for (;;)
        {
            FF_random(PRIV->q,RNG,HFLEN_RSA2048);
            while (FF_lastbits(PRIV->q,2)!=3) FF_inc(PRIV->q,1,HFLEN_RSA2048);
            while (!FF_prime(PRIV->q,RNG,HFLEN_RSA2048))
                FF_inc(PRIV->q,4,HFLEN_RSA2048);

            FF_copy(q1,PRIV->q,HFLEN_RSA2048);
            FF_dec(q1,1,HFLEN_RSA2048);
            if (FF_cfactor(q1,e,HFLEN_RSA2048)) continue;

            break;
        }

    }
    else
    {
        FF_fromOctet(PRIV->p,P,HFLEN_RSA2048);
        FF_fromOctet(PRIV->q,Q,HFLEN_RSA2048);

        FF_copy(p1,PRIV->p,HFLEN_RSA2048);
        FF_dec(p1,1,HFLEN_RSA2048);

        FF_copy(q1,PRIV->q,HFLEN_RSA2048);
        FF_dec(q1,1,HFLEN_RSA2048);
    }

    FF_mul(PUB->n,PRIV->p,PRIV->q,HFLEN_RSA2048);
    PUB->e=e;

    FF_copy(t,p1,HFLEN_RSA2048);
    FF_shr(t,HFLEN_RSA2048);
    FF_init(PRIV->dp,e,HFLEN_RSA2048);
    FF_invmodp(PRIV->dp,PRIV->dp,t,HFLEN_RSA2048);
    if (FF_parity(PRIV->dp)==0) FF_add(PRIV->dp,PRIV->dp,t,HFLEN_RSA2048);
    FF_norm(PRIV->dp,HFLEN_RSA2048);

    FF_copy(t,q1,HFLEN_RSA2048);
    FF_shr(t,HFLEN_RSA2048);
    FF_init(PRIV->dq,e,HFLEN_RSA2048);
    FF_invmodp(PRIV->dq,PRIV->dq,t,HFLEN_RSA2048);
    if (FF_parity(PRIV->dq)==0) FF_add(PRIV->dq,PRIV->dq,t,HFLEN_RSA2048);
    FF_norm(PRIV->dq,HFLEN_RSA2048);

    FF_invmodp(PRIV->c,PRIV->p,PRIV->q,HFLEN_RSA2048);

    return;
}

/* destroy the Private Key structure */
void RSA2048::RSA_PRIVATE_KEY_KILL(rsa_private_key *PRIV)
{
    FF_zero(PRIV->p,HFLEN_RSA2048);
    FF_zero(PRIV->q,HFLEN_RSA2048);
    FF_zero(PRIV->dp,HFLEN_RSA2048);
    FF_zero(PRIV->dq,HFLEN_RSA2048);
    FF_zero(PRIV->c,HFLEN_RSA2048);
}

void RSA2048::RSA_fromOctet(BIG x[],octet *w)
{
	FF_fromOctet(x,w,FFLEN_RSA2048);
}

/* RSA encryption with the public key */
void RSA2048::RSA_ENCRYPT(rsa_public_key *PUB,octet *F,octet *G)
{
    BIG f[FFLEN_RSA2048];
    FF_fromOctet(f,F,FFLEN_RSA2048);

    FF_power(f,f,PUB->e,PUB->n,FFLEN_RSA2048);

    FF_toOctet(G,f,FFLEN_RSA2048);
}

/* RSA decryption with the private key */
void RSA2048::RSA_DECRYPT(rsa_private_key *PRIV,octet *G,octet *F)
{
    BIG g[FFLEN_RSA2048],t[FFLEN_RSA2048],jp[HFLEN_RSA2048],jq[HFLEN_RSA2048];

    FF_fromOctet(g,G,FFLEN_RSA2048);

    FF_dmod(jp,g,PRIV->p,HFLEN_RSA2048);
    FF_dmod(jq,g,PRIV->q,HFLEN_RSA2048);

    FF_skpow(jp,jp,PRIV->dp,PRIV->p,HFLEN_RSA2048);
    FF_skpow(jq,jq,PRIV->dq,PRIV->q,HFLEN_RSA2048);


    FF_zero(g,FFLEN_RSA2048);
    FF_copy(g,jp,HFLEN_RSA2048);
    FF_mod(jp,PRIV->q,HFLEN_RSA2048);
    if (FF_comp(jp,jq,HFLEN_RSA2048)>0)
        FF_add(jq,jq,PRIV->q,HFLEN_RSA2048);
    FF_sub(jq,jq,jp,HFLEN_RSA2048);
    FF_norm(jq,HFLEN_RSA2048);

    FF_mul(t,PRIV->c,jq,HFLEN_RSA2048);
    FF_dmod(jq,t,PRIV->q,HFLEN_RSA2048);

    FF_mul(t,jq,PRIV->p,HFLEN_RSA2048);
    FF_add(g,t,g,FFLEN_RSA2048);
    FF_norm(g,FFLEN_RSA2048);

    FF_toOctet(F,g,FFLEN_RSA2048);

    return;
}

