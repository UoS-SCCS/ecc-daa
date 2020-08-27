/*******************************************************************************
* File:        Amcl_utils.h
*
* Description: Utility functions to use with the AMCL crypto library
*
* Author:      Chris Newton
* Created:     Tuesday 27 November 2018
*
* (C) Copyright 2018, University of Surrey.
*
*******************************************************************************/

/*******************************************************************************
*                                                                              *
* (C) Copyright 2019 University of Surrey                                      *
*                                                                              *
* Redistribution and use in source and binary forms, with or without           *
* modification, are permitted provided that the following conditions are met:  *
*                                                                              *
* 1. Redistributions of source code must retain the above copyright notice,    *
* this list of conditions and the following disclaimer.                        *
*                                                                              *
* 2. Redistributions in binary form must reproduce the above copyright notice, *
* this list of conditions and the following disclaimer in the documentation    *
* and/or other materials provided with the distribution.                       *
*                                                                              *
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"  *
* AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE    *
* IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE   *
* ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE    *
* LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR          *
* CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF         *
* SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS     *
* INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN      *
* CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)      *
* ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE   *
* POSSIBILITY OF SUCH DAMAGE.                                                  *
*                                                                              *
*******************************************************************************/


#pragma once 

#include <iostream>
#include <string>
#include "Byte_buffer.h"
#include "Logging.h"
#include "G1_utils.h"
#include "Amcl_includes.h"

#ifdef MODBYTES_B256_56
static const size_t amcl_component_size=MODBYTES_B256_56;
#else
static const size_t amcl_component_size=MODBYTES_B256_28;
#endif

using FP256BN::ECP;
using FP256BN::ECP2;
using FP256BN::FP12;
using FP256BN_BIG::BIG;

Byte_buffer big_to_bb(BIG& n);

void bb_to_big(Byte_buffer const& bb,BIG& n);

Byte_buffer ecp_to_bb(ECP* ecp);

Byte_buffer ecp_concat_bb(ECP* ecp);

void bb_to_ecp(Byte_buffer const& bb, ECP* ecp);

void g1_point_to_ecp(G1_point const& g1_pt, ECP* ecp);

G1_point ecp_to_g1_point(ECP* pt);

Byte_buffer ecp2_to_bb(ECP2* ecp2);

void bb_to_ecp2(Byte_buffer const& bb, ECP2* ecp2);

Byte_buffer fp12_to_bb(FP12* fp);

// Calculate a+b.c mod n
void schnorr_calculation(BIG& a, BIG& b, BIG& c, BIG& n);
