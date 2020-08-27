/*******************************************************************************
* File:        Amcl_utils.cpp
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


#include <iostream>
#include <cstring>
#include <string>
#include "Byte_buffer.h"
#include "G2_utils.h"
#include "G1_utils.h"
#include "Amcl_includes.h"
#include "Amcl_utils.h"

using namespace FP256BN;
using namespace FP256BN_BIG;


Byte_buffer big_to_bb(BIG& n)
{
    std::string n_char(amcl_component_size,'\0');
    BIG_toBytes(&n_char[0],n);
    
    return Byte_buffer(n_char);
}

void bb_to_big(Byte_buffer const& bb,BIG& n)
{
    std::string bb_char=bb_to_string(bb);
    BIG_fromBytesLen(n,&bb_char[0],bb_char.size());
}

Byte_buffer ecp_to_bb(ECP* ecp)
{
    std::string ochar(g1_uncompressed_point_size,'\0');
    octet ostr;
    ostr.val=&ochar[0];
    ECP_toOctet(&ostr,ecp,false);

    Byte_buffer bb(ochar);
    
    return bb;
}

Byte_buffer ecp_concat_bb(ECP* ecp)
{
    Byte_buffer uncompressed_pt=ecp_to_bb(ecp);

    Byte_buffer bb=uncompressed_pt.get_part(1,g1_affine_point_size);

    return bb;
}

void bb_to_ecp(Byte_buffer const& bb, ECP* ecp)
{
    std::string ochar=bb_to_string(bb);
    octet ostr;
    ostr.len=ochar.size();
    ostr.val=&ochar[0];
    ECP_fromOctet(ecp,&ostr);
}

G1_point ecp_to_g1_point(ECP* pt)
{
    Byte_buffer tmp_bb=ecp_concat_bb(pt);
    G1_point pt_bb=std::make_pair(tmp_bb.get_part(0,component_size),tmp_bb.get_part(component_size,component_size));

    return pt_bb;
}

void g1_point_to_ecp(G1_point const& g1_pt, ECP* ecp)
{
    Byte_buffer tmp_uncompressed=g1_point_uncompressed(g1_pt);
    bb_to_ecp(tmp_uncompressed,ecp);
}

Byte_buffer ecp2_to_bb(ECP2* ecp2)
{
	std::string ochar(g2_affine_point_size,'\0');
    octet ostr;
    ostr.val=&ochar[0];
    ECP2_toOctet(&ostr,ecp2);

    Byte_buffer bb(ochar);
 
    return bb;
}

void bb_to_ecp2(Byte_buffer const& bb, ECP2* ecp2)
{
    std::string ochar=bb_to_string(bb);
    octet ostr;
    ostr.len=ochar.size();
    ostr.max=ochar.size();
    ostr.val=&ochar[0];
    ECP2_fromOctet(ecp2,&ostr);
}

Byte_buffer fp12_to_bb(FP12* fp)
{
	std::string ochar(12*component_size,'\0');
    octet ostr;
    ostr.val=&ochar[0];
	FP12_toOctet(&ostr,fp);

	Byte_buffer bb(ochar);

    return bb;
}

// Calculate sc=a+b.c (mod n)
void schnorr_calculation(BIG& sc, BIG& a, BIG& b, BIG& c, BIG& n)
{
    BIG big_temp;
    BIG_modmul(big_temp,b,c,n);
    BIG_add(sc,a,big_temp);
    BIG_mod(sc,n);
}
