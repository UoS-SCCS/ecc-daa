/*******************************************************************************
* File:        Model_hashes.cpp
* Description: The hashes used in the model
*
* Author:      Chris Newton
*
* Created:     Thursday 18 April 2019
*
* (C) Copyright 2019, University of Surrey.
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
#include <string>
#include <array>
#include "Byte_buffer.h"
#include "Sha.h"
#include "G1_utils.h"
#include "G2_utils.h"
#include "Openssl_bn_utils.h"
#include "Daa_credential.h"
#include "bnp256_param.h"

Byte_buffer host_str(G2_point const& x, G2_point const& y, Byte_buffer const& key, Byte_buffer const& ek)
{
    return g2_point_concat(x)+g2_point_concat(y)+key+ek;
}

Byte_buffer host_p(G1_point const& p1, G1_point const& daa_key, G1_point const& e, Byte_buffer const& str)
{
    Byte_buffer bb=g1_point_concat(p1)+g1_point_concat(daa_key)+g1_point_concat(e)+str;
    return sha256_bb(bb);
}

Byte_buffer issuer_u(G1_point p1, G1_point const& daa_key, Daa_credential const& cre, G1_point const& rb, G1_point const& rd)
{
    Byte_buffer tmp_bb=g1_point_concat(p1)+g1_point_concat(daa_key)+daa_credential_concat(cre)+g1_point_concat(rb)+g1_point_concat(rd);
    return bb_mod(sha256_bb(tmp_bb),bnp256_order);
}

Byte_buffer sign_c(Byte_buffer const& label, Daa_credential const& cre, G1_point const& j, G1_point const& k, G1_point const& l, G1_point const& e)
{
    Byte_buffer tmp_bb=label+daa_credential_concat(cre)+g1_point_concat(j)+g1_point_concat(k)+g1_point_concat(l)+g1_point_concat(e);
    return sha256_bb(tmp_bb);
}

