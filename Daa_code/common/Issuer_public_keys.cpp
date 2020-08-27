/*******************************************************************************
* File:        Issuer_public_keys.cpp
* Description: Routines for the Issuer's public keys
*
* Author:      Chris Newton
*
* Created:     Saturday 1 June 2019
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
#include "G2_utils.h"
#include "Issuer_public_keys.h"

Byte_buffer serialise_issuer_public_keys(Issuer_public_keys const& ipk)
{
	std::vector<Byte_buffer> tmp_bb{2};
	tmp_bb[0]=g2_point_serialise(ipk.first);
	tmp_bb[1]=g2_point_serialise(ipk.second);
	return serialise_byte_buffers(tmp_bb);
}

Issuer_public_keys deserialise_issuer_public_keys(Byte_buffer const& bb)
{
	std::vector<Byte_buffer> tmp_bb=deserialise_byte_buffers(bb);
	Issuer_public_keys ipk;
	ipk.first=g2_point_deserialise(tmp_bb[0]);
	ipk.second=g2_point_deserialise(tmp_bb[1]);
	return ipk;
}

