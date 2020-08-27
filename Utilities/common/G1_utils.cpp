/*******************************************************************************
* File:        G1_utils.cpp
* Description: Utility functions for the base field, G1
*
* Author:      Chris Newton
*
* Created:     Wednesday 20 June 2018
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


#include <exception>
#include <stdexcept>
#include "G1_utils.h"


Byte_buffer g1_point_concat(G1_point const& pt)
{
    G1_point tmp=pt;
	tmp.first.pad_left(g1_coord_size);
    tmp.second.pad_left(g1_coord_size);
    return tmp.first+tmp.second;
}

Byte_buffer g1_point_uncompressed(G1_point const& pt)
{
	Byte_buffer prefix{0x04};
	return prefix+g1_point_concat(pt);
}

G1_point g1_point_from_bb(Byte_buffer const& bb)
{
    if (bb.size()!=g1_affine_point_size)
    {
        throw(std::runtime_error("g1_point_from_bb: must use padded coordinates"));
    }
	return std::make_pair(bb.get_part(0,g1_coord_size),
						  bb.get_part(g1_coord_size,g1_coord_size));
}

G1_point g1_point_from_uncompressed(Byte_buffer const& bb)
{
    if (bb.size()!=g1_uncompressed_point_size)
    {
        throw(std::runtime_error("g1_point_from_uncompressed: incorrect buffer size"));
    }
    if (bb[0]!=0x04)
    {
        throw(std::runtime_error("g1_point_from_uncompressed: first byte should be 0x04"));
    }

	return std::make_pair(bb.get_part(0,g1_coord_size),
						  bb.get_part(g1_coord_size,g1_coord_size));
}

Byte_buffer g1_point_serialise(G1_point const& pt)
{
	std::vector<Byte_buffer> tmp_bv(2);
	tmp_bv[0]=pt.first;
	tmp_bv[1]=pt.second;
	return serialise_byte_buffers(tmp_bv);
}

G1_point g1_point_deserialise(Byte_buffer const& bb)
{
	auto tmp_bv=deserialise_byte_buffers(bb);
	if (tmp_bv.size()!=2)
	{
		throw(std::runtime_error("G1 point deserialisation failed"));
	}
	return std::make_pair(tmp_bv[0],tmp_bv[1]);
}
