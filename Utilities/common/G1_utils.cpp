/***************************************************************************
* File:        G1_utils.cpp
* Description: Utility functions for the base field, G1
*
* Author:      Chris Newton
*
* Created:     Wednesday 20 June 2018
*
* (C) Copyright 2018, University of Surrey.
*
****************************************************************************/

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
