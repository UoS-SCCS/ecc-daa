/***************************************************************************
* File:        G2_utils.cpp
* Description: Utility functions for the extension field, G2
*
* Author:      Chris Newton
* Created:     Tursday 15 November 2018
*
* (C) Copyright 2018, University of Surrey.
*
****************************************************************************/ 

#include <cstdint>
#include <string>
#include <iostream>
#include <memory>
#include "Tpm_error.h"
#include "G2_utils.h"

Byte_buffer g2_coord_concat(G2_coord const& coord)
{
	return coord.first+coord.second;
}

G2_coord g2_coord_from_bb(Byte_buffer const& bb)
{
	return std::make_pair(bb.get_part(0,g2_coord_component_size),
				bb.get_part(g2_coord_component_size,g2_coord_component_size));
}

Byte_buffer g2_point_concat(G2_point const& pt)
{
	return g2_coord_concat(pt.first)+g2_coord_concat(pt.second);
}

G2_point g2_point_from_bb(Byte_buffer const& bb)
{
	return std::make_pair(g2_coord_from_bb(bb.get_part(0,g2_coord_size)),
				g2_coord_from_bb(bb.get_part(g2_coord_size,g2_coord_size)));
}

Byte_buffer g2_coord_serialise(G2_coord const& coord)
{
	std::vector<Byte_buffer> tmp_bb(2);
	tmp_bb[0]=coord.first;
	tmp_bb[1]=coord.second;
	return serialise_byte_buffers(tmp_bb);
}

Byte_buffer g2_point_serialise(G2_point const& pt)
{
	std::vector<Byte_buffer> tmp_bb(2);
	tmp_bb[0]=g2_coord_serialise(pt.first);
	tmp_bb[1]=g2_coord_serialise(pt.second);
	return serialise_byte_buffers(tmp_bb);
}

G2_coord g2_coord_deserialise(Byte_buffer const& bb)
{
	auto tmp_bb=deserialise_byte_buffers(bb);
	if (tmp_bb.size()!=2)
	{
		throw(Tpm_error("Failed to deserialise a G2 coordinate"));
	}
	G2_coord coord;
	coord.first=tmp_bb[0];
	coord.second=tmp_bb[1];
	
	return coord;
}

G2_point g2_point_deserialise(Byte_buffer const& bb)
{
	auto tmp_bb=deserialise_byte_buffers(bb);
	if (tmp_bb.size()!=2)
	{
		throw(Tpm_error("Failed to deserialise a G2 point"));
	}
	return std::make_pair(g2_coord_deserialise(tmp_bb[0]),g2_coord_deserialise(tmp_bb[1]));
}



