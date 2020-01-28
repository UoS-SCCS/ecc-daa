/***************************************************************************
* File:        Issuer_public_keys.cpp
* Description: Routines for the Issuer's public keys
*
* Author:      Chris Newton
*
* Created:     Saturday 1 June 2019
*
* (C) Copyright 2019, University of Surrey.
*
****************************************************************************/

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

