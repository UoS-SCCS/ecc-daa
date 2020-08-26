/***************************************************************************
* File:        Issuer_public_keys.h
* Description: Routines for the Issuer's public keys
*
* Author:      Chris Newton
*
* Created:     Saturday 1 June 2019
*
* (C) Copyright 2019, University of Surrey.
*
****************************************************************************/

#pragma once

#include <iostream>
#include <string>
#include <array>
#include "Byte_buffer.h"
#include "G2_utils.h"

using Issuer_private_keys=std::pair<Byte_buffer,Byte_buffer>;
using Issuer_public_keys=std::pair<G2_point,G2_point>;

Byte_buffer serialise_issuer_public_keys(Issuer_public_keys const& ipk);

Issuer_public_keys deserialise_issuer_public_keys(Byte_buffer const& bb);

