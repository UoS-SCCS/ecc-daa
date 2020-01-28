/*******************************************************************************
* File:        G2_utils.h
* Description: Utility functions for the extension field, G2
*
* Author:      Chris Newton
* Created:     Tursday 15 November 2018
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

#include <cstdint>
#include <string>
#include <iostream>
#include <memory>
#include "bnp256_param.h"
#include "Byte_buffer.h"

const size_t g2_coord_component_size=component_size;
const size_t g2_coord_size=2*g2_coord_component_size;
const size_t g2_affine_point_size=2*g2_coord_size;

using G2_coord=std::pair<Byte_buffer,Byte_buffer>;
using G2_point=std::pair<G2_coord,G2_coord>;

Byte_buffer g2_coord_concat(G2_coord const& coord);
G2_coord g2_coord_from_bb(Byte_buffer const& bb);

Byte_buffer g2_point_concat(G2_point const& pt);
G2_point g2_point_from_bb(Byte_buffer const& bb);

Byte_buffer g2_coord_serialise(G2_coord const& coord);
Byte_buffer g2_point_serialise(G2_point const& pt);

G2_coord g2_coord_deserialise(Byte_buffer const& bb);
G2_point g2_point_deserialise(Byte_buffer const& bb);

