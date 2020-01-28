/*******************************************************************************
* File:        G1_utils.h
* Description: Utility functions for the base field, G1
*
* Author:      Chris Newton
*
* Created:     Wednesday 28 November 2018
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

const size_t g1_coord_size=component_size;
const size_t g1_affine_point_size=2*g1_coord_size;
// Size for uncompressed representation (uncompressed code) + x + y
const size_t g1_uncompressed_point_size=g1_affine_point_size+1;
// Size for compressed representation - (compressed code) + x-coord + 1
// - check this !!!!)
const size_t g1_compressed_point_size=g1_coord_size+2;

using G1_point=std::pair<Byte_buffer,Byte_buffer>;

Byte_buffer g1_point_concat(G1_point const& pt);

Byte_buffer g1_point_uncompressed(G1_point const& pt);

G1_point g1_point_from_bb(Byte_buffer const& bb);

Byte_buffer g1_point_serialise(G1_point const& pt);

G1_point g1_point_deserialise(Byte_buffer const& bb);
