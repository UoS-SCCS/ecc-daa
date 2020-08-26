/***************************************************************************
* File:        Model_hashes.h
* Description: The hashes used in the model
*
* Author:      Chris Newton
*
* Created:     Thursday 18 April 2019
*
* (C) Copyright 2019, University of Surrey.
*
****************************************************************************/

#pragma once

#include <iostream>
#include <string>
#include <array>
#include "Byte_buffer.h"
#include "G1_utils.h"
#include "G2_utils.h"
#include "Daa_credential.h"
#include "Sha.h"
#include "bnp256_param.h"

Byte_buffer host_str(G2_point const& x, G2_point const& y, Byte_buffer const& key, Byte_buffer const& ek);

Byte_buffer host_p(G1_point const& p1, G1_point const& daa_key, G1_point const& e, Byte_buffer const& str);

Byte_buffer issuer_u(G1_point p1, G1_point const& daa_key, Daa_credential const& cre, G1_point const& rb, G1_point const& rd);

Byte_buffer sign_c(Byte_buffer const& label, Daa_credential const& cre, G1_point const& j, G1_point const& k, G1_point const& l, G1_point const& e);
