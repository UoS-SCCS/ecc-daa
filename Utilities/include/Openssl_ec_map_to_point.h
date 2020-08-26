/***************************************************************************
* File:        Openssl_ec_map_to_point.h
* Description: Functions implementing map_to-point in Openssl EC
*
* Author:      Chris Newton
* Created:     Saturday 7 July 2018
*
* (C) Copyright 2018, University of Surrey.
*
****************************************************************************/

#pragma once 

#include <cstdint>
#include <string>
#include <iostream>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include "Sha.h"
#include "Byte_buffer.h"
#include "Number_conversions.h"
#include "Openssl_bn_utils.h"
#include "Openssl_ec_utils.h"
#include "Openssl_utils.h"


// Prepends a counter to the initial value and calculates a test point,
// s_2=counter+initial_value, test point=(sha256(s_2), y_2). If the point
// is on the curve then it returns s_2 and y_2. If not, it increments
// the counter and tries again.
G1_point map_to_point(
Ec_group_ptr const& ecgrp,
Byte_buffer const& initial_value,
uint32_t max_iter
);

G1_point point_from_basename(Byte_buffer const& bsn);
