/***************************************************************************
* File:        Amcl_pairings.h
* Description: Routines for checking pairings using AMCL
*
* Author:      Chris Newton
* Created:     Wednesday 28 November 2018
*
* (C) Copyright 2018, University of Surrey.
*
****************************************************************************/

#pragma once

#include "Mechanism_4_data.h"
#include "G2_utils.h"
#include "Amcl_utils.h"
#include "Issuer_public_keys.h"
#include "Daa_credential.h"

Issuer_public_keys amcl_calculate_public_keys(Issuer_private_keys const& pks);

bool check_daa_pairings(
Daa_credential const& cre,
Issuer_public_keys const& issuer_keys
);
