/******************************************************************************
* File:        create_primary_rsa_key.h
* Description: Create primary RSA key in the given hierarchy
*
* Author:      Chris Newton
*
* Created:     Thursday 5 April 2018
*
* Closely modelled on example code from the IBM TSS software
*
* (C) Copyright 2018, University of Surrey, all rights reserved.
*
******************************************************************************/

#pragma once

#include <iostream>
#include <cstring>
#include "Tss_includes.h"
#include "Openssl_aes.h"

// Create a primary key in the endorsement hierarchy
TPM_RC create_primary_rsa_key(
	TSS_CONTEXT *tssContext,
	TPMI_RH_HIERARCHY hierarchy,
	CreatePrimary_Out* out
);
