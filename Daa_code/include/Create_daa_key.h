/******************************************************************************
* File:        create_daa_key.h
* Description: Create a DAA key
*
* Author:      Chris Newton
*
* Created:     Friday 6 April 2018
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

TPM_RC create_daa_key(
	TSS_CONTEXT* tssContext,
	TPM_HANDLE parent_key_handle,
    TPMI_ECC_CURVE curve_ID,
    Create_Out* out	
);

