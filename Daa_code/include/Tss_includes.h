/******************************************************************************
* File:        Tss_includes.h
* Description: Include file to use with TSS, disables warnings from TSS files
*
* Author:      Chris Newton
*
* Created:     Monday 20 August 2018
*
* (C) Copyright 2018, University of Surrey, all rights reserved.
*
******************************************************************************/
#pragma once

// This removes most of the warnings from C++ due to the use of the TSS C code
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
#include "tss2/tss.h"
#include "tss2/tssresponsecode.h"
#include "tss2/tssutils.h"
#include "tss2/tssmarshal.h"
#include "tss2/Unmarshal_fp.h"
#include "tss2/tsscrypto.h"
#include "tss2/tsstransmit.h"
#include "tssproperties.h"
#pragma GCC diagnostic pop
