/******************************************************************************
* File:        Amcl_includes.h
* Description: Include file to use with AMCL, disables warnings from AMCL files
*
* Author:      Chris Newton
*
* Created:     Sunday 25 November 2018
*
* (C) Copyright 2018, University of Surrey, all rights reserved.
*
******************************************************************************/
#pragma once

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"

#include "amcl.h"
#include "arch.h"

#if CHUNK==32 || CHUNK==64

#include "pair_FP256BN.h"

#endif

#pragma GCC diagnostic pop

