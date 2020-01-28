/*******************************************************************************
* File:        Tss_includes.h
* Description: Include file to use with TSS, disables warnings from TSS files
*
* Author:      Chris Newton
*
* Created:     Monday 20 August 2018
*
* (C) Copyright 2018, University of Surrey, all rights reserved.
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

// This removes most of the warnings from C++ due to the use of the TSS C code
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
#include <tss2/tss.h>
#include <tss2/tssresponsecode.h>
#include "tss2/tssutils.h"
#include "tss2/tssmarshal.h"
#include <tss2/Unmarshal_fp.h>
#include <tss2/tsscrypto.h>
#include <tss2/tsstransmit.h>
#include <tssproperties.h>
#pragma GCC diagnostic pop
