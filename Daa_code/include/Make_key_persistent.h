/*******************************************************************************
* File:        Make_persistent_key.h
* Description: Use TPM2_EvictControl to make a key persistent
*
* Author:      Chris Newton
*
* Created:     Sunday 6 May 2018
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

#include <cstring>
#include "Tss_includes.h"


TPM_RC make_key_persistent(
TSS_CONTEXT* tssContext,
TPMI_RH_PROVISION   auth,
TPM_HANDLE key_handle,
TPM_HANDLE persistent_handle
);

TPM_RC remove_persistent_key(
TSS_CONTEXT* tssContext,
TPMI_RH_PROVISION   auth,
TPM_HANDLE persistent_handle
);