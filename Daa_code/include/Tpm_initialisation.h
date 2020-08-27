/*******************************************************************************
* File:        Tpm_initialisation.h
* Description: Tpm initialisation routines
*
* Author:      Chris Newton
* Created:     Monday 15 October 2018
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

#include "Tss_setup.h"

TPM_RC powerup(Tss_setup const& tps);

TPM_RC startup(TSS_CONTEXT* tss_context);

TPM_RC shutdown(TSS_CONTEXT* tss_context);

std::pair<TPM_RC,bool> take_ownership_enabled(TSS_CONTEXT* tss_context);

void provision_pcr(TSS_CONTEXT* tss_context);

bool check_pcr_provision(TSS_CONTEXT* tss_context);

bool persistent_key_available(TSS_CONTEXT* tss_context,TPM_HANDLE handle);

std::vector<TPM_HANDLE> retrieve_persistent_handles(TSS_CONTEXT* tss_context, size_t ph_count);

void setup_primary_ek(TSS_CONTEXT* tss_context);

TPM_RC set_tpm_clock(TSS_CONTEXT* tss_context);

void read_ek_public_data(TSS_CONTEXT* tss_context, TPM2B_PUBLIC& pd);

void read_persistent_key_public_data(
TSS_CONTEXT* tss_context,
TPM_HANDLE handle,
TPM2B_PUBLIC& pd);

TPM_RC make_ek_persistent(TSS_CONTEXT* tss_context,TPM_HANDLE ek_handle);
