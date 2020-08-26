/***************************************************************************
* File:        Tpm_initialisation.h
* Description: Tpm initialisation routines
*
* Author:      Chris Newton
* Created:     Monday 15 October 2018
*
* (C) Copyright 2018, University of Surrey.
*
**********************************************************************/

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
