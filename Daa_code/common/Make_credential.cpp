/*******************************************************************************
* File:        Make_credential.cpp
* Description: Implement make credential, using TPM and without the TPM
*
* Author:      Chris Newton
*
* Created:     Wednesday 13 June 2018
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



#include <iostream>
#include <tuple>
#include "Tss_includes.h"
#include <openssl/evp.h>
#include "Openssl_utils.h"
#include "Key_name_from_public_data.h"
#include "Get_random_bytes.h"
#include "Openssl_rsa_public.h"
#include "Flush_context.h"
#include "KDF_sha256.h"
#include "Sha.h"
#include "Tpm_error.h"
#include "Tpm_defs.h"
#include "Openssl_aes.h"
#include "Make_credential.h"

Credential_data make_credential_TPM(
TSS_CONTEXT* tss_context,
TPM2B_PUBLIC const& ek_public, 
TPM2B_PUBLIC const& daa_public_data,
Byte_buffer const& credential_key)
{
    TPM_RC rc=0;

    Credential_data cd;

    Tpm_timer tt;

    LoadExternal_In in;
    LoadExternal_Out out;
    in.inPublic=ek_public;
    in.inPrivate.t.size=0;
    in.hierarchy=TPM_RH_ENDORSEMENT;
    rc = TSS_Execute(tss_context,
                    (RESPONSE_PARAMETERS *)&out,
                    (COMMAND_PARAMETERS *)&in,
                    NULL,
                    TPM_CC_LoadExternal,
                    TPM_RH_NULL, NULL, 0); // No authorisation sessions needed                     
    if (rc!=0)
    {
        log_ptr->os() << "Loading EK public data" << get_tpm_error(rc) << std::endl;
        throw(Tpm_error("loading EK public data failed"));
    }

    tpm_timings.add("TPM2_LoadExternal",tt.get_duration());

    tt.reset();

    TPM_HANDLE ek_handle=out.objectHandle;
    TPMT_PUBLIC daa_pd=daa_public_data.publicArea;
    Byte_buffer key_name=get_key_name(&daa_pd);

    MakeCredential_In make_credential_in;
    MakeCredential_Out make_credential_out;

    make_credential_in.handle = ek_handle;
    make_credential_in.objectName.t.size=key_name.size();
    for (int i = 0; i < key_name.size(); ++i)
        make_credential_in.objectName.t.name[i] = key_name[i];    
    make_credential_in.credential.t.size = credential_key.size();
    for (int i = 0; i < credential_key.size(); ++i)
        make_credential_in.credential.t.buffer[i] = credential_key[i];

    rc = TSS_Execute(tss_context,
                    (RESPONSE_PARAMETERS *)&make_credential_out,
                    (COMMAND_PARAMETERS *)&make_credential_in,
                    NULL,
                    TPM_CC_MakeCredential,
                    TPM_RH_NULL, NULL, 0); // No authorisation sessions needed
    if (rc != 0)
    {
        log_ptr->os() << "make_credential_TPM: " << get_tpm_error(rc) << std::endl;
        throw(Tpm_error("TPM2_MakeCredential failed"));
    }

    tpm_timings.add("TPM2_MakeCredential",tt.get_duration());

    Byte_buffer credential_blob(make_credential_out.credentialBlob.t.credential, make_credential_out.credentialBlob.t.size);
    Byte_buffer secret(make_credential_out.secret.t.secret, make_credential_out.secret.t.size);

    rc = flush_context(tss_context, ek_handle);
    if (rc != 0)
    {
        log_ptr->os() << "make_credential_TPM: " << get_tpm_error(rc) << std::endl;
        std::cerr << "make_credential_TPM: flush_context failed\n";
    }

    return std::make_pair(secret,credential_blob);
}

Credential_data make_credential_issuer(
Byte_buffer const& ek_public_key,
TPM2B_PUBLIC const& daa_public_data,
Byte_buffer const& credential_key,
Random_byte_generator& rbg
)
{
    size_t seed_bytes=32;
    size_t seed_bits=8*seed_bytes;    //  This should be the digest size
    Byte_buffer seed=rbg(seed_bytes);

    TPMT_PUBLIC daa_pd=daa_public_data.publicArea;
    Byte_buffer key_name=get_key_name(&daa_pd);

    Byte_buffer exponent{0x01,0x00,0x01};
    // label=identity_str+nul
    Byte_buffer secret=encrypt_rsa2048(identity_str+nul,seed,ek_public_key,exponent);

    Byte_buffer aes_key=KDFa_sha256(seed,storage_str+nul,key_name,Byte_buffer(),aes_key_bits,false);
    Byte_buffer hmac_key=KDFa_sha256(seed,integrity_str+nul,Byte_buffer(),Byte_buffer(),seed_bits,false);

    Byte_buffer iv(aes_block_size,0);
    Byte_buffer cvm=Byte_buffer{aes_block_size/256,aes_block_size%256}+credential_key;  // size in bytes as uint16_t + credential_key
    Byte_buffer c_hat=ossl_encrypt("AES-128-CFB",cvm,aes_key,iv);

    Byte_buffer cblob{0x00,0x20};
    cblob+=hmac_sha256(hmac_key,c_hat+key_name)+c_hat;

    return std::make_pair(secret,cblob);
}
