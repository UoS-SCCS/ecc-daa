/******************************************************************************
* File:        Display_public_data.cpp
* Description: Display a key's public data (TPMT_PUBLIC)
*
* Author:      Chris Newton
*
* Created:     Friday 6 July 2018
*
* (C) Copyright 2018, University of Surrey.
*
******************************************************************************/

#include <iostream>
#include <iomanip>
#include "Byte_buffer.h"
#include "Marshal_public_data.h"
#include "Tpm_utils.h"
#include "Display_public_data.h"

void display_rsa_public_bb(
std::ostream& os,
Byte_buffer& pd_bb      
)
{
    TPM2B_PUBLIC tpm2b;
	unmarshal_public_data_B(pd_bb,&tpm2b);
	display_rsa_public(std::cout,tpm2b);    
}

void display_rsa_public(
std::ostream& os,
TPM2B_PUBLIC const& pd
)
{
    TPMT_PUBLIC const& tpmt_public=pd.publicArea;
    if (tpmt_public.type!=TPM_ALG_RSA)
    {
        std::cerr << "display_rsa_key: not an RSA key\n";
        return;
    }
    os << "RSA key\n" << std::hex;
    os << "TPMI_ALG_PUBLIC: type: " << tpmt_public.type << '\n';  
    os << "TPMI_ALG_HASH: nameAlg: " << tpmt_public.nameAlg << '\n';  
    os << "TPMA_OBJECT: objectAttributes: " << tpmt_public.objectAttributes.val <<'\n';
    Byte_buffer auth_policy(tpmt_public.authPolicy.t.buffer,tpmt_public.authPolicy.t.size);
    if (auth_policy.size()==0)
        os << "TPM2B_DIGEST: authPolicy: empty\n";
    else
        os << "TPM2B_DIGEST: authPolicy: " << auth_policy.to_hex_string() << '\n';
    Byte_buffer unique_data(tpmt_public.unique.rsa.t.buffer,tpmt_public.unique.rsa.t.size);
    os << "TPMU_PUBLIC_ID: unique: size: " << unique_data.size() << '\n';
    if (unique_data.size()==0)
        os << "TPMU_PUBIC_ID: unique: empty\n";
    else
        os << "TPMU_PUBIC_ID: unique: data: " << unique_data.to_hex_string() << '\n';
}

void display_ecc_public_bb(
std::ostream& os,
Byte_buffer& pd_bb
)
{
    TPM2B_PUBLIC tpm2b;
	unmarshal_public_data_B(pd_bb,&tpm2b);
	display_ecc_public(std::cout,tpm2b);    
}

void display_ecc_public(
std::ostream& os,
TPM2B_PUBLIC const& pd
)
{
    TPMT_PUBLIC const& tpmt_public=pd.publicArea;
    if (tpmt_public.type!=TPM_ALG_ECC)
    {
        std::cerr << "display_ecc_key: not an ECC key\n";
        return;
    }    
    os << "ECC key - !!! OPTIONS NOT CORRECT YET !!!\n";
    
    os << "TPMI_ALG_PUBLIC: type: " << tpmt_public.type << '\n';  
    os << "TPMI_ALG_HASH: nameAlg: " << tpmt_public.nameAlg << '\n';  
    os << "TPMA_OBJECT: objectAttributes: " << tpmt_public.objectAttributes.val <<'\n';
    Byte_buffer auth_policy(tpmt_public.authPolicy.t.buffer,tpmt_public.authPolicy.t.size);
    if (auth_policy.size()==0)
        os << "TPM2B_DIGEST: authPolicy: empty\n";
    else
        os << "TPM2B_DIGEST: authPolicy: " << auth_policy.to_hex_string() << '\n';
    os << "TPMU_PUBLIC_PARMS: TPMS_ECC_PARMS: symmetric: algorithm: " << tpmt_public.parameters.asymDetail.symmetric.algorithm << '\n';
    os << "TPMU_PUBLIC_PARMS: TPMS_ECC_PARMS: scheme: scheme: " << tpmt_public.parameters.asymDetail.scheme.scheme << '\n';
    os << "TPMU_PUBLIC_PARMS: TPMS_ECC_PARMS: scheme: details: anySig: hashAlg: " << tpmt_public.parameters.asymDetail.scheme.details.anySig.hashAlg << '\n';
    os << "TPMU_PUBLIC_PARMS: TPMS_ECC_PARMS: curveID: " << tpmt_public.parameters.eccDetail.curveID << '\n';
    os << "TPMU_PUBLIC_PARMS: TPMS_ECC_PARMS: kdf: scheme: " << tpmt_public.parameters.eccDetail.kdf.scheme << '\n';
    os << "TPMU_PUBLIC_ID: TPMS_ECC_POINT: x: " << ecc_param_to_bb(tpmt_public.unique.ecc.x).to_hex_string() << '\n'; 
    os << "TPMU_PUBLIC_ID: TPMS_ECC_POINT: y: " << ecc_param_to_bb(tpmt_public.unique.ecc.y).to_hex_string() << '\n'; 
}

void display_hmac_public(
std::ostream& os,
TPM2B_PUBLIC const& pd
)
{
    TPMT_PUBLIC const& tpmt_public=pd.publicArea;
    if (tpmt_public.type!=TPM_ALG_KEYEDHASH)
    {
        std::cerr << "display_hmac_key: not an HMAC key\n";
        return;
    }    
    os << "HMAC key - !!! OPTIONS NOT CORRECT YET !!!\n";
    
    os << "TPMI_ALG_PUBLIC: type: " << tpmt_public.type << '\n';  
    os << "TPMI_ALG_HASH: nameAlg: " << tpmt_public.nameAlg << '\n';  
    os << "TPMA_OBJECT: objectAttributes: " << tpmt_public.objectAttributes.val <<'\n';
    Byte_buffer auth_policy(tpmt_public.authPolicy.t.buffer,tpmt_public.authPolicy.t.size);
    if (auth_policy.size()==0)
        os << "TPM2B_DIGEST: authPolicy: empty\n";
    else
        os << "TPM2B_DIGEST: authPolicy: " << auth_policy.to_hex_string() << '\n';
    os << "TPMI_ALG_KEYEDHASH_PARMS: scheme: " << tpmt_public.parameters.keyedHashDetail.scheme.scheme << '\n';
    os << "TPMU_SCHEME_KEYEDHASH: hmac.hashalg: " << tpmt_public.parameters.keyedHashDetail.scheme.details.hmac.hashAlg << '\n';
}

void display_object_attributes(
std::ostream& os,
uint32_t val
)
{
	os << "           TPMA_OBJECT_RESTRICTED: " << ((val&TPMA_OBJECT_RESTRICTED)?1:0) << '\n';
	os << "                 TPMA_OBJECT_SIGN: " << ((val&TPMA_OBJECT_SIGN)?1:0) << '\n';
	os << "              TPMA_OBJECT_DECRYPT: " << ((val&TPMA_OBJECT_DECRYPT)?1:0) << '\n';
	os << "         TPMA_OBJECT_USERWITHAUTH: " << ((val&TPMA_OBJECT_USERWITHAUTH)?1:0) << '\n';
	os << "      TPMA_OBJECT_ADMINWITHPOLICY: " << ((val&TPMA_OBJECT_ADMINWITHPOLICY)?1:0) << '\n';
	os << "                 TPMA_OBJECT_NODA: " << ((val&TPMA_OBJECT_NODA)?1:0) << '\n';
	os << "             TPMA_OBJECT_FIXEDTPM: " << ((val&TPMA_OBJECT_FIXEDTPM)?1:0) << '\n';
	os << "          TPMA_OBJECT_FIXEDPARENT: " << ((val&TPMA_OBJECT_FIXEDPARENT)?1:0) << '\n';
	os << " TPMA_OBJECT_ENCRYPTEDDUPLICATION: " << ((val&TPMA_OBJECT_ENCRYPTEDDUPLICATION)?1:0) << '\n';
	os << "  TPMA_OBJECT_SENSITIVEDATAORIGIN: " << ((val&TPMA_OBJECT_SENSITIVEDATAORIGIN)?1:0) << '\n';
	os << "              TPMA_OBJECT_STCLEAR: " << ((val&TPMA_OBJECT_STCLEAR)?1:0) << '\n';
}

void display_tpm2b_public(
std::ostream& os,
TPM2B_PUBLIC const& pd
)
{
    TPMT_PUBLIC const& tpmt_pd=pd.publicArea;
    if (tpmt_pd.type==TPM_ALG_ECC) {
        display_ecc_public(os,pd);
    } else if (tpmt_pd.type==TPM_ALG_RSA) {
        display_rsa_public(os,pd);
    } else if (tpmt_pd.type==TPM_ALG_KEYEDHASH) {
        display_hmac_public(os,pd);
    } else {
        TPM2B_PUBLIC tmp_pd=pd;
        Byte_buffer pd_bb=marshal_public_data_B(&tmp_pd);
        os << pd_bb.to_hex_string();
    }
}
