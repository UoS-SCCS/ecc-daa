/***************************************************************************
* File:        Tpm_utils.cpp
* Description: TPM utilities (that are not dependent on the Tpm_daa class)
*
* Author:      Chris Newton
*
* Created:     Thursday 21 June 2018
*
* (C) Copyright 2018, University of Surrey.
*
****************************************************************************/

#include <iostream>
#include <iomanip>
#include <string>
#include <cstring>
#include "Marshal_public_data.h"
#include "Tpm_error.h"
#include "Tpm_utils.h"

Byte_buffer ecc_param_to_bb(TPM2B_ECC_PARAMETER const& ecp)
{
    return Byte_buffer(ecp.t.buffer,ecp.t.size);
}

TPM2B_ECC_PARAMETER ecc_param_from_bb(Byte_buffer const& bb)
{
    TPM2B_ECC_PARAMETER ecp;    // !!!! Check how the size of this parameter is fixed
    ecp.t.size=bb.size();
    memcpy(ecp.t.buffer,&bb[0],bb.size());

    return ecp;
}

TPM2B_SENSITIVE_DATA sensitive_data_from_bb(Byte_buffer const& bb)
{
    TPM2B_SENSITIVE_DATA sd;    // !!!! Check how the size of this parameter is fixed
    sd.t.size=bb.size();
    memcpy(sd.t.buffer,&bb[0],bb.size());

    return sd;
}

Byte_buffer get_ek_from_public_data_bb(Byte_buffer const& ek_pd)
{
    TPM_RC rc=0;
    Byte_buffer ek_bb;
    Byte_buffer ekd=ek_pd;
    TPM2B_PUBLIC tpm2b_ekpd;
    rc=unmarshal_public_data_B(ekd,&tpm2b_ekpd);
    if (rc!=0)
    {
        std::cerr << "get_ek_from_public_data: unmarshalling failed\n";
        return ek_bb;
    }
    
    return get_ek_from_public_data(tpm2b_ekpd);
}

Byte_buffer get_ek_from_public_data(TPM2B_PUBLIC const& tpm2b_ekpd)
{
    Byte_buffer ek_bb;
    TPMT_PUBLIC const& tpmt_public=tpm2b_ekpd.publicArea;
    if (tpmt_public.type!=TPM_ALG_RSA)
    {
        std::cerr << "get_ek_from_public_data: not an RSA key\n";
        return ek_bb;
    }
    
    ek_bb=Byte_buffer(tpmt_public.unique.rsa.t.buffer,tpmt_public.unique.rsa.t.size);

    return ek_bb;
}

G1_point get_daa_key_from_public_data_bb(Byte_buffer const& daa_pd)
{
    TPM_RC rc=0;
    G1_point daa_pt;
    Byte_buffer daad=daa_pd;
    TPM2B_PUBLIC tpm2b_daapd;
    rc=unmarshal_public_data_B(daad,&tpm2b_daapd);
    if (rc!=0)
    {
        std::cerr << "get_daa_key_from_public_data: unmarshalling failed\n";
        return daa_pt;
    }
    if (tpm2b_daapd.publicArea.type!=TPM_ALG_ECC)
    {
        std::cerr << "get_daa_key_from_public_data: not an ECC key\n";
        return daa_pt;
    }    

    return get_daa_key_from_public_data(tpm2b_daapd);
}

G1_point get_daa_key_from_public_data(TPM2B_PUBLIC const& tpm2b_daapd)
{
    G1_point daa_pt;
    if (tpm2b_daapd.publicArea.type!=TPM_ALG_ECC)
    {
        std::cerr << "get_daa_key_from_public_data: not an ECC key\n";
        return daa_pt;
    }    

	TPMS_ECC_POINT tpm_pt=tpm2b_daapd.publicArea.unique.ecc;
	daa_pt=std::make_pair(ecc_param_to_bb(tpm_pt.x),ecc_param_to_bb(tpm_pt.y));

    return daa_pt;
}

TPM_RC report_ecc_parameters(
TSS_CONTEXT* tss_context,
TPMI_ECC_CURVE curve_id,
std::ostream& os
)
{
    TPM_RC rc=0;

    ECC_Parameters_In ep_in;
    ECC_Parameters_Out ep_out;
    ep_in.curveID=curve_id;
    if (rc == 0) {
		rc = TSS_Execute(tss_context,
			(RESPONSE_PARAMETERS *)&ep_out,
			(COMMAND_PARAMETERS *)&ep_in,
			NULL,
			TPM_CC_ECC_Parameters,
			TPM_RH_NULL, NULL, 0);
	}
    if (rc!=0)
    {
        report_tpm_error(rc, "Querying ECC parameters");
    }
    else
    {
        Byte_buffer ep_a(ep_out.parameters.a.t.buffer,ep_out.parameters.a.t.size);
        Byte_buffer ep_b(ep_out.parameters.b.t.buffer,ep_out.parameters.b.t.size);
        Byte_buffer ep_gX(ep_out.parameters.gX.t.buffer,ep_out.parameters.gX.t.size);
        Byte_buffer ep_gY(ep_out.parameters.gY.t.buffer,ep_out.parameters.gY.t.size);
        Byte_buffer ep_p(ep_out.parameters.p.t.buffer,ep_out.parameters.p.t.size);
        Byte_buffer ep_n(ep_out.parameters.n.t.buffer,ep_out.parameters.n.t.size);
        os << "  a: " << ep_a.to_hex_string() << '\n';
        os << "  b: " << ep_b.to_hex_string() << '\n';
        os << " gX: " << ep_gX.to_hex_string() << '\n';
        os << " gY: " << ep_gY.to_hex_string() << '\n';
        os << "  p: " << ep_p.to_hex_string() << '\n';
        os << "  n: " << ep_n.to_hex_string() << '\n';
        os << "sign.scheme: 0x" << std::hex << ep_out.parameters.sign.scheme << '\n';
        os << " kdf.scheme: 0x" << ep_out.parameters.kdf.scheme << '\n';
        os << "    keySize: " << std::dec << ep_out.parameters.keySize << '\n';
    }

    return rc;
}

// Useful print routines
void print_buffer(
std::ostream& os,
const uint8_t* buf,
const size_t len,
bool remove_leading
)
{
    if (len==0)
    {
        os << "buffer empty";
        return;
    }
    std::ios oldState(nullptr);
	oldState.copyfmt(os);
	os << std::setfill('0') << std::hex;
	if (remove_leading)
	{
		if (buf[0]!=0)
			os << 0+buf[0];
	}
	else
		os << std::setw(2) << 0 + buf[0];
	
	for (int i = 1; i < len; ++i)
		os << std::setw(2) << 0 + buf[i];	// 0 + used to force conversion to an integer for printing

	os.copyfmt(oldState);
}

void print_attest_data(
std::ostream& os,
TPMS_ATTEST const& ad
)
{
    os << std::setfill('0') << std::hex;    
    os << std::hex << "Attestation data:";
    os << "\n           magic: " << ad.magic;
    os << "\n            type: " << ad.type;
    os << "\n qualifiedSigner: ";
    print_buffer(os,ad.qualifiedSigner.t.name,ad.qualifiedSigner.t.size,false);
    os << "\n       extraData: ";
    print_buffer(os,ad.extraData.t.buffer,ad.extraData.t.size,false);
    os << "\n      clock info: clock: " << std::setw(16) << ad.clockInfo.clock;
    os << "\n      clock info: resetCount: " << std::setw(8) << ad.clockInfo.resetCount;
    os << "\n      clock info: restartCount: " << std::setw(8) << ad.clockInfo.restartCount;
    os << "\n      clock info: safe: " << std::setw(2) << 0+ad.clockInfo.safe;
    os << "\n firmwareVersion: " << std::setw(16) << ad.firmwareVersion;
    if (ad.type==TPM_ST_ATTEST_CERTIFY)
    {
        os << "\n         Certify:";
        TPMS_CERTIFY_INFO const& cert_info=ad.attested.certify;
        os << "\n            name: ";
        print_buffer(os,cert_info.name.t.name,cert_info.name.t.size,false);
        os << "\n   qualifiedName: ";
        print_buffer(os,cert_info.qualifiedName.t.name,cert_info.qualifiedName.t.size,false);
        os << '\n';
    }
    else if (ad.type==TPM_ST_ATTEST_QUOTE)
    {
        TPMS_QUOTE_INFO const& quote_info=ad.attested.quote;
        os << "\n           Quote:";
        os << "\n          digest: ";
        print_buffer(os,quote_info.pcrDigest.t.buffer,quote_info.pcrDigest.t.size,false);
        os << '\n';
        
    }
    else if (ad.type==TPM_ST_ATTEST_TIME)
    {
        os << "\n            Time:";
        TPMS_TIME_ATTEST_INFO const& time_info=ad.attested.time;
        os << "\n            time: " << std::setw(16) << time_info.time.time;
        TPMS_CLOCK_INFO const& ci=time_info.time.clockInfo;
        os << "\n      clock info: clock: " << std::setw(16) << ci.clock;
        os << "\n      clock info: resetCount: " << std::setw(8) << ci.resetCount;
        os << "\n      clock info: restartCount: " << std::setw(8) << ci.restartCount;
        os << "\n      clock info: safe: " << std::setw(2) << 0+ci.safe;    
        os << "\n firmwareVersion: " << std::setw(16) << time_info.firmwareVersion << '\n';        
    }
    else
    {
        os << "\nPrinting details for attest data of type: " << ad.type << " not yet implemented\n";
    }
}
