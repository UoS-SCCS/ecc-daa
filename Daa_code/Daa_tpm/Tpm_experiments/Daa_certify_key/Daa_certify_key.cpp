/*******************************************************************************
* File:        Daa_certify_key.cpp
* Description: Program to test the DAA sign protocol
*
* Author:      Chris Newton
*
* Created:     Sunday 5 May 2019
*
* (C) Copyright 2019, University of Surrey, all rights reserved.
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
#include <fstream>
#include <string>
#include "Tss_includes.h"
#include "Tss_setup.h"
#include "Make_credential.h"
#include "Tpm_error.h"
#include "Tpm_initialisation.h"
#include "Tpm_daa.h"
#include "Tpm_utils.h"
#include "bnp256_param.h"
#include "Openssl_utils.h"
#include "Openssl_bn_utils.h"
#include "Openssl_ec_utils.h"
#include "Openssl_aes.h"
#include "Openssl_bnp256.h"
#include "Openssl_verify.h"
#include "Number_conversions.h"
#include "Clock_utils.h"
#include "Credential_issuer.h"
#include "Host.h"
#include "Sha.h"
#include "G1_utils.h"
#include "G2_utils.h"
#include "Model_hashes.h"
#include "Amcl_utils.h"
#include "Amcl_pairings.h"
#include "Tpm2_commit.h"
#include "Daa_certify.h"
#include "Daa_credential.h"
#include "Openssl_ec_map_to_point.h"
#include "Daa_signatures.h"

int main(int argc, char *argv[])
{
	Program_data pd;
 	init_openssl();

    auto ir=initialise(argc,argv,"certify",pd);
    if (ir!=Init_result::init_ok)
    {
        if (ir==Init_result::init_help)
            return EXIT_SUCCESS;
            
        return EXIT_FAILURE;
    }
   
    Random_byte_generator rbg;
    Protocol_result pr;
    try
    {
        pr=run_protocol(pd,rbg);
    }
    catch(const std::exception& e)
    {
        log_ptr->os() << "Exception caught: " << e.what() << std::endl;
        std::cerr << e.what() << std::endl;
        pr=Protocol_result::protocol_failed;
    }
   
 	cleanup_openssl();
	
	if (pr==Protocol_result::protocol_failed)
    {
        return EXIT_FAILURE;
    }
    
    tpm_timings.write_tpm_timings(log_ptr->os());

    return EXIT_SUCCESS;
}

Protocol_result run_protocol(Program_data& pd, Random_byte_generator& rbg)
{
    TPM_RC rc=pd.tpm.initialise(*pd.sp);
    if (rc!=0)
    {
        std::cerr << "Initialisation of the tpm failed\n";
        return Protocol_result::protocol_failed;
    }

    std::ifstream is;
    std::string filename=pd.file_basename;
    filename+="/"+pd.credential_filename;
    is.open(filename.c_str(),std::ios::in);
    if (!is)
    {
        std::cerr << "Unable to open the DAA credential file: " << filename << '\n';
        return Protocol_result::protocol_failed;
    }
    
    Byte_buffer tmp;
    is >> tmp;
    Key_data daa_kd=deserialise_key_data(tmp);
    if (log_ptr->debug_level()>0)
    {
        log_ptr->write_to_log("Key_data read from file\n");
    }    
    is >> tmp;
    Issuer_public_keys ipk=deserialise_issuer_public_keys(tmp);
    if (log_ptr->debug_level()>0)
    {
        log_ptr->write_to_log("Issuer_public_keys read from file\n");
    }    
    Byte_buffer serialised_cre;
    is >> serialised_cre;
    if (log_ptr->debug_level()>0)
    {
        log_ptr->write_to_log("Serialised credential read from file\n");
    }    

    is.close();

    G2_point const& pk_x=ipk.first;
    G2_point const& pk_y=ipk.second;;

    if (log_ptr->debug_level()>0)
    {
        log_ptr->os() << "data read from the credential file:\npk_x1: (" << pk_x.first.first.to_hex_string()
                  << "," << pk_x.first.second.to_hex_string() << ")\npk_x2: (" << pk_x.second.first.to_hex_string()
                  << "," << pk_x.second.second.to_hex_string() << ")\npk_y1: (" << pk_y.first.first.to_hex_string()
                  << "," << pk_y.first.second.to_hex_string() << ")\npk_y2: (" << pk_y.second.first.to_hex_string()
                  << "," << pk_y.second.second.to_hex_string() << ")\nPrivate data: " << daa_kd.first.to_hex_string()
                  << "\nPublic data: " << daa_kd.second.to_hex_string() << "\nSerialied credential: " 
                  << serialised_cre.to_hex_string() << std::endl;
    }

    auto daa_cre=deserialise_daa_credential(serialised_cre);
    if (log_ptr->debug_level()>0)
    {
        log_ptr->write_to_log("Credential deserialised\n");
    }    

    rc=pd.tpm.install_and_load_key("daa","ek",daa_kd);
    if (rc!=0)
    {
        std::cerr << "Failed to load the DAA key retrieved from the file\n" << pd.tpm.get_last_error() << '\n';
        return Protocol_result::protocol_failed;
    }

    Tpm_timer tt;
    // Prepare to use the DAA key
    Daa_credential r_cre=randomise_daa_credential(daa_cre,rbg);
  
    Byte_buffer bsn;
    if (pd.use_basename)
    {
        bsn=rbg(1);
        uint8_t bsn_size=1+(bsn[0]>>3);
        bsn=rbg(bsn_size);
    }

    log_ptr->os() << "Basename: ";

    G1_point map_pt;
    G1_point pt_j;
    if (bsn.size()!=0)
    {
        map_pt=point_from_basename(bsn);
        pt_j=std::make_pair(bb_mod(sha256_bb(map_pt.first),bnp256_p),map_pt.second);
        log_ptr->os() << bsn << std::endl;
    }
    else
    {
        log_ptr->os() << "unset\n";
    }

    G1_point pt_s=r_cre[1];
    Commit_data cd;
    rc=pd.tpm.initiate_daa_signature(map_pt.first,map_pt.second,pt_s,cd);
    if (rc!=0)
    {
        std::cerr << "initiate_daa_signature returned: " << pd.tpm.get_last_error() << '\n';
        return Protocol_result::protocol_failed;;
    }
    auto dur=tt.get_duration();
    std::string prefix=(pd.use_basename)?"T8B":"T8N";
    tpm_timings.add(prefix+" Host commits",dur);
    tt.reset();

    // Host creates a test key
    Byte_buffer qps_pd;
    int qps_id=0;
    rc=pd.tpm.create_and_load_pseudonym_key(qps_id,qps_pd);
    if (rc!=0)
    {
        std::cerr << "create_and_load_pseudonym_key_data returned: " << pd.tpm.get_last_error() << '\n';
        return Protocol_result::protocol_failed;
    }

    tt.reset();
    Commit_points const& pts=cd.second;
    Byte_buffer label("credential data");
    Byte_buffer c=sign_c(label,r_cre,pt_j,pts[0],pts[1],pts[2]);

    Byte_buffer cert;
    Byte_buffer nt;
    Byte_buffer sig_s;
    pd.tpm.certify_and_sign(qps_id,cd.first,c,cert,nt,sig_s);

    tpm_timings.add("T10 Host certifies",tt.get_duration());

    if (log_ptr->debug_level()>0)
    {
        TPMS_ATTEST att_cert;
        rc=unmarshal_attest_data_B(cert,&att_cert);
        if (rc!=0)
        {
            log_ptr->os() << "Unable to unmarshal the attestation data\n";
            return Protocol_result::protocol_failed;
        }
        print_attest_data(log_ptr->os(),att_cert);        
    }

    Byte_buffer h1=sha256_bb(c+sha256_bb(cert));

    Byte_buffer h2=bb_mod(sha256_bb(nt+h1),bnp256_order);

    filename=pd.file_basename+"/"+pd.signature_file+pd.run_number;
    std::ofstream os(filename.c_str());
    if (!os)
    {
        std::cerr << "Unable to open the attestation file: " << filename << '\n';
        return Protocol_result::protocol_failed;
    }

    os << "certify\n";
    os << label << '\n';
    os << qps_pd<< '\n';
    os << cert << '\n';
    os << serialise_issuer_public_keys(ipk) << '\n';
    if (pd.use_basename)
    {
        os << bsn << '\n';
        os << g1_point_serialise(pt_j) << '\n';
        os << g1_point_serialise(pts[0]) << '\n';
    }
    os << serialise_daa_credential(r_cre) << '\n';
    os << nt << '\n' << sig_s << '\n' << h2 << '\n';
    os.close();   

    return Protocol_result::protocol_ok;
}

