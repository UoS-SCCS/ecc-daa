/*****************************************************************************
* File:        Make_daa_credential.cpp
* Description: Program to generate the credential for a DAA key
*
* Author:      Chris Newton
*
* Created:     Saturday 4 May 2019
*
* (C) Copyright 2019, University of Surrey, all rights reserved.
*
*****************************************************************************/
#include <iostream>
#include <fstream>
#include <string>
#include "Tss_includes.h"
#include "Tss_setup.h"
#include "Tpm_error.h"
#include "Tpm_daa.h"
#include "Tpm_utils.h"
#include "Tpm_param.h"
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
#include "Make_credential.h"
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
#include "Verify_daa_attestation.h"
#include "Make_daa_credential.h"

int main(int argc, char *argv[])
{

	Program_data pd;
	init_openssl();

    auto ir=initialise(argc,argv,pd);
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
	
	if (pr==Protocol_result::protocol_ok)
    {
        tpm_timings.write_tpm_timings(log_ptr->os());
    }
    
	return EXIT_SUCCESS;
}

void usage(std::ostream& os, const char* name)
{
    os << code_version << '\n';
	os << "Usage: " << name << "\n\t-h, --help - this message\n\t-v, --version - the code version\n"
                    << "\t-t, --dev - use the TPM device\n\t-s, --sim - use the TPM simulator (default)\n"
                    <<  "\t-g, --debug <debug level> - (0,1,2)\n\t-d, --datadir <data directory> - (default .)\n";
}

Init_result initialise(int argc, char *argv[], Program_data& pd)
{
    // Used to catch multiple inputs for the device type
    std::string device="null";
    // Option defaults
    int debug_level=0;
    pd.file_basename=".";
 
    int arg=1;
    while (arg<argc)
    {
        auto search=program_options.find(argv[arg++]);
        if (search==program_options.end())
        {
            std::cerr << "Invalid option: " << argv[arg-1] << '\n';
            usage(std::cerr,argv[0]);
            return Init_result::init_failed;
        }
        Option o=search->second;
        switch (o)
        {
        case Option::datadir:
            pd.file_basename=std::string(argv[arg++]);
            break;
        case Option::usedev:
            if (device=="null")
            {
                device="T";
            }
            else
            {
                std::cerr << "Only one interface can be selected\n";
                usage(std::cerr,argv[0]);
                return Init_result::init_failed;
            }
            break;
        case Option::usesim:
            if (device=="null")
            {
                device="S";
            }
            else
            {
                std::cerr << "Only one interface can be selected\n";
                usage(std::cerr,argv[0]);
                return Init_result::init_failed;
            }
            break;
        case Option::debug:
            {
                std::string level(argv[arg]);
                if (level!="0" && level!="1" && level!="2")
                {
                    usage(std::cerr,argv[0]);
                    std::cerr << "Debug levels are 0, 1 or 2 (default 0)\n";
                    return Init_result::init_failed;            
                }
                debug_level=atoi(argv[arg++]);
            }
            break;
        case Option::help:
            usage(std::cout,argv[0]);
            return Init_result::init_help;
        case Option::version:
            std::cout << code_version << '\n';
            return Init_result::init_help;
        default:
            std::cerr << "Invalid option - " << argv[arg-1] << '\n';
            usage(std::cerr,argv[0]);
            return Init_result::init_failed;
        }
    }
    
    if (device=="null") //  then use default
    {
        device="S";
        pd.sp.reset(new Simulator_setup);
        pd.sp->data_dir.value=Tss_option::sim_data_dir.value;
    }
	else
	{
        pd.sp.reset(new Device_setup);
        pd.sp->data_dir.value=Tss_option::pi_data_dir.value;
	}

    pd.file_basename+="/Daa_"+device+"_cre_";
	pd.run_number=generate_log_number();
    std::string filename=pd.file_basename+"log_"+pd.run_number;
	try
	{
		log_ptr.reset(new Timed_file_log(filename));
	}
	catch (std::runtime_error &e)
	{
		std::cerr << e.what() << '\n';
		return Init_result::init_failed;
	}

	log_ptr->set_debug_level(debug_level);

    log_ptr->os() << "\ndevice: " << device << "\nDebug level: " << debug_level << std::endl;

    TPM_RC rc=pd.tpm.setup(*pd.sp);
	if (rc!=0)
	{
		log_ptr->os() << "Setting up the TPM returned: " << pd.tpm.get_last_error() << '\n';
		return Init_result::init_failed;
	}

	Byte_buffer ek_pd;
	rc=pd.tpm.get_endorsement_key_data(ek_pd);
	if (rc!=0)
	{
		std::cerr << "get_endorsement_key_data returned: " << pd.tpm.get_last_error() << '\n';
		return Init_result::init_failed;
	}	

	pd.ek_bb=get_ek_from_public_data_bb(ek_pd);
	if (pd.ek_bb.size()==0)
	{
        std::cerr << "Unable to extract the endorsement key from the public data\n";
		return Init_result::init_failed;
	}

	return Init_result::init_ok;
}

Protocol_result run_protocol(Program_data& pd, Random_byte_generator& rbg)
{
  
	Credential_issuer issuer;
	issuer.set_ek_public_key(pd.ek_bb);

    TPM_RC rc=pd.tpm.initialise(*pd.sp);
    if (rc!=0)
    {
        std::cerr << "Initialisation of the tpm failed\n";
        return Protocol_result::protocol_failed;
    }
    
    Tpm_timer tt;
     
	Byte_buffer daa_pd;
	rc=pd.tpm.create_and_load_daa_key(daa_pd);
	if (rc!=0)
	{
		std::cerr << "create_and_load_daa_key returned: " << pd.tpm.get_last_error() << '\n';
		return Protocol_result::protocol_failed;
	}	
    tpm_timings.add("T1 Host prepares",tt.get_duration());
    tt.reset();
	
    rc=issuer.set_daa_public_data(daa_pd);
	if (rc!=0)
	{
		std::cerr << "Unmarshalling the daa_key_data failed." << '\n';
		return Protocol_result::protocol_failed;		
	}

	Credential_data cd=issuer.make_credential_data();
    tpm_timings.add("T2 Issuer challenges",tt.get_duration());
    tt.reset();

	Byte_buffer ck;
	rc=get_credential_key(pd.tpm,cd,ck);
	if (rc!=0)
	{
		return Protocol_result::protocol_failed;	
	}
	
	auto issuer_public_keys=issuer.get_public_keys();
	G2_point const& pk_x=issuer_public_keys.first;
	G2_point const& pk_y=issuer_public_keys.second;
	Byte_buffer str=host_str(pk_x,pk_y,ck,pd.ek_bb);

	// Initiate the validation of the DAA key 
    G1_point s;
    Byte_buffer s2;
	Byte_buffer y2;
	Commit_data comd1;
    rc=pd.tpm.initiate_daa_signature(s2,y2,s,comd1);
    if (rc!=0)
    {
        std::cerr << "initiate_daa_signature returned: " << pd.tpm.get_last_error() << '\n';
        throw(Tpm_error("initiate_daa_signature failed"));
    }

	G1_point daa_public_key=get_daa_key_from_public_data_bb(daa_pd);
    G1_point p1=std::make_pair(bnp256_gX,bnp256_gY);
	Byte_buffer p=host_p(p1,daa_public_key,comd1.second[2],str);

	Daa_signature daa_sig;
	rc=pd.tpm.complete_daa_signature(comd1.first,p,daa_sig[0],daa_sig[1]);
	if (rc!=0)
	{
		std::cerr << "complete_daa_signature: returned: " << pd.tpm.get_last_error() << '\n';
		return Protocol_result::protocol_failed;
	}

    Byte_buffer p_tpm=sha256_bb(p);
	if (pd.tpm.uses_new_daa_signature())
	{
		daa_sig[2]=daa_sig[0];
		daa_sig[0]=bb_mod(sha256_bb(daa_sig[2]+p_tpm),bnp256_order);
	}
    tpm_timings.add("T3 Host responds",tt.get_duration());
    tt.reset();

	if(!issuer.check_daa_signature(pd.tpm.uses_new_daa_signature(),ck,daa_sig))
	{
		std::cerr << "Verify_daa_data failed\n";
		return Protocol_result::protocol_failed;
	}
    tpm_timings.add("T4 Issuer verifies response",tt.get_duration());
    tt.reset();

	auto fcre=issuer.make_full_credential();
    tpm_timings.add("T5 Issuer creates credential",tt.get_duration());
    tt.reset();

	rc=get_credential_key(pd.tpm,fcre.first,ck);
	if (rc!=0)
	{
		std::cerr << "Failed to obtain the credential key from the TPM\n";
		return Protocol_result::protocol_failed;
	}

	Byte_buffer initial_iv(aes_block_size,0);
    Byte_buffer cre=ossl_decrypt("AES-128-CTR",fcre.second,ck,initial_iv);

	auto tmp_bv=deserialise_byte_buffers(cre);
	auto daa_cre=deserialise_daa_credential(tmp_bv[0]);
	auto daa_cre_sig=deserialise_daa_credential_signature(tmp_bv[1]);

	bool sig_ok=verify_daa_credential_signature(p1,daa_public_key,daa_cre,daa_cre_sig);
	if (!sig_ok)
	{
		std::cout << "DAA credential signature failed\n";
        return Protocol_result::protocol_failed;
	}
    
	Tpm_timer tt2;
    bool pairings_ok=check_daa_pairings(daa_cre,issuer_public_keys);
    if (!pairings_ok)
    {
        std::cout << "DAA credential pairings test (Host) failed\n";
        return Protocol_result::protocol_failed;
    }
    tpm_timings.add("T6 Host verifies credential",tt.get_duration());
    tpm_timings.add("T7 Host checks pairings",tt2.get_duration());

    Key_data daa_kd;
    rc=pd.tpm.get_daa_key_data(daa_kd);
    if (rc!=0)
    {
        std::cerr << "get_daa_key_data returned: " << pd.tpm.get_last_error() << '\n';
        return Protocol_result::protocol_failed;        
    }

    if (log_ptr->debug_level()>0)
    {
        log_ptr->os() << "data written to the credential file:\npk_x1: (" << pk_x.first.first
                  << "," << pk_x.first.second << ")\npk_x2: (" << pk_x.second.first
                  << "," << pk_x.second.second << ")\npk_y1: (" << pk_y.first.first
                  << "," << pk_y.first.second << ")\npk_y2: (" << pk_y.second.first
                  << "," << pk_y.second.second << ")\nPrivate data: " << daa_kd.first
                  << "\nPublic data: " << daa_kd.second << "\nSerialied credential: " 
                  << tmp_bv[0] << std::endl;
    }
    std::string filename=pd.file_basename+pd.run_number;
    std::ofstream os;
    os.open(filename.c_str(),std::ios::out);
    if (!os)
    {
        std::cerr << "Unable to open the DAA credential file\n";
    }
    os << serialise_key_data(daa_kd) << '\n';
    os << serialise_issuer_public_keys(issuer_public_keys) << '\n';
    os << tmp_bv[0] << '\n';
    os.close();

    return Protocol_result::protocol_ok;
}

