/*****************************************************************************
* File:        Verify_daa_signature.cpp
* Description: Program to verify a DAA signature
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
#include "Make_credential.h"
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
#include "Sha.h"
#include "G1_utils.h"
#include "G2_utils.h"
#include "Issuer_public_keys.h"
#include "Model_hashes.h"
#include "Amcl_utils.h"
#include "Amcl_pairings.h"
#include "Tpm2_commit.h"
#include "Daa_certify.h"
#include "Daa_credential.h"
#include "Openssl_ec_map_to_point.h"
#include "Verify_daa_attestation.h"
#include "Verify_daa_signature.h"


Tpm_timings tpm_timings;

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

    Verify_result vr;
    try
    {
        vr=verify(pd);
    }
    catch(const std::exception& e)
    {
        log_ptr->os() << "Exception caught: " << e.what() << std::endl;
        std::cerr << e.what() << std::endl;
        vr=Verify_result::verify_failed;
    }
   
 	cleanup_openssl();
	
	if (vr==Verify_result::verify_failed)
    {
       	return EXIT_FAILURE;

    }

    tpm_timings.write_tpm_timings(log_ptr->os());

    return EXIT_SUCCESS;
}

void usage(std::ostream& os, const char* name)
{
	os << "Usage: " << name << "\n\t-h, --help - this message\n"
                    << "\t-v, --version - the code version\n"
                    << "\t-g, --debug <debug level> - (0,1,2)\n"
                    << "\t-d, --datadir <data directory> - (default .)\n"
                    << "\t<signature filename>\n";
}

Init_result initialise(int argc, char *argv[],Program_data& pd)
{
   if (argc<2)
    {
        std::cerr << "A signature filename, or help request (-h, or --help, or -v, or --version) must be given\n";
        usage(std::cerr,argv[0]);
		return Init_result::init_failed;        
    }
    std::string first_arg(argv[1]);
    if (argc==2)
    {
        if (first_arg=="-h" || first_arg=="--help")
        { 
            usage(std::cout,argv[0]);
            return Init_result::init_help;
        }
        else if (first_arg=="-v" || first_arg=="--version")
        {
            std::cout << code_version << '\n';
            return Init_result::init_help;
        }
    }
    // The last argument is the signature filename
    pd.signature_filename=std::string(argv[argc-1]);
    // The remaining arguments will be options
    argc--;
    auto pos=pd.signature_filename.find_first_of('_');
    if (pos==std::string::npos)
    {
        std::cerr << "Signature filename: " << pd.signature_filename << " has the wrong format" << '\n';
        return Init_result::init_failed;
    }

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
        default:
            std::cerr << "Invalid option: " << argv[arg-1] << '\n';
            usage(std::cerr,argv[0]);
            return Init_result::init_failed;
        }
    }
    
    pos=pd.signature_filename.find("bsn");
    if (pos==std::string::npos)
    {
        std::cerr << "Signature filename: " << pd.signature_filename << " has the wrong format\n";
        return Init_result::init_failed;
    }

    pd.use_basename=false;
    pos=pd.signature_filename.find("_no_bsn");
    if (pos==std::string::npos)
    {
        pd.use_basename=true;
    }

    pos=pd.signature_filename.find_last_of('_');
    if (pos==std::string::npos)
    {
        std::cerr << "Signature filename has the wrong format" << '\n';
        return Init_result::init_failed;
    }
    std::string filename_prefix=pd.signature_filename.substr(0,pos+1);
    std::string run_number=pd.signature_filename.substr(pos+1);

    std::string filename=pd.file_basename+"/"+filename_prefix+"ver_"+run_number;
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

    log_ptr->os() << std::boolalpha << "\nUse basename: " << pd.use_basename
                  << "\nDebug level: " << debug_level << std::endl;

    return Init_result::init_ok;
}

Verify_result verify(Program_data& pd)
{
    std::string filename=pd.file_basename+"/"+pd.signature_filename;
    std::ifstream is(filename.c_str());
    if (!is)
    {
        log_ptr->os() << "Unable to open the signature filename: " << filename << std::endl;
        return Verify_result::verify_failed;
    }

    try
    {
        std::string type;
        std::string msg;
        Byte_buffer bsn;
        G1_point pt_j;
        G1_point pt_k;
        Byte_buffer tmp;

        getline(is,type);
        if (log_ptr->debug_level()>0)
        {
            log_ptr->write_to_log("Signature type read from file\n");
        }   
        getline(is,msg);
        if (log_ptr->debug_level()>0)
        {
            log_ptr->write_to_log("Test message read from file\n");
        }   
        is >> tmp;
        Issuer_public_keys ipk=deserialise_issuer_public_keys(tmp);
        if (log_ptr->debug_level()>0)
        {
            log_ptr->write_to_log("Issuer_public_keys read from file\n");
        }    

        if (pd.use_basename)
        {
            is >>bsn;
            if (log_ptr->debug_level()>0)
            {
                log_ptr->write_to_log("basename read from file\n");
            }
            is >> tmp;
            pt_j=g1_point_deserialise(tmp);
            if (log_ptr->debug_level()>0)
            {
                log_ptr->write_to_log("J read from file\n");
            }
            is >> tmp;
            pt_k=g1_point_deserialise(tmp);
            if (log_ptr->debug_level()>0)
            {
                log_ptr->write_to_log("K read from file\n");
            }
        }
               
        Byte_buffer serialised_cre;
        is >> serialised_cre;
        if (log_ptr->debug_level()>0)
        {
            log_ptr->write_to_log("Serialised credential read from file\n");
        }   
        Daa_signature daa_sig;
        is >> daa_sig[0] >> daa_sig[1] >> daa_sig[2];
        if (log_ptr->debug_level()>0)
        {
            log_ptr->write_to_log("Signature data read from file\n");
        }           
        is.close();

        G2_point const& pk_x=ipk.first;
        G2_point const& pk_y=ipk.second;
        Byte_buffer msg_digest=sha256_bb(Byte_buffer(msg));
    
        if (log_ptr->debug_level()>0)
        {
            log_ptr->os() << "data read from the signature file:\ntype: " << type <<"\nmsg: " << msg << "\nbsn: "
                    << bsn.to_hex_string() << "\nJ: (" << pt_j.first.to_hex_string() << "," << pt_j.second.to_hex_string()
                    << ")\nK: (" << pt_k.first.to_hex_string() << "," << pt_k.second.to_hex_string() 
                    << ")\npk_x1: (" << pk_x.first.first.to_hex_string() << "," << pk_x.first.second.to_hex_string()
                    << ")\npk_x2: (" << pk_x.second.first.to_hex_string() << "," << pk_x.second.second.to_hex_string()
                    << ")\npk_y1: (" << pk_y.first.first.to_hex_string() << "," << pk_y.first.second.to_hex_string()
                    << ")\npk_y2: (" << pk_y.second.first.to_hex_string() << "," << pk_y.second.second.to_hex_string()
                    << "\nSerialied credential: " << serialised_cre.to_hex_string() << "\nn_M: " 
                    << daa_sig[0].to_hex_string() << "\ns: " << daa_sig[1].to_hex_string() << "\nh_2: " 
                    << daa_sig[2].to_hex_string() << std::endl;
        }

        auto r_cre=deserialise_daa_credential(serialised_cre);

        Tpm_timer tt;

        G1_point map_pt;
        G1_point pt_j_prime;
        if (bsn.size()!=0)
        {
            Tpm_timer tt2;
            map_pt=point_from_basename(bsn);
            pt_j_prime=std::make_pair(bb_mod(sha256_bb(map_pt.first),bnp256_p),map_pt.second);
        }
        if (pt_j!=pt_j_prime)
        {
            log_ptr->os() << "J != J'\n";
            throw(std::runtime_error("J!=J'"));
        }

        Bn_ctx_ptr ctx =new_bn_ctx();
        Ec_group_ptr ecgrp=new_ec_group("bnp256"); // Name ignored for now
        if (ecgrp.get()==nullptr)
        {
            throw(Openssl_error("tes_daa_sign: error generating the curve"));
        }
        if (1!=EC_GROUP_check(ecgrp.get(),ctx.get()))
        {
            throw(Openssl_error("test_daa_sign: EC_GROUP_check failed"));
        }

        // h_2
        Byte_buffer& hash2=daa_sig[2];
        Byte_buffer& sig_s=daa_sig[1];

        G1_point l_prime_bb;
        G1_point e_prime_bb;
        G1_point tmp_bb;
        if (bsn.size()>0)
        {
            // [s]J
            G1_point s_j_bb=ec_point_mul(ecgrp,sig_s,pt_j);
            // [h_2]K
            G1_point h2_k_bb=ec_point_mul(ecgrp,hash2,pt_k);
            // L'
            tmp_bb=ec_point_invert(ecgrp,h2_k_bb);
            l_prime_bb=ec_point_add(ecgrp,s_j_bb,tmp_bb); 
        }
        // [s]S
        G1_point s_pt_s_bb=ec_point_mul(ecgrp,sig_s,r_cre[1]);
        // [h_2]W
        G1_point h2_pt_w_bb=ec_point_mul(ecgrp,hash2,r_cre[3]);
        // E'
        tmp_bb=ec_point_invert(ecgrp,h2_pt_w_bb);
        e_prime_bb=ec_point_add(ecgrp,s_pt_s_bb,tmp_bb); 

        Byte_buffer v_c=sign_c(msg_digest,r_cre,pt_j,pt_k,l_prime_bb,e_prime_bb);

        Byte_buffer h2_prime=bb_mod(sha256_bb(daa_sig[0]+sha256_bb(v_c)),bnp256_order);


        if (h2_prime!=hash2)
        {
            log_ptr->write_to_log("Signature check failed\n");
            return Verify_result::verify_failed;
        }

        Tpm_timer tt2;
        bool pairings_ok=check_daa_pairings(r_cre,std::make_pair(pk_x,pk_y));
        if (!pairings_ok)
        {
            log_ptr->write_to_log("DAA credential pairings test (S,C,Q) failed\n");
            return Verify_result::verify_failed;
        }
        auto dur=tt.get_duration();
        auto dur2=tt2.get_duration();
        std::string prefix=(pd.use_basename)?"T12B":"T12N";
        tpm_timings.add(prefix+" verify signature",dur);
        tpm_timings.add("T13 Verifier checks pairings (S,C,Q)",dur2);
    }
    catch(const std::exception& e)
    {
        log_ptr->os() << "Exception caught: " << e.what() << std::endl;
        std::cerr << e.what() << std::endl;
        return Verify_result::verify_failed;   
    }

	return Verify_result::verify_ok;
}
