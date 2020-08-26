/******************************************************************************
* File:        Tpm_daa.cpp
* Description: Implementation of the 'vanilla" TPM class, derived from the
*              VANET TPM class, so currently still returning an error code
*              and passing data in Byte_buffers
*
* Author:      Chris Newton
*
* Created:     Friday 12 April 2019
*
* (C) Copyright 2019, University of Surrey, all rights reserved.
*
******************************************************************************/

#include <chrono>
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <cstdlib>
#include "Tss_includes.h"
#include "Create_primary_rsa_key.h"
#include "Make_key_persistent.h"
#include "Flush_context.h"
#include "Tpm_error.h"
#include "Tpm_keys.h"
#include "Create_daa_key.h"
#include "Create_ecdsa_key.h"
#include "Tpm2_commit.h"
#include "Daa_sign.h"
#include "Daa_certify.h"
#include "Daa_quote.h"
#include "Display_public_data.h"
#include "Openssl_ec_utils.h"
#include "Clock_utils.h"
#include "Tss_setup.h"
#include "Tpm_initialisation.h"
#include "Tpm_defs.h"
#include "Tpm_param.h"
#include "Tpm_daa.h"

Tpm_timings tpm_timings;

// To interface with Java most of the parameters are passed to-and-fro in Byte_Buffers
TPM_RC Tpm_daa::setup(Tss_setup const& tps)
{
	TPM_RC rc=0;
	try
	{
		if (available_)
		{
			throw(Tpm_error("Tpm_daa class already setup"));
		}

		if (log_ptr->debug_level()>0)
		{
			log_ptr->write_to_log("Tpm_daa: setup\n");
		}

        auto nc=set_new_context(tps);
        rc=nc.first;
        if (rc!=0)
        {
            log_ptr->os() << "Tpm_daa: setup: set_new_context : " << get_tpm_error(rc) << std::endl;
            throw(Tpm_error("TPM_daa: setup: failed to create a TSS context\n"));
        }
        tss_context_=nc.second;

        if (!check_pcr_provision(tss_context_))
        {
            log_ptr->os() << "Tpm_daa: setup: check_pcr_provision failed" << std::endl;
            throw(Tpm_error("Tpm_daa: setup: check_pcr_provision failed - provision the TPM\n"));            
        } 

        if (!persistent_key_available(tss_context_,ek_persistent_handle))
        {
			log_ptr->os() << "Tpm_daa: setup: seting up primary key: " << get_tpm_error(rc) << std::endl; 
			throw(Tpm_error("Tpm_daa: setup: setting primary key failed - provision the TPM"));
		}

        TPM2B_PUBLIC ek_public;
        read_ek_public_data(tss_context_,ek_public);
        Tpm_key ek("ek",ek_public,ek_persistent_handle);
        ek.persistent=true;
        key_store_.add_key(ek);

        get_tpm_revision_data();
    
        rc=TSS_Delete(tss_context_);
        tss_context_=nullptr;

        available_=true;
    }
	catch (Tpm_error &e)
	{
		rc=1;
		last_error_=std::string(e.what());
	}
	catch (...)
	{
		rc=2;
		last_error_="Tpm_daa: setup: failed - uncaught exception";
	}

	return rc;
}

TPM_RC Tpm_daa::initialise(Tss_setup const& tps)
{
	TPM_RC rc=0;
	try
	{
		if (log_ptr->debug_level()>0)
		{
			log_ptr->write_to_log("Tpm_daa: initialise\n");
		}

        if (tss_context_!=nullptr)
        {
            log_ptr->write_to_log("Re-initialising the TPM\n");
            key_store_.delete_all_transient_keys(tss_context_);
            key_store_.report();
		    TSS_Delete(tss_context_);
            tss_context_=nullptr;
        }

        auto nc=set_new_context(tps);
        rc=nc.first;
        if (rc!=0)
        {
            log_ptr->os() << "Tpm_daa: initialise: set_new_context: " << get_tpm_error(rc) << std::endl;
            throw(Tpm_error("Tpm_daa: initialise: failed to create a new TSS context\n"));
        }
        tss_context_=nc.second;

		if (log_ptr->debug_level()>0)
		{
			log_ptr->write_to_log("Tpm_daa: initialise: successful\n");
		}
		next_id_=0; // Used for generating pseudonym key names
		available_=true;
	}
	catch (Tpm_error &e)
	{
		rc=1;
		last_error_=std::string(e.what());
	}
	catch (...)
	{
		rc=2;
		last_error_="Failed - uncaught exception";
	}

	return rc;
}

TPM_RC Tpm_daa::get_endorsement_key_data(Byte_buffer& ek_pd)
{
	TPM_RC rc=0;

	try
	{
		if (log_ptr->debug_level()>0)
		{
			log_ptr->write_to_log("Tpm_daa: get_endorsement_key_data\n");
		}

		Byte_buffer pd=key_store_.public_data_bb("ek");
		if (pd.size()==0)
		{
			log_ptr->write_to_log("Tpm_daa: get_endorsement_key_data: marshalling public data failed\n");
			throw(Tpm_error("Marshalling EK public data failed"));
		}
		ek_pd=pd;
	}
	catch (Tpm_error &e)
	{
		rc=1;
		last_error_=std::string(e.what());
	}
	catch (...)
	{
		rc=2;
		last_error_="Failed - uncaught exception";
	}

	if (log_ptr->debug_level()>0)
	{
		log_ptr->os() << "Tpm_daa: get_endorsement_key_data returned:\npd: " << ek_pd.to_hex_string() << std::endl;
	}
	return rc;
}

TPM_RC Tpm_daa::create_and_load_daa_key(Byte_buffer& daa_pd)
{
	TPM_RC rc=0;

	try
	{
		if (log_ptr->debug_level()>0)
		{
			log_ptr->write_to_log("Tpm_daa: create_and_load_daa_key\n");
		}

		Create_Out out_daa;
		rc=create_daa_key(tss_context_,ek_persistent_handle,TPM_ECC_BN_P256,&out_daa);
		if (rc!=0)
		{
    		log_ptr->os() << "Tpm_daa: initialise: create_daa_key: " << get_tpm_error(rc) << std::endl;
			throw(Tpm_error("Tpm_daa: initialise: unable to create the DAA key"));
		}
		// Accept defaults this key is not loaded yet
		Tpm_key key("daa","ek",out_daa.outPublic,out_daa.outPrivate);
		key_store_.add_key(key);

		Byte_buffer pd=key_store_.public_data_bb("daa");
		if (pd.size()==0)
		{
			log_ptr->write_to_log("Tpm_daa: get_daa_key_data: marshalling public data failed\n");
			throw(Tpm_error("Marshalling DAA public data failed"));
		}

		daa_pd=std::move(pd);

        if (log_ptr->debug_level()>0)
        {
            display_ecc_public(log_ptr->os(),key_store_.public_data("daa"));
            log_ptr->os() << "Tpm_daa: get_daa_key_data returned:\npd: " << daa_pd.to_hex_string() << std::endl;
        }

		TPM_HANDLE daa_handle=key_store_.load_key(tss_context_,"daa");
        if (log_ptr->debug_level()>0)
        {
            log_ptr->os() << "daa handle: " << std::hex << daa_handle << std::endl;;
        }        
    }
	catch (Tpm_error &e)
	{
		rc=1;
		last_error_=std::string(e.what());
	}
	catch (...)
	{
		rc=2;
		last_error_="Failed - uncaught exception";
	}
	
	return rc;
}

TPM_RC Tpm_daa::install_and_load_key(std::string const& name, std::string const& parent, Key_data& kd)
{
	TPM_RC rc=0;

	try
	{
		if (log_ptr->debug_level()>0)
		{
			log_ptr->write_to_log("Tpm_daa: install_and_load_daa_key\n");
		}
        TPM2B_PRIVATE priv;
        rc=unmarshal_private_data_B(kd.first,&priv);
        if (rc!=0)
        {
 			log_ptr->write_to_log("Tpm_daa: install_and_load_key: unmarshalling private data failed\n");
			throw(Tpm_error("Unmarshalling key's private data failed"));           
        }

        TPM2B_PUBLIC pub;
        rc=unmarshal_public_data_B(kd.second,&pub);
        if (rc!=0)
        {
 			log_ptr->write_to_log("Tpm_daa: install_and_load_key: unmarshalling public data failed\n");
			throw(Tpm_error("Unmarshalling key's public data failed"));           
        }
        Tpm_key key(name,parent,pub,priv);
		key_store_.add_key(key);
        if (log_ptr->debug_level()>0)
        {
            log_ptr->os() << "Tpm_daa: install and load key: key " << name << " installed\n";
        }
        key_store_.load_key(tss_context_,name);
        if (log_ptr->debug_level()>0)
            {
                log_ptr->os() << "Tpm_daa: install and load key: key " << name << " loaded\n";
            }        
    }
	catch (Tpm_error &e)
	{
		rc=1;
		last_error_=std::string(e.what());
	}
	catch (...)
	{
		rc=2;
		last_error_="Failed - uncaught exception";
	}
	
	return rc;
}

TPM_RC Tpm_daa::activate_credential(
Byte_buffer const& credential_blob,
Byte_buffer const& secret,
Byte_buffer& c_key
)
{
	if (log_ptr->debug_level()>0)
	{
		log_ptr->write_to_log("Tpm_daa: activate_credential\n");
	}

	TPM_RC rc=0;
	try
	{
		TPM_HANDLE ek_handle=key_store_.load_key(tss_context_,"ek");
		TPM_HANDLE daa_handle=key_store_.load_key(tss_context_,"daa");

		Tpm_timer tt;
 
		ActivateCredential_In ac_in;
		ActivateCredential_Out ac_out;
		ac_in.activateHandle = daa_handle; 
		ac_in.keyHandle = ek_handle;

		ac_in.credentialBlob.t.size = credential_blob.size();
		for (int i = 0; i < credential_blob.size(); ++i)
			ac_in.credentialBlob.t.credential[i] = credential_blob[i];

		ac_in.secret.t.size = secret.size();
		for (int i = 0; i < secret.size(); ++i)
			ac_in.secret.t.secret[i] = secret[i];

		rc = TSS_Execute(tss_context_,
						(RESPONSE_PARAMETERS *)&ac_out,
						(COMMAND_PARAMETERS *)&ac_in,
						NULL,
						TPM_CC_ActivateCredential,
						TPM_RS_PW, NULL, 0, // Authorisation for 'certified' key
						TPM_RS_PW, NULL, 0, // Authorisation for EK
						TPM_RH_NULL, NULL, 0);
		if (rc != 0)
		{
			log_ptr->os() << "Tpm_daa: activate credential failed: " << get_tpm_error(rc) << std::endl;
			throw(Tpm_error("Tpm_daa: activating the credential failed"));
		}

		tpm_timings.add("TPM2_Activate_Credential",tt.get_duration());

		c_key=Byte_buffer(ac_out.certInfo.t.buffer, ac_out.certInfo.t.size);

	}
	catch (Tpm_error &e)
	{
		rc=1;
		last_error_=std::string(e.what());
	}
	catch (...)
	{
		rc=2;
		last_error_="Failed - uncaught exception";
	}

	if (log_ptr->debug_level()>0)
	{
		log_ptr->os() << "Tpm_daa: activate_credential: returned: " << c_key.to_hex_string() << std::endl;
	}
	return rc;
}

bool Tpm_daa::uses_new_daa_signature() const
{
	bool new_signature=true;

    if (revision_data_[0] <116 || (revision_data_[0]==116 && revision_data_[1]<265))
        new_signature=false;

    return new_signature;
}

TPM_RC Tpm_daa::create_and_load_pseudonym_key(int& id, Byte_buffer& qps_pd)
{
	TPM_RC rc=0;

	if (log_ptr->debug_level()>0)
	{
		log_ptr->write_to_log("Tpm_daa: create_and_load_pseudonym_key\n");
	}
	
	try
	{
		Tpm_key key=create_new_pseudonym_key();
		id=next_id_++;

		Byte_buffer pd=key.public_data_bb();
		if (pd.size()==0)
		{
			log_ptr->write_to_log("Tpm_daa: get_new_pseudonym_key: marshalling public data failed\n");
			throw(Tpm_error("Marshalling pseudonym key public data failed"));
		}
        qps_pd=std::move(pd);

        if (log_ptr->debug_level()>0)
        {
            log_ptr->os() << "Tpm_daa: get_new_pseudonym_key: returned:\nid: " << id 
                        << "\npd:" << qps_pd.to_hex_string() << std::endl;
        }
        
		std::string key_name=ps_name(id);
        TPM_HANDLE psk_handle=key_store_.load_key(tss_context_,key_name);
        if (log_ptr->debug_level()>0)
        {
            log_ptr->os() << "psk handle: " << std::hex << psk_handle << std::endl;
        }
	}
	catch (Tpm_error &e)
	{
		rc=1;
		last_error_=std::string(e.what());
	}
	catch (...)
	{
		rc=2;
		last_error_="Failed - uncaught exception";
	}

	return rc;
}

TPM_RC Tpm_daa::get_daa_key_data(Key_data& daa_data)
{
    TPM_RC rc=0;
	try
	{
        daa_data=key_store_.key_data_bb("daa");
	}
	catch (Tpm_error &e)
	{
		rc=1;
		last_error_=std::string(e.what());
	}
	catch (...)
	{
		rc=2;
		last_error_="Failed - uncaught exception";
	}

	return rc;    
}

TPM_RC Tpm_daa::get_pseudonym_key_data(int id, Key_data& qps_data)
{
	TPM_RC rc=0;

	if (log_ptr->debug_level()>0)
	{
		log_ptr->write_to_log("Tpm_daa: get_pseudonym_key_data\n");
	}
	
	try
	{
		std::string key_name=ps_name(id);
        qps_data=key_store_.key_data_bb(key_name);
	}
	catch (Tpm_error &e)
	{
		rc=1;
		last_error_=std::string(e.what());
	}
	catch (...)
	{
		rc=2;
		last_error_="Failed - uncaught exception";
	}

	return rc;    
}


TPM_RC Tpm_daa::initiate_daa_signature(Byte_buffer const& s2, Byte_buffer const& y2,
		G1_point const& pt_s, Commit_data& cd)
{
	TPM_RC rc=0;
	
	if (log_ptr->debug_level()>0)
	{
		log_ptr->write_to_log("Tpm_daa: initiate_daa_signature\n");
	}

	try
	{
        G1_point map_pt;
        if (s2.size()!=0)
        {
            if (y2.size()!=0)
            {
                map_pt=std::make_pair(s2,y2);
            }
            else
            {
                log_ptr->write_to_log("Inconsistent data for TPM2_Commit\n");
                throw(Tpm_error("Inconsistent data for TPM2_Commit"));
            }
        }
		
		TPM_HANDLE daa_handle=key_store_.load_key(tss_context_,"daa");

        cd=tpm2_commit(tss_context_,daa_handle,pt_s,map_pt);
	}
	catch (Tpm_error &e)
	{
		rc=1;
		last_error_=std::string(e.what());
	}
	catch (...)
	{
		rc=2;
		last_error_="Failed - uncaught exception";
	}

	if (log_ptr->debug_level()>0)
	{
        Commit_points const& pts=cd.second;
		log_ptr->os() << "Tpm_daa: initiate_daa_signature: returned: \nK_x: " << pts[0].first.to_hex_string()
					  << "\nK_y: " << pts[0].second.to_hex_string() << "\nL_x: " << pts[1].first.to_hex_string() 
					  << "\nL_y: " << pts[1].second.to_hex_string() << "\nE_x: " << pts[2].first.to_hex_string() 
					  << "\nE_y: " << pts[2].second.to_hex_string() << std::endl;
	}
	return rc;
}

TPM_RC Tpm_daa::complete_daa_signature(uint16_t counter, Byte_buffer const& p,
									   Byte_buffer& k, Byte_buffer& w)
{
	TPM_RC rc=0;
	if (log_ptr->debug_level()>0)
	{
		log_ptr->write_to_log("Tpm_daa: complete_daa_signature\n");
	}
	try
	{
		TPM_HANDLE daa_key_handle=key_store_.load_key(tss_context_,"daa");
		Cdj cds_result=complete_daa_sign(tss_context_,daa_key_handle,counter,p);

		k=cds_result.first;
		w=cds_result.second;
	}
	catch (Tpm_error &e)
	{
		rc=1;
		last_error_=std::string(e.what());
	}
	catch (...)
	{
		rc=2;
		last_error_="Failed - uncaught exception";
	}
	if (log_ptr->debug_level()>0)
	{
		log_ptr->os() << "Tpm_daa: complete_daa_signature: returned:\n"
                      << "k: " << k.to_hex_string() << '\n'
		              << "w: " << w.to_hex_string() << std::endl;
	}
	return rc;
}

TPM_RC Tpm_daa::certify_and_sign(int id, uint16_t counter, Byte_buffer const& c, Byte_buffer& a_cert,
                Byte_buffer& nt, Byte_buffer& s)
{
	TPM_RC rc=0;

	if (log_ptr->debug_level()>0)
	{
		log_ptr->write_to_log("Tpm_daa: certify_and_sign\n");
	}
	try
	{
		std::string key_name=ps_name(id);
		TPM_HANDLE daa_handle=key_store_.load_key(tss_context_,"daa");
		TPM_HANDLE psk_handle=key_store_.load_key(tss_context_,key_name);

        Certify_data cert=complete_daa_certify(tss_context_,daa_handle,psk_handle,counter,c);
		a_cert=cert[0];
		nt=cert[1];
		s=cert[2];
	}
	catch (Tpm_error &e)
	{
		rc=1;
		last_error_=std::string(e.what());
	}
	catch (...)
	{
		rc=2;
		last_error_="Failed - uncaught exception";
	}

	if (log_ptr->debug_level()>0)
	{
		log_ptr->os() << "Tpm_daa: certify_and_sign: returned:\ncert: " << a_cert.to_hex_string()
					  << "\nn_t: " << nt.to_hex_string() << "\ns: " << s.to_hex_string() << std::endl;
	}
	return rc;
}

TPM_RC Tpm_daa::quote_and_sign(TPML_PCR_SELECTION const& pcr_sel, uint16_t counter, Byte_buffer const& c, Byte_buffer& a_pcr,
                Byte_buffer& nt, Byte_buffer& s)
{
	TPM_RC rc=0;

	if (log_ptr->debug_level()>0)
	{
		log_ptr->write_to_log("Tpm_daa: quote_and_sign\n");
	}
	try
	{
		TPM_HANDLE daa_handle=key_store_.load_key(tss_context_,"daa");

        auto pcr_quote=complete_daa_quote(tss_context_,daa_handle,pcr_sel,counter,c);
		a_pcr=pcr_quote[0];
		nt=pcr_quote[1];
		s=pcr_quote[2];
	}
	catch (Tpm_error &e)
	{
		rc=1;
		last_error_=std::string(e.what());
	}
	catch (...)
	{
		rc=2;
		last_error_="Failed - uncaught exception";
	}

	if (log_ptr->debug_level()>0)
	{
		log_ptr->os() << "Tpm_daa: certify_and_quote: returned:\npcr_quote: " << a_pcr.to_hex_string()
					  << "\nn_t: " << nt.to_hex_string() << "\ns: " << s.to_hex_string() << std::endl;
	}
	return rc;
}

std::string Tpm_daa::get_last_error()
{
	// Move the contents of last_error also clears the value
	std::string error(std::move(last_error_));

	return error;
}

Tpm_daa::~Tpm_daa()
{
	if (tss_context_)
	{
		if (!key_store_.flush_all_transient_keys(tss_context_))
        {
            log_ptr->write_to_log("Warning: not all transient keys removed from the TPM\n");
        }
		TSS_Delete(tss_context_);
	}
}

std::string Tpm_daa::ps_name(uint32_t id)
{
	std::ostringstream os;
	os << std::hex << id;
							
	return "ps"+os.str();
}

Tpm_key Tpm_daa::create_new_pseudonym_key()
{

	if (log_ptr->debug_level()>0)
	{
		log_ptr->write_to_log("Tpm_daa: create_new_pseudonym_key\n");
	}
	std::string key_name=ps_name(next_id_);

	if (key_store_.key_already_in_store(key_name))
	{
		log_ptr->write_to_log("Tpm_daa: create_new_pseudonym_key: key already in the store\n");
		throw(Tpm_error("Tpm_daa: create_new_pseudonym_key: key already in the store"));
	}

	TPM_HANDLE parent_handle=key_store_.load_key(tss_context_,"ek");
	if (parent_handle==0)
	{
		log_ptr->write_to_log("Tpm_daa: create_new_pseudonym_key: unable to load the endorsement key\n");
		throw(Tpm_error("Tpm_daa: create_new_pseudonym_key: unable to load the endorsement key"));
	}

    key_store_.prepare_for_new_key(tss_context_,"ek");

	Create_Out out;
	TPM_RC rc=create_ecdsa_key(tss_context_,parent_handle,TPM_ECC_NIST_P256,&out);	
	if (rc != 0)
	{
		log_ptr->os() << "Tpm_daa: create_new_pseudonym_key: unable to create the key: " << get_tpm_error(rc) << std::endl;
		throw(Tpm_error("Tpm_daa: create_new_pseudonym_key: unable to create an ECDSA key"));
	}

	Tpm_key key(key_name,"ek",out.outPublic,out.outPrivate);

	key_store_.add_key(key);

	return key;
}

/*
TPM_RC Tpm_daa::powerup(Tss_setup const& tps)
{
	TPM_RC rc=0;

	if (log_ptr->debug_level()>0)
	{
		log_ptr->write_to_log("Tpm_daa: powerup\n");
	}

    TSS_CONTEXT* tmp_context=nullptr;   // powerup seems to leave the TSS_CONTEXT in a funny state,
                                        // so use a temporary one and then delete it.
    
    auto nc=set_new_context(tps);
    rc=nc.first;
    if (rc==0)
    {
        tmp_context=nc.second;
        rc=TSS_TransmitPlatform(tmp_context,TPM_SIGNAL_POWER_OFF,"TPM2_PowerOffPlatform");
    }
    if (rc==0)
    {
        rc=TSS_TransmitPlatform(tmp_context,TPM_SIGNAL_POWER_ON,"TPM2_PowerOnPlatform");
    }
    if (rc==0)
    {
        rc=TSS_TransmitPlatform(tmp_context,TPM_SIGNAL_NV_ON,"TPM2_NvOnPlatform");
    }
    
    TPM_RC rc1=TSS_Delete(tmp_context);
    if (rc==0)
    {
        rc=rc1;
    }

	return rc;
}

TPM_RC Tpm_daa::startup()
{
	TPM_RC rc=0;
	if (log_ptr->debug_level()>0)
	{
		log_ptr->write_to_log("Tpm_daa: startup\n");
	}

	Tpm_timer tt;

	Startup_In in;
	in.startupType = TPM_SU_CLEAR;
	rc = TSS_Execute(tss_context_,
			NULL, 
			(COMMAND_PARAMETERS *)&in,
			NULL,
			TPM_CC_Startup,
			TPM_RH_NULL, NULL, 0);

	tpm_timings.add("TPM2_startup",tt.get_duration());

	return rc;
}

TPM_RC Tpm_daa::shutdown()
{
	TPM_RC rc=0;
	if (log_ptr->debug_level()>0)
	{
		log_ptr->write_to_log("Tpm_daa: shutdown\n");
	}

	Tpm_timer tt;

	Shutdown_In in;
	in.shutdownType = TPM_SU_CLEAR;
	rc = TSS_Execute(tss_context_,
			NULL, 
			(COMMAND_PARAMETERS *)&in,
			NULL,
			TPM_CC_Shutdown,
			TPM_RH_NULL, NULL, 0);

	tpm_timings.add("TPM2_Shutdown", tt.get_duration());
	
	return rc;
}
*/
void Tpm_daa::get_tpm_revision_data()
{
    TPM_RC rc;

	if (log_ptr->debug_level()>0)
	{
		log_ptr->write_to_log("Tpm_daa: get_tpm_revision_data\n");
	}

    size_t revision_size=3;

	Tpm_timer tt;

	GetCapability_In in;
	GetCapability_Out out;         
	in.capability=TPM_CAP_TPM_PROPERTIES;
	in.property=TPM_PT_REVISION;
	in.propertyCount=revision_size;
	rc=TSS_Execute(tss_context_,
		(RESPONSE_PARAMETERS*)&out,
		(COMMAND_PARAMETERS*)&in,
		NULL,
		TPM_CC_GetCapability,
		TPM_RH_NULL,NULL,0
	);
	if (rc!=0)
	{
		log_ptr->os() << "Tpm_daa: get_tpm_revision_data: " << get_tpm_error(rc) << std::endl;
		throw(Tpm_error("GetCapability (TPM_PT_REVISION) failed"));        
	}
	tpm_timings.add("TPM2_GetCapability (TPM_PT_REVISION)", tt.get_duration());
	
    for (int i=0;i<revision_size;++i)
    {
	    revision_data_[i]=out.capabilityData.data.tpmProperties.tpmProperty[i].value;
    }
}

