/******************************************************************************
* File:        Tpm_keys.cpp
* Description: Code for handling the TPM keys in the VANET project
*
* Author:      Chris Newton
*
* Created:     Wednesday 4 July 2018
*
* (C) Copyright 2018, University of Surrey.
*
******************************************************************************/
#include <iostream>
#include <chrono>
#include "Tpm_error.h"
#include "Flush_context.h"
#include "Tpm_keys.h"

Byte_buffer serialise_key_data(Key_data const& kd)
{
    std::vector<Byte_buffer> tmp_bb(2);
    tmp_bb[0]=kd.first;
    tmp_bb[1]=kd.second;

    return serialise_byte_buffers(tmp_bb);
}

Key_data deserialise_key_data(Byte_buffer const& bb)
{
    std::vector<Byte_buffer> tmp_bb=deserialise_byte_buffers(bb);
    return std::make_pair(tmp_bb[0],tmp_bb[1]);
}

// Constructor for a top level (primary) key
Tpm_key::Tpm_key(std::string const& v_name,TPM2B_PUBLIC const& public_data,TPM_HANDLE handle) :
                 primary_(true),loaded(true), persistent(false), handle(handle), v_name_(v_name),
                 public_data_(public_data) {}

// Constructor for keys at other levels
Tpm_key::Tpm_key(std::string const& v_name, std::string const& parent_name,
		        TPM2B_PUBLIC const& public_data,
	            TPM2B_PRIVATE const& private_data) : primary_(false), loaded(false), persistent(false),
                handle(no_handle), v_name_(v_name), parent_v_name_(parent_name),
                public_data_(public_data), private_data_(private_data){}

Byte_buffer Tpm_key::public_data_bb() const
{
    TPM2B_PUBLIC pa=public_data_;
    return marshal_public_data_B(&pa);
}

Byte_buffer Tpm_key::private_data_bb() const
{
    if (primary_)
        return Byte_buffer();
    TPM2B_PRIVATE pa=private_data_;
    return marshal_private_data_B(&pa);
}

void Vanet_key_manager::prepare_for_new_key(TSS_CONTEXT* context, std::string const& parent_name)
{
    auto pos=get_key(parent_name);
    if (pos==keys_.cend())
    {
        throw(Tpm_error("Parent key not in the store"));
    }
    if (!pos->loaded)
    {
        throw(Tpm_error("prepare_for_new_key: parent not loaded"));
    }
    
    if (key_handles_avail_==0)
    {
        if (log_ptr->debug_level()>0)
        {
            log_ptr->os() << "prepare_for_new_key: making space\n";
        }
        Vanet_key_iterator pos_n;
        for (pos_n=keys_.begin();pos_n!=keys_.cend();++pos_n)
        {
            if (pos_n->v_name()==parent_name || !(pos_n->loaded))
                continue;
            TPM_RC rc_n=flush_context(context, pos_n->handle);
            if (rc_n!=0)
            {
                throw(Tpm_error("prepare_for_new_key: unable to flush a key to make space"));
            }
            pos_n->loaded=false;
            pos_n->handle=no_handle;
            ++key_handles_avail_;
        }
    }

    return;
}

void Vanet_key_manager::add_key(Tpm_key const& key)
{
    // EK should be added first
    if (key.v_name()=="ek" && keys_.size()!=0)
    {
        throw(Tpm_error("The endorsement key must be added first"));
    }
    
    if (key.v_name()!="ek" && key.loaded)
    {
        throw(Tpm_error("Add non-endorsement keys to the store before loading them"));
    }

    auto pos=get_key(key.v_name());
    if (pos==keys_.cend())
    {
        keys_.push_back(key);
//        std::cout << "Key: " << key.v_name() << " added to the store\n";
        if (key.v_name()=="ek")
        {
            // Adjust to leave a slot for the EK to use 
            --key_handles_avail_;   
        }
    }
    else
    {
        throw(Tpm_error("The key being added already in the store"));
    }
}

TPM2B_PUBLIC const& Vanet_key_manager::public_data(std::string const& key_name) const
{
    auto pos=get_key(key_name);
    if (pos==keys_.cend())
    {
        throw(Tpm_error("public_data: requested a key not in key store"));
    }
   
    return pos->public_data();    
} 

TPM2B_PRIVATE const& Vanet_key_manager::private_data(std::string const& key_name) const
{
    auto pos=get_key(key_name);
    if (pos==keys_.cend())
    {
        throw(Tpm_error("private_data: requested a key not in key store"));
    }
   
    return pos->private_data();    
} 

Byte_buffer Vanet_key_manager::public_data_bb(std::string const& key_name) const
{
    auto pos=get_key(key_name);
    if (pos==keys_.cend())
    {
        throw(Tpm_error("public_data_bb: requested a key not in key store"));
    }
   
    return pos->public_data_bb();
}

Byte_buffer Vanet_key_manager::private_data_bb(std::string const& key_name) const
{
    auto pos=get_key(key_name);
    if (pos==keys_.cend())
    {
        throw(Tpm_error("private_data_bb: requested a key not in key store"));
    }
   
    return pos->private_data_bb();
}

Key_data Vanet_key_manager::key_data_bb(std::string const& key_name) const
{
    auto pos=get_key(key_name);
    if (pos==keys_.cend())
    {
        throw(Tpm_error("key_data_bb: requested a key not in key store"));
    }
   
    return pos->key_data_bb();
}

TPM_HANDLE Vanet_key_manager::load_key(
TSS_CONTEXT* context,
std::string const& key_name
)
{
    if (log_ptr->debug_level()>1)
    {
        log_ptr->os() << "key slots available: " << key_handles_avail_ << " Loading key: " << key_name << std::endl;
    }
    auto pos=get_key(key_name);
    if (pos==keys_.cend())
    {
        log_ptr->os() << "load key: the key requested is not in the store" << std::endl;
        throw(Tpm_error("load_key: requested a key not in key store"));
    }

    if (pos->loaded)
    {
        if (log_ptr->debug_level()>1)
        {
            log_ptr->os() << "key " << key_name << " already loaded"  << std::endl;
        }        
        return pos->handle;
    }

    auto pos_p=get_key(pos->parent());
    if (pos_p==keys_.cend())
    {
        log_ptr->os() << "Corrupted key store - a key with no parent" << std::endl;
        throw(Tpm_error("Corrupted key store - key with no parent"));
    }

    if (!pos_p->loaded)
    {
//        std::cout << "Loading parent " << pos_p->v_name() << '\n';
        load_key(context, pos_p->v_name());
    }

    if (key_handles_avail_==0)
    {
        Vanet_key_iterator pos_n;
        for (pos_n=keys_.begin();pos_n!=keys_.cend();++pos_n)
        {
//            std::cout << "Key: " << pos_n->v_name() << " being tested\n";
            if (pos_n->v_name()==key_name || pos_n->v_name()=="ek" || !(pos_n->loaded))
                continue;
            TPM_RC rc_n=flush_context(context, pos_n->handle);
            if (rc_n!=0)
            {
                log_ptr->os() << "Load key: unable to flush a key to make space" << std::endl;
                throw(Tpm_error("load_key: unable to flush a key to make space"));
            }
            pos_n->loaded=false;
            pos_n->handle=no_handle;
            ++key_handles_avail_;
//            std::cout << "Key: " << pos_n->v_name() << " unloaded\n";
        }
    }

	Tpm_timer tt;

    Load_In load_in;
    Load_Out load_out;

    load_in.parentHandle=pos_p->handle;
    load_in.inPrivate=pos->private_data();
    load_in.inPublic=pos->public_data();

    TPM_RC rc = TSS_Execute(context,
			(RESPONSE_PARAMETERS *)&load_out,
			(COMMAND_PARAMETERS *)&load_in,
			NULL,
			TPM_CC_Load,
			TPM_RS_PW, NULL, 0,
			TPM_RH_NULL, NULL, 0);

    if (rc != 0)
    {
        log_ptr->os() << "Vanet_ket_manager: load key: " << get_tpm_error(rc) << std::endl;
        throw(Tpm_error("Vanet_key_manager: unable to load key"));
    }
    tpm_timings.add("TPM2_Load",tt.get_duration());

    pos->handle=load_out.objectHandle;
    pos->loaded=true;
    --key_handles_avail_;
    
    return pos->handle;
}

Vanet_key_manager::Vanet_key_iterator Vanet_key_manager::get_key(std::string const& v_name)
{
    Vanet_key_iterator pos;
    for (pos=keys_.begin();pos!=keys_.cend();++pos)
    {
        if (pos->v_name()==v_name)
            break;
    }
    return pos;
}

Vanet_key_manager::Vanet_key_const_iterator Vanet_key_manager::get_key(std::string const& v_name) const
{
    Vanet_key_const_iterator pos;
    for (pos=keys_.begin();pos!=keys_.cend();++pos)
    {
        if (pos->v_name()==v_name)
            break;
    }
    return pos;
}

bool Vanet_key_manager::flush_all_transient_keys(TSS_CONTEXT* context)
{
    if (log_ptr->debug_level()>1)
    {
        log_ptr->os() << "flush_all_transient_keys: key slots available: " << key_handles_avail_ << std::endl;
    }    
    TPM_RC rc;
    bool all_keys_flushed=true;

    for (Tpm_key key : keys_)
    {
        if (key.loaded && !key.persistent)
		{
			rc=flush_context(context,key.handle);
			if (rc==0)
			{
                key.handle=no_handle;
                key.loaded=false;
				++key_handles_avail_;
			}
			else
			{
				log_ptr->os() << "Failed to flush the key: " << key.v_name() << std::endl;
                all_keys_flushed=false;
			}
		}	
    }

    if (log_ptr->debug_level()>1)
    {
        log_ptr->os() << "flush_all_transient_keys (done): key slots available: " << key_handles_avail_ << std::endl;
    }    

    return all_keys_flushed;
}

TPM_RC Vanet_key_manager::delete_transient_key(TSS_CONTEXT* context, std::string const& key_name)
{
    TPM_RC rc=0;
    auto pos=get_key(key_name);
    if (pos==keys_.cend())
    {
        log_ptr->os() << "delete_transient_key: " << key_name << " not in the store" << std::endl;
        throw(Tpm_error("delete_transient_key: key not in the store\n"));
    }
    if (pos->persistent)
    {
        log_ptr->os() << "delete_transient_key: " << key_name << " is apersistent key" << std::endl;
        throw(Tpm_error("delete_transient_key: the key is a persistent key\n"));
    }

    if (pos->loaded)
    {
        log_ptr->os() << "delete_transient_key: flushing the key: " << key_name << std::endl;
        rc=flush_context(context,pos->handle);
        if (rc==0)
        {
            pos->handle=no_handle;
            pos->loaded=false;
            ++key_handles_avail_;
        }
        else
        {
            log_ptr->os() << "delete_transient_key: failed to flush the key: " << key_name << std::endl;
            throw(Tpm_error("delete_transient_key: unable to flush the key\n"));
        }
    }

    keys_.erase(pos);
    if (log_ptr->debug_level()>0)
    {
        log_ptr->os() << "delete_transient_key: " << key_name << " deleted\n" << std::flush;
    }
    
    return rc;
}

void Vanet_key_manager::delete_all_transient_keys(TSS_CONTEXT* context)
{
    flush_all_transient_keys(context);
    auto key = keys_.begin();
    while (key != keys_.end())
    {
        if (!key->persistent)
            key = keys_.erase(key);
        else
            ++key;
    }
}

bool Vanet_key_manager::key_already_in_store(std::string const& key_name) const
{
    Vanet_key_const_iterator pos=get_key(key_name);
    
    return (pos!=keys_.cend());
}

void Vanet_key_manager::report() const
{
    int p_keys=0;
    int t_keys=0;
    int l_keys=0;

    for (Tpm_key key : keys_)
    {
        p_keys+=key.persistent;
        t_keys+=!key.persistent;
        l_keys+=key.loaded;
    }

    if (log_ptr->debug_level()>0)
    {
        log_ptr->os() << "Key store reports: total: " << keys_.size() << " persistent: " << p_keys
                      << " transient: " << t_keys << " loaded: " << l_keys << std::endl;
    }
}
