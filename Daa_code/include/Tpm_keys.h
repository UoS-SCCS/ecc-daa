/*******************************************************************************
* File:        Tpm_keys.h
* Description: Code for handling the TPM keys in the VANET project
*
* Author:      Chris Newton
*
* Created:     Wednesday 4 July 2018
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

#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include "Tss_includes.h"
#include "Byte_buffer.h"
#include "Marshal_public_data.h"
#include "Clock_utils.h"
#include "Logging.h"
#include "Tpm_defs.h"

using Key_data=std::pair<Byte_buffer,Byte_buffer>;

Byte_buffer serialise_key_data(Key_data const& kd);
Key_data deserialise_key_data(Byte_buffer const& bb);

const uint32_t default_free_handles=3;
const uint32_t default_persistent_handles=6;

const TPM_HANDLE no_handle=0;

/**
 * The Tpm_key class stores infomation about the TPM keys that have
 * been created. The TPM has limited storage for keys and so they need
 * to be swapped in and out as required.
 * 
 * Keys can be made peresitent and stored in non-volatile memory, but
 * to use them there must still be a free slot in the TPM's RAM.
 * 
 * Key names must be unique.
 */
class Tpm_key
{
public:
	Tpm_key()=delete;
	/**
	 * Constructor for a primary key, these are automatically loaded and only the
	 * public data made available outside the TPM.
	 */
	Tpm_key(std::string const& v_name,TPM2B_PUBLIC const& public_data,TPM_HANDLE handle);
	/**
	 * Constructor for non-primary keys. These are not loaded automatically.
	 */
	Tpm_key(std::string const& v_name, std::string const& parent_name,
		    TPM2B_PUBLIC const& public_data,
	        TPM2B_PRIVATE const& private_data);
	/**
	 * Returns the name of the key.
	 * 
	 * @return - the name of the key.
	 */
	std::string v_name() const {return v_name_;}
	/**
	 * Returns the name of the key's parent.
	 * 
	 * @return - the name of the key's parent.
	 */
	std::string parent() const {return parent_v_name_;}
	/**
	 * Returns the TPM2B_PUBLIC data for the given key.
	 * 
	 * @return - a const reference to the key's public data.
	 */	
	TPM2B_PUBLIC const& public_data() const {return public_data_;}
	/**
	 * Returns the TPM2B_PRIVATE data for the given key.
	 * 
	 * @return - a const reference to the key's private data.
	 */
	TPM2B_PRIVATE const& private_data() const {return private_data_;}
	/**
	 * Returns the TPM2B_PUBLIC data for the given key in a Byte_buffer.
	 * 
	 * @return - the key's public data.
	 */	
	Byte_buffer public_data_bb() const;
	/**
	 * Returns the TPM2B_PRIVATE data for the given key in a Byte_buffer.
	 * 
	 * @return - the key's private data.
	 */	
	Byte_buffer private_data_bb() const;
	/**
	 * Returns the key's data (private and public) in two Byte_buffers.
	 * 
	 * @return - the key's data.
	 */	
    Key_data key_data_bb() const {return std::make_pair(private_data_bb(),public_data_bb());}

    bool primary_;
	bool loaded;
	bool persistent;
	TPM_HANDLE handle;
	
private:
	std::string v_name_;
	std::string parent_v_name_;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
	TPM2B_PUBLIC public_data_;
	TPM2B_PRIVATE private_data_;
#pragma GCC diagnostic pop
};

/**
 * The Vanet_key mamanger class implements the very simple (flat) key hierarchy used
 * in the VANET project, ek-->daa_key and ek-->pseudonym_key(s).
 * 
 * All child keys must have a parent and parent key's must be loaded into the TPM
 * before any child key can be created.
 * 
 * The primary key, ek, must be put into the store first.
 * 
 * Key names must be unique.
 */
class Vanet_key_manager
{
public:
	using Vanet_key_store=std::vector<Tpm_key>;
	using Vanet_key_iterator=Vanet_key_store::iterator;
	using Vanet_key_const_iterator=Vanet_key_store::const_iterator;
	/**
	 * Default constructor, used when constructed as part of the Tpm_daa class. the
	 * default value for key_handles_avail_ is updated once it is read from the TPM.
	 */
	Vanet_key_manager() : key_handles_avail_(default_free_handles) {}
	/**
	 * Update key_handles_avail_ once it is read from the TPM.
	 * 
	 * @param[in] free_kh - the number of free key handles available.
	 */	
	void update_parameters(uint32_t free_kh){key_handles_avail_=free_kh;}
	/**
	 * Add a key to the key store.
	 * 
	 * @param[in] key- the key to be added.
	 */
	void add_key(Tpm_key const& key);
	/**
	 * Checks whether a key with the same name is already in the store.
	 * 
	 * @return - true if the key is found, false otherwise.
	 */
	bool key_already_in_store(std::string const& key_name) const;
	/**
	 * Returns the TPM2B_PUBLIC data for the given key.
	 * 
	 * @param key_name - the name of the key whose data is required.
	 * @return - a const reference to the key's public data.
	 */
	TPM2B_PUBLIC const& public_data(std::string const& key_name) const;
	/**
	 * Returns the TPM2B_PRIVATE data for the given key.
	 * 
	 * @param key_name - the name of the key whose data is required.
	 * @return - a const reference to the key's private data.
	 */
	TPM2B_PRIVATE const& private_data(std::string const& key_name) const;
	/**
	 * Returns the TPM2B_PUBLIC data for the given key in a Byte_buffer.
	 * 
	 * @param key_name - the name of the key whose data is required.
	 * @return - the key's public data.
	 */	
	Byte_buffer public_data_bb(std::string const& key_name) const;
	/**
	 * Returns the TPM2B_PRIVATE data for the given key in a Byte_buffer.
	 * 
	 * @param key_name - the name of the key whose data is required.
	 * @return - the key's private data.
	 */	
	Byte_buffer private_data_bb(std::string const& key_name) const;
	/**
	 * Returns the data for the given key in a pair of Byte_buffers.
	 * 
	 * @param key_name - the name of the key whose data is required.
	 * @return - the key's data.
	 */	
    Key_data key_data_bb(std::string const& key_name) const;
	/**
	 * Loads the given key into the TPM ready for use.
	 * 
	 * Assumes that the key with the given name is already in the key store.
	 * If already loaded, just returns the handle, otherwise loads the key,
	 * updates the key store and returns the key handle. Called recursively,
	 * if necessary, other keys may be unloaded to make space. Keeps the EK
	 * loaded and if the EK is made persisent it keeps a slot available for
	 * its use.
	 * 
	 * @param[in] key_name - the name of the key to be loaded.
	 * @return - the handle for the key.
	 */
	TPM_HANDLE load_key(TSS_CONTEXT* context, std::string const& key_name);
	/**
	 * Prepares for a new key to be created, there must be slot available. Assumes
	 * that the parent key is already loaded.
	 * 
	 * @param[in] parent_name - the name of the parent key.
	 * @throw - throws if the parent key is not loaded or if a space cannot be created.
	 */
    void prepare_for_new_key(TSS_CONTEXT* context, std::string const& parent_name);
	/**
	 * Flushes all transient keys from the TPM
	 * 
	 * @return - true if successful, false otherwise.
	 */
	bool flush_all_transient_keys(TSS_CONTEXT* context);
	/**
	 * Deletes the given transient key after, if necessary, flushing it from the TPM.
	 * 
	 * @return TPM_RC - this will be zero for a successful call.
	 */
    TPM_RC delete_transient_key(TSS_CONTEXT*, std::string const& key_name);
	/**
	 * Deletes all of the transient keys in preparation for a restart.
	 * 
	 */	
	void delete_all_transient_keys(TSS_CONTEXT* context);
	/**
	 * Writes information about key usage to the log stream.
	 * 
	 */
    void report() const;
	~Vanet_key_manager(){}

private:
	uint32_t key_handles_avail_;
	Vanet_key_store keys_;
	Vanet_key_iterator get_key(std::string v_name);
	Vanet_key_const_iterator get_key(std::string v_name) const;
};
