/******************************************************************************
* File:        Tpm_daa.h
* Description: The TPM class for the 'vanilla' DAA protocol, based on the
*              VANET TPM class
*
* Author:      Chris Newton
*
* Created:     Friday 12 April 2019
*
* (C) Copyright 2019, University of Surrey, all rights reserved.
*
******************************************************************************/

#pragma once

#include <string>
#include <chrono>
#include <array>
#include <fstream>
#include "Tss_includes.h"
#include "Tss_setup.h"
#include "Tpm_keys.h"
#include "Openssl_ec_utils.h"
#include "Clock_utils.h"
#include "Logging.h"
#include "Byte_buffer.h"
#include "Tpm2_commit.h"
#include "Tpm_defs.h"

/**
 * The Tpm_daa class, implements the calls needed for the VANET DAA protocol. Details of the protocol are given separately.
 *
 */
class Tpm_daa
{
public:
    using Tpm_revision_data=std::array<uint32_t,3>;
	/**
	 * Default constructor.
	 */
 	Tpm_daa() : available_(false), hw_tpm_(false),  next_id_(0), tss_context_(nullptr) {}
	Tpm_daa(Tpm_daa const& t)=delete;
	Tpm_daa& operator=(Tpm_daa const& t)=delete;
	bool is_available() const {return available_;}
	/**
	 * Initial setup of the Tpm_daa class. Only call this once.
	 *
	 * @param tps - the setup data, a Tss_setup object.
	 * @return TPM_RC - this will be zero for a successful call. If non-zero use get_last_error() to return the error.
	 */
    TPM_RC setup(Tss_setup const& tps);
	/**
	 * The second phase of setting up the Tpm_daa class. This can be called repeatedly to reset and start a new session.
	 *
	 * @param tps - the setup data, a Tss_setup object.
	 * @return TPM_RC - this will be zero for a successful call. If non-zero use get_last_error() to return the error.
	 */
    TPM_RC initialise(Tss_setup const& tps);
	/**
	 * Returns the revison data from the TPM identifying the TPM version that is being used.
	 *
	 * @return Tpm_revision_data, ...
	 */
	Tpm_revision_data tpm_revision_data() const {return revision_data_;}
	/**
	 *
	 * @return - true if the TPM uses the new signature definition, false otherwise.
	 */
	bool uses_new_daa_signature() const;
	/**
	 * Returns the endorsement key's public data.
	 *
	 * @param[out] ek_pd - the endorsement key's public data.
 	 * @return TPM_RC - this will be zero for a successful call. If non-zero use get_last_error() to return the error.
	 */
	TPM_RC get_endorsement_key_data(Byte_buffer& ek_pd);
	/**
	 * Creates and loads the DAA, returns the DAA key's public data.
	 *
	 * @param[out] daa_pd  - the DAA key's public data.
 	 * @return TPM_RC - this will be zero for a successful call. If non-zero use get_last_error() to return the error.
	 */
	TPM_RC create_and_load_daa_key(Byte_buffer& daa_pd);
    /**
	 * Installs and loads a key from Key_data, used when the key has been saved and retieved then for
     * futher operations. The key is loaded to ensure that it is a key from the TPM
	 *
     * @param[in] name - the key's name for the key store (not the TPM name calculated from the public data)
     * @param[in] parent - the name of the key's parent in the hierarchy
     * @param[in] kd - the Key data for the key (private and public parts as Byte_buffers)
 	 * @return TPM_RC - this will be zero for a successful call. If non-zero use get_last_error() to return the error.
	 */
    TPM_RC install_and_load_key(std::string const& name, std::string const& parent, Key_data& kd);
    /**
	 * Retrieves the key data for the DAA key.
	 *
	 * @param[out] daa_data - the DAA key's data (private and public).
 	 * @return TPM_RC - this will be zero for a successful call. If non-zero use get_last_error() to return the error.
	 */
	TPM_RC get_daa_key_data(Key_data& daa_data);
	/**
	 * Used to unwrap the credial blob and return the credential key.
	 *
	 * @param[in] cb - the credential blob.
	 * @param[in] secret - the encrypted seed, use to generate the keys needed to unwrap the credential blob.
	 * @param[out] c_key - the credential key.
 	 * @return TPM_RC - this will be zero for a successful call. If non-zero use get_last_error() to return the error.
	 */	
	TPM_RC activate_credential(Byte_buffer const& cb, Byte_buffer const& secret, Byte_buffer& c_key);
	/**
	 * Creates a new pseudonym key.
	 *
	 * @param[out] id - the new pseudonym key's ID number.
	 * @param[out] qps_pd - the new pseudonym key's public data.
 	 * @return TPM_RC - this will be zero for a successful call. If non-zero use get_last_error() to return the error.
	 */
	TPM_RC create_and_load_pseudonym_key(int& id, Byte_buffer& qps_pd);
    /**
	 * Retrieves the key data for a pseudonym key.
	 *
	 * @param[out] id - the pseudonym key's ID number.
	 * @param[out] qps_data - the pseudonym key's data (private and public).
 	 * @return TPM_RC - this will be zero for a successful call. If non-zero use get_last_error() to return the error.
	 */
	TPM_RC get_pseudonym_key_data(int id, Key_data& qps_data);
	/**
	 * Prepares for an ECDAA signature by running TPM2_Commit.
	 *
	 * @param[in] s2 - the TPM2_Commit parameter s2. 
	 * @param[in] y2 - the TPM2_Commit parameter y2.
	 * @param[in] pt_s - the TPM2_Commit parameter, S, an EC point.
	 * @param[out] counter - the counter returned from TPM2_Commit.
	 * @param[out] pt_k - the EC point K from TPM2_Commit
	 * @param[out] pt_ra - the EC point R_A from TPM2_Commit
	 * @param[out] pt__rb - the EC point R_B from TPM2_Commit
 	 * @return TPM_RC - this will be zero for a successful call. If non-zero use get_last_error() to return the error.
	 */
	TPM_RC initiate_daa_signature(Byte_buffer const& s2, Byte_buffer const& y2,
		                                        G1_point const& pt_s, Commit_data& cd);
	/**
	 * Completes the ECDAA signature, first calling TPM2_Hash to generate the digest to be signed using TPM2_sign.
	 * 
	 * @param[in] counter - the counter previously returned from TPM2_Commit.
	 * @param[in] p - the external digest to be hashed and signed.
	 * @param[out] k - the k value from ECDAA sign.
	 * @param[out] w - the w value from ECDAA sign.
 	 * @return TPM_RC - this will be zero for a successful call. If non-zero use get_last_error() to return the error.
	 */
	TPM_RC complete_daa_signature(uint16_t counter, Byte_buffer const& p, Byte_buffer& k, Byte_buffer& w);
	/**
	 * Certifies a pseudonym key and signs the result with an ECDAA signature.
	 * 
	 * @param[in] id - the ID of the pseudonym key being certified.
	 * @param[in] counter - the counter previously returned from TPM2_Commit.
	 * @param[in] c - the digest, c, to be hashed with the key certificate and signed.
	 * @param[out] a_cert - the pseudonym key's certificate.
	 * @param[out] nt - the n_t value from ECDAA sign.
	 * @param[out] s - the s value from ECDAA sign.
 	 * @return TPM_RC - this will be zero for a successful call. If non-zero use get_last_error() to return the error.
	 */
	TPM_RC certify_and_sign(int id, uint16_t counter, Byte_buffer const& c, Byte_buffer& a_cert,
           Byte_buffer& nt, Byte_buffer& s);
    /**
	 * Obtains the PCR quote result for a PCR selection and signs the result with an ECDAA signature.
	 * 
	 * @param[in] pcr_sel - the PCR sellection to be quoted.
	 * @param[in] counter - the counter previously returned from TPM2_Commit.
	 * @param[in] c - the digest, c, to be hashed with the PCD data and signed.
	 * @param[out] a_pcr - the PCR attestation data.
	 * @param[out] nt - the n_t value from ECDAA sign.
	 * @param[out] s - the s value from ECDAA sign.
 	 * @return TPM_RC - this will be zero for a successful call. If non-zero use get_last_error() to return the error.
	 */
	TPM_RC quote_and_sign(TPML_PCR_SELECTION const& pcr_sel, uint16_t counter, Byte_buffer const& c,
                            Byte_buffer& a_pcr, Byte_buffer& nt, Byte_buffer& s);
	/**
	 * Returns the TSS_CONTEXT pointer. Only used for testing, particularly with the TPM simulator..
	 *
	 * @return - a pointer to the current TSS_CONTEXT.
	 */
	TSS_CONTEXT* get_context() {return tss_context_;}
	/**
	 * Returns the last error reported, or the empty string. The last error is cleared ready for next time.
	 *
	 * @return - a string containing the last error that was reported.
	 */
	std::string get_last_error();
	/**
	 * The destructor - tidies up. In particular flushing all of the transient keys from the TPM and doing an orderly shutdown.
	 *
	 */
	~Tpm_daa();

private:
	bool available_;
    bool hw_tpm_;
	uint32_t next_id_;
    Tpm_revision_data revision_data_;
	
	
	TSS_CONTEXT* tss_context_;
	Vanet_key_manager key_store_;
	std::string last_error_;

//	TPM_RC powerup(Tss_setup const& tps);
//	TPM_RC startup();
//	TPM_RC shutdown();
	void get_tpm_revision_data();
//	void setup_primary_key();
//	bool persistent_ek_available();
//	std::vector<TPM_HANDLE> retrieve_persistent_handles(size_t ph_count);
//	void read_ek_public_data(TPM2B_PUBLIC& pd);
//	TPM_RC make_ek_persistent(TPM_HANDLE ek_handle);
	Tpm_key create_new_pseudonym_key();
	std::string ps_name(uint32_t id);
};
