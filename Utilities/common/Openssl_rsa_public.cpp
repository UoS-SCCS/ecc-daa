/*******************************************************************************
* File:        Openssl_rsa_encrypt.cpp
* Description: RSA encryption using public key and a label (for TPM test)
*
* Author:      Chris Newton
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
#include <openssl/rand.h>
#include <openssl/evp.h>
#include "Openssl_utils.h"
#include "Openssl_rsa_public.h"

Byte_buffer encrypt_rsa2048(
Byte_buffer const& label,
Byte_buffer const& in,
Byte_buffer const& modulus_bb,
Byte_buffer const& exponent_bb
)
{
//    std::cout << "\nPublic modulus:\n" << modulus_bb.to_hex_string() << '\n';
    BIGNUM *n = BN_new();
    bin2bn(&modulus_bb[0],modulus_bb.size(),n);
//    BN_print_fp(stdout, n);
//    std::cout << '\n';

//    std::cout << "Public exponent:\n" << exponent_bb.to_hex_string() << '\n';
    BIGNUM *e = BN_new();
    bin2bn(&exponent_bb[0],exponent_bb.size(),e);
//    BN_print_fp(stdout, e);
//    std::cout << '\n';

    RSA* rsa_key=RSA_new();
    if (rsa_key != NULL)
    {
        RSA_set0_key(rsa_key,n,e,NULL);
    }    
   
    size_t outlen=RSA_size(rsa_key);
    Byte_buffer padded_data(outlen,0);   
    Byte_buffer cipher_text(outlen,0);
    
    // Initialise random seed for padding operations
    Byte_buffer seed{0x42};
    RAND_seed(&seed[0],1);

    // Manually do the padding to select the hash functions, SHA256 is used for both OAEP and MGF1 
    if(RSA_padding_add_PKCS1_OAEP_mgf1(&padded_data[0],outlen,&in[0],in.size(),&label[0],label.size(),EVP_sha256(),EVP_sha256())<=0)
    {
        std::cout << "Padding failed\n";
        handle_openssl_error();
        exit(EXIT_FAILURE);
    }

//    std::cout << "Padded data: " << padded_data.to_hex_string() << '\n';

    // Now do the encryption
    size_t ct_size = RSA_public_encrypt(padded_data.size(),&padded_data[0],&cipher_text[0],rsa_key,RSA_NO_PADDING);
    if (ct_size != outlen)
    {
        std::cout << "Error: length of ciphertext should match the length of key\n";
        exit(EXIT_FAILURE);
    }

    RSA_free(rsa_key); // BIGNUMs freed from here

    return cipher_text;
}


