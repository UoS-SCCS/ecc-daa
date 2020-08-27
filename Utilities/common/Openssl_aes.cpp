/*******************************************************************************
* File:        Openssl_aes.cpp
* Description: AES functions
*
* Author:      Chris Newton
* Created:     Wednesday 30 May 2018
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


#include "Openssl_utils.h"
#include "Openssl_aes.h"
#include "Get_random_bytes.h"

Byte_buffer initialise_random_iv(size_t size)
{
    unsigned int seed = 1+time(NULL);
    Byte_buffer rand_iv=get_random_bytes(size,seed);

    return rand_iv;
}

AES_KEY get_aes_key(Byte_buffer const& aes_bb)
{
    if (aes_bb.size()!=aes_block_size)
    {
        throw(std::runtime_error("Incorrect length for AES key"));
    }
    AES_KEY key;
    if (AES_set_encrypt_key(&aes_bb[0], 8*aes_block_size, &key) != 0)
    {
        throw(Openssl_error("get_aes_key: could not set encryption key."));
    }   

    return key;
}

Byte_buffer encrypt_aes128(
Byte_buffer const& in,
Byte_buffer const& aes_key_bb
)
{
    size_t d_size=in.size();
    if (d_size!=aes_block_size)
    {
        throw(std::runtime_error("encrypt_aes128: input data should be a complete block"));
    }
    Byte_buffer out(aes_block_size,0);
    AES_KEY key=get_aes_key(aes_key_bb);
    AES_encrypt(&in[0],&out[0],&key);

    return out;  // Truncate to the original length ?? Check this ??
}

Byte_buffer ossl_encrypt(
std::string const& cipher_name,
Byte_buffer const& in,
Byte_buffer const& aes_key_bb,
Byte_buffer const& initial_iv
)
{
    Evp_cipher_ctx_ptr ctx=new_evp_cipher_ctx();

    /* Create and initialise the context */
    if(ctx.get()== nullptr)
    {
        throw(Openssl_error("ossl_encrypt: unable to set context"));
    }
    int num=0;
    Byte_buffer iv=initial_iv;    
    size_t enc_blocks=1+in.size()/aes_block_size;
    Byte_buffer enc_out(enc_blocks*aes_block_size,0);

    if(1 != EVP_EncryptInit_ex(ctx.get(), EVP_get_cipherbyname(cipher_name.c_str()), NULL, &aes_key_bb[0], &iv[0]))
    {
        throw(Openssl_error("ossl_encrypt: EncryptInit failed"));
    }

    if(1 != EVP_EncryptUpdate(ctx.get(), &enc_out[0], &num, &in[0], in.size()))
    {
       throw(Openssl_error("ossl_encrypt: EncryptUpdate failed"));
    }

    int ciphertext_len=num;

    if(1 != EVP_EncryptFinal_ex(ctx.get(), &enc_out[num], &num))
    {
       throw(Openssl_error("ossl_encrypt: EncryptFinal failed"));
    }
    ciphertext_len += num;
//    std::cout << "Ciphertext length: " << ciphertext_len << '\n';

    return enc_out.get_part(0,ciphertext_len);
}


Byte_buffer ossl_decrypt(
std::string const& cipher_name,
Byte_buffer const& in,
Byte_buffer const& aes_key_bb,
Byte_buffer const& initial_iv
)
{
    Evp_cipher_ctx_ptr ctx=new_evp_cipher_ctx();

    /* Create and initialise the context */
    if(ctx.get()== nullptr)
    {
        throw(Openssl_error("ossl_decrypt: unable to set context"));
    }
    int num=0;
    Byte_buffer iv=initial_iv;    
    size_t dec_blocks=(in.size()+aes_block_size-1)/aes_block_size;
    Byte_buffer dec_out(dec_blocks*aes_block_size,0);

    //AES_KEY key=get_aes_key(aes_key_bb);
    if(1 != EVP_DecryptInit_ex(ctx.get(),EVP_get_cipherbyname(cipher_name.c_str()), NULL, &aes_key_bb[0], &iv[0]))
    {
        throw(Openssl_error("ossl_decrypt: DecryptInit failed"));
    }

    if(1 != EVP_DecryptUpdate(ctx.get(), &dec_out[0], &num, &in[0], in.size()))
    {
        throw(Openssl_error("ossl_decrypt: DecryptUpdate failed"));
    }
    int plaintext_len=num;

    if(1 != EVP_DecryptFinal_ex(ctx.get(), &dec_out[num], &num))
    {
        throw(Openssl_error("ossl_decrypt: DecryptFinal failed"));
    }
    plaintext_len += num;
//    std::cout << "Plaintext length: " << plaintext_len << '\n';
    return dec_out.get_part(0,plaintext_len);
}
