/******************************************************************************
* File:        Key_name_from_public_data.cpp
* Description: Calculate the key's name from its public data (TPMT_PUBLIC)
*
* Author:      Chris Newton
*
* Created:     Tueday 29 May 2018
*
* (C) Copyright 2018, University of Surrey.
*
******************************************************************************/

#include <iostream>
#include "Marshal_public_data.h"
#include "Byte_buffer.h"
#include "Sha.h"

Byte_buffer get_key_name(
TPMT_PUBLIC* public_data
)
{
    Byte_buffer marshalled_public_area=marshal_public_data_T(public_data);
//    std::cout << "Marshalled area: size: " << marshalled_public_area.size() << '\n';
//    std::cout << "Marshalled area: data: " << marshalled_public_area.to_hex_string() << '\n';

    Byte_buffer sha256_ma=sha256_bb(marshalled_public_area);
//    std::cout << "SHA256 of marshalled area: " << sha256_ma.to_hex_string() << '\n';

    Byte_buffer name{0x00,0x0b}; // nameAlg (0x0b for sha256)
    name+=sha256_ma;
//    std::cout << "   Key name: size: " << name.size() << '\n';   
//    std::cout << "   Key name: data: " << name.to_hex_string() << '\n';

    return name;
}

Byte_buffer get_key_name_bb(
Byte_buffer key_pd
)
{
    Byte_buffer name;
    TPM2B_PUBLIC tpm2b_pub;
    TPM_RC rc=unmarshal_public_data_B(key_pd, &tpm2b_pub);
    if (rc!=0)
    {
        return name; // Leave it to others to sort out
    }

    return get_key_name(&tpm2b_pub.publicArea);
}
