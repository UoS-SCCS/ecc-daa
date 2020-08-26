/******************************************************************************
* File:        Key_name_from_public_data.h
* Description: Calculate the key's name from its public data (TPMT_PUBLIC)
*
* Author:      Chris Newton
*
* Created:     Tueday 29 May 2018
*
* (C) Copyright 2018, University of Surrey.
*
******************************************************************************/

#pragma once

#include "Tss_includes.h"
#include "Byte_buffer.h"

Byte_buffer get_key_name(
TPMT_PUBLIC* public_data
);

Byte_buffer get_key_name_bb(
Byte_buffer key_pd
);
