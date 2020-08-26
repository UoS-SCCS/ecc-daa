/***************************************************************************
* File:        Openssl_ec_map_to_point.cpp
* Description: Function implementing map_to-point in Openssl EC
*
* Author:      Chris Newton
* Created:     Saturday 7 July 2018
*
* (C) Copyright 2018, University of Surrey.
*
****************************************************************************/

#include <cstdint>
#include <string>
#include <iostream>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include "Openssl_utils.h"
#include "Openssl_bn_utils.h"
#include "Openssl_ec_utils.h"
#include "Openssl_ec_map_to_point.h"

// Prepends a counter to the initial value and calculates a test point,
// s_2=counter+initial_value, test point=(sha256(s_2), y_2). If the point
// is on the curve then it returns s_2 and y_2. If not, it increments
// the counter and tries again.
G1_point map_to_point(
Ec_group_ptr const& ecgrp,
Byte_buffer const& initial_value,
uint32_t max_iter
)
{
	G1_point pt;
	// Get the curve parameters
	Bn_ctx_ptr ctx=new_bn_ctx();
	Bn_ptr p_bn=new_bn();
	Bn_ptr a_bn=new_bn();
	Bn_ptr b_bn=new_bn();
	int rc=EC_GROUP_get_curve_GFp(ecgrp.get(),p_bn.get(),a_bn.get(),b_bn.get(),ctx.get());
	if (rc!=1)
	{
		throw(Openssl_error("map_to_point: failed to get the curve parameters"));
	}
	Byte_buffer p_bb=bn2bb(p_bn.get());
	bool point_on_curve=false;
	uint32_t counter=0;
	Byte_buffer s_2;
	Byte_buffer x_2;
	Byte_buffer y_2;
	Bn_ptr x_bn=new_bn();
	Bn_ptr y_bn=new_bn();
	Bn_ptr xsq_bn=new_bn();
	Bn_ptr ysq_bn=new_bn();
	while (!point_on_curve && counter<max_iter)
	{
		s_2=uint32_to_bb(counter)+initial_value;
		x_2=bb_mod(sha256_bb(s_2),p_bb);
		bin2bn(&x_2[0],x_2.size(),x_bn.get());

		BN_mod_sqr(xsq_bn.get(),x_bn.get(),p_bn.get(),ctx.get());
		BN_mod_add(ysq_bn.get(),x_bn.get(),a_bn.get(),p_bn.get(),ctx.get());
		BN_mod_mul(ysq_bn.get(),ysq_bn.get(),xsq_bn.get(),p_bn.get(),ctx.get());
		BN_mod_add(ysq_bn.get(),ysq_bn.get(),b_bn.get(),p_bn.get(),ctx.get());
		BN_mod_sqrt(y_bn.get(),ysq_bn.get(),p_bn.get(),ctx.get());
		y_2=bn2bb(y_bn.get());
		pt=std::make_pair(x_2,y_2);
		point_on_curve=point_is_on_curve(ecgrp,pt);
/*		
		std::cout << counter << '\n';
		std::cout << "s_2: " << s_2.to_hex_string() << '\n';
		std::cout << "x_2: " << x_2.to_hex_string() << '\n';
		std::cout << "y_2: " << y_2.to_hex_string() << '\n';
*/
		++counter;
	}

    if (!point_on_curve)
    {
        throw(std::runtime_error("map_to_point: failed to find a point"));
    }

	return std::make_pair(s_2,y_2);
}

G1_point point_from_basename(Byte_buffer const& bsn)
{
    G1_point map_pt;
    if (bsn.size()!=0)
    {
        Ec_group_ptr ecgrp=new_ec_group("bnp256");
        if (ecgrp==NULL)
        {
            throw(Openssl_error("Error generating the curve"));
        }
            
        uint32_t max_map_tries{10};
        map_pt=map_to_point(ecgrp,bsn,max_map_tries);
    }
    return map_pt;    
}
