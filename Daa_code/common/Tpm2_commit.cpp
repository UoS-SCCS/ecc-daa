/*******************************************************************************
* File:        Tpm2_commit.cpp
* Description: Routine to call and time TPM2_commit 
*
* Author:      Chris Newton
*
* Created:     Saturday 15 September 2018
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


#include <sstream>
#include <chrono>
#include <cstring>
#include "Tpm_defs.h"
#include "Tpm2_commit.h"

Commit_data tpm2_commit(
TSS_CONTEXT* tss_context,
TPM_HANDLE daa_key_handle,
G1_point const& pt_s,
G1_point const& mapping_point
)
{
	uint16_t counter=0;
	Commit_points pts;
    
	Tpm_timer tt;

	Commit_In commit_in;
	Commit_Out commit_out;
	commit_in.signHandle=daa_key_handle;
	commit_in.P1.point.x=ecc_param_from_bb(pt_s.first);
	commit_in.P1.point.y=ecc_param_from_bb(pt_s.second);
	commit_in.s2=sensitive_data_from_bb(mapping_point.first);
	commit_in.y2=ecc_param_from_bb(mapping_point.second);
	TPM_RC rc = TSS_Execute(tss_context,
		(RESPONSE_PARAMETERS *)&commit_out,
		(COMMAND_PARAMETERS *)&commit_in,
		NULL,
		TPM_CC_Commit,
		TPM_RS_PW, NULL, 0,
		TPM_RH_NULL, NULL, 0);
	if (rc!=0)
	{
		log_ptr->os() << "tpm2_commit: "	<< get_tpm_error(rc) << std::endl;
		throw(Tpm_error("commit_for_certify: commit failed"));
	}

	counter=commit_out.counter;
	pts[0]=std::make_pair(ecc_param_to_bb(commit_out.K.point.x),
									ecc_param_to_bb(commit_out.K.point.y));
	pts[1]=std::make_pair(ecc_param_to_bb(commit_out.L.point.x),
										ecc_param_to_bb(commit_out.L.point.y));
	pts[2]=std::make_pair(ecc_param_to_bb(commit_out.E.point.x),
										ecc_param_to_bb(commit_out.E.point.y));       


    Tpm_timer::Rep t=tt.get_duration();
    std::string id_string("TPM2_Commit ");
    if (pt_s.first.size()!=0)
        id_string+="P1 ";
    if (mapping_point.first.size()!=0)
        id_string+="(s2,y2) ";
    tpm_timings.add(id_string,t);

	return std::make_pair(counter,pts);
}

void print_commit_data(
std::ostream& os,    
Commit_data const& cd
)
{
    std::string labels[]={"K","L","E"};    
    os << "TPM2_Commit returned: counter: " << cd.first << " and\n";
    for (int i=0;i<3;++i)
    {
        os << labels[i] << "-x: " << cd.second[i].first.to_hex_string() << '\n';
        os << labels[i] << "-y: " << cd.second[i].second.to_hex_string() << '\n';
    }
}
