/******************************************************************************
* File:        Tpm2_commit.cpp
* Description: Routine to call and time TPM2_commit 
*
* Author:      Chris Newton
*
* Created:     Saturday 15 September 2018
*
* (C) Copyright 2018, University of Surrey.
*
******************************************************************************/

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
    
	std::ostringstream oss;

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
