/***************************************************************************
* File:        Tpm_initialisation.cpp
* Description: TPM initialisation routines
*
* Author:      Chris Newton
*
* Created:     Saturday 25 May 2019
*
* (C) Copyright 2019, University of Surrey.
*
****************************************************************************/

#include <iostream>
#include <cstring>
#include <ctime>
#include <string>
#include "Tss_includes.h"
#include "Tpm_error.h"
#include "Tpm_utils.h"
#include "Tpm_param.h"
#include "Tpm_defs.h"
#include "Sha.h"
#include "Create_primary_rsa_key.h"
#include "Make_key_persistent.h"
#include "Flush_context.h"
#include "Tpm_initialisation.h"

TPM_RC powerup(Tss_setup const& tps)
{
    TPM_RC rc=0;

    if (log_ptr->debug_level()>0)
    {
        log_ptr->write_to_log("powerup\n");
    }

    TSS_CONTEXT* tmp_context=nullptr;   // powerup seems to leave the TSS_CONTEXT in a funny state,
                                        // so use a temporary one and then delete it.
    
    auto nc=set_new_context(tps);
    rc=nc.first;
    if (rc==0)
    {
        tmp_context=nc.second;
        rc=TSS_TransmitPlatform(tmp_context,TPM_SIGNAL_POWER_OFF,"TPM2_PowerOffPlatform");
    }
    if (rc==0)
    {
        rc=TSS_TransmitPlatform(tmp_context,TPM_SIGNAL_POWER_ON,"TPM2_PowerOnPlatform");
    }
    if (rc==0)
    {
        rc=TSS_TransmitPlatform(tmp_context,TPM_SIGNAL_NV_ON,"TPM2_NvOnPlatform");
    }
    
    TPM_RC rc1=TSS_Delete(tmp_context);
    if (rc==0)
    {
        rc=rc1;
    }

    return rc;
}

TPM_RC startup(TSS_CONTEXT* tss_context)
{
    TPM_RC rc=0;
    if (log_ptr->debug_level()>0)
    {
        log_ptr->write_to_log("startup\n");
    }

    Tpm_timer tt;

    Startup_In in;
    in.startupType = TPM_SU_CLEAR;
    rc = TSS_Execute(tss_context,
                    NULL, 
                    (COMMAND_PARAMETERS *)&in,
                    NULL,
                    TPM_CC_Startup,
                    TPM_RH_NULL, NULL, 0);

    tpm_timings.add("TPM2_startup",tt.get_duration());

    return rc;
}

TPM_RC shutdown(TSS_CONTEXT* tss_context)
{
    TPM_RC rc=TPM_RC_SUCCESS;
    if (log_ptr->debug_level()>0)
    {
            log_ptr->write_to_log("shutdown\n");
    }

    Tpm_timer tt;

    Shutdown_In in;
    in.shutdownType = TPM_SU_CLEAR;
    rc = TSS_Execute(tss_context,
                    NULL, 
                    (COMMAND_PARAMETERS *)&in,
                    NULL,
                    TPM_CC_Shutdown,
                    TPM_RH_NULL, NULL, 0);

    tpm_timings.add("TPM2_Shutdown", tt.get_duration());
    
    return rc;
}

std::pair<TPM_RC,bool> take_ownership_enabled(
TSS_CONTEXT* tss_context
)
{
    TPM_RC rc=TPM_RC_SUCCESS;

    GetCapability_In in;
    GetCapability_Out out;
    in.capability=TPM_CAP_TPM_PROPERTIES;
    in.property=TPM_PT_PERMANENT;
    in.propertyCount=2;
    rc=TSS_Execute(tss_context,
        (RESPONSE_PARAMETERS*)&out,
        (COMMAND_PARAMETERS*)&in,
        NULL,
        TPM_CC_GetCapability,
        TPM_RH_NULL,NULL,0
    );
    if (rc!=TPM_RC_SUCCESS)
    {
        return std::make_pair(rc,false);
    }

    if (out.capabilityData.data.tpmProperties.count!=2)
    {
        std::cerr << "take_ownership_enabled: property count incorrect\n";
        shutdown(tss_context);
        exit(EXIT_FAILURE);
    }
    uint32_t pt_permanent=out.capabilityData.data.tpmProperties.tpmProperty[0].value;
    uint32_t pt_startup=out.capabilityData.data.tpmProperties.tpmProperty[1].value;

    std::cout << "PT_PERMANENT: " << pt_permanent << '\n';
    std::cout << "  PT_STARTUP: " << pt_startup << '\n';

    bool res=!(pt_permanent&TPMA_PERMANENT_OWNERAUTHSET);

    res |= (pt_startup&TPMA_STARTUP_CLEAR_SHENABLE);

    return std::make_pair(rc,res);
}

TPM_RC set_tpm_clock(TSS_CONTEXT* tss_context)
{
    TPM_RC rc=TPM_RC_SUCCESS;

    time_t linux_time=time(NULL);

    TPMI_SH_AUTH_SESSION session_handle = TPM_RS_PW;
    unsigned int         session_attrib = 0;

    return rc;

/*
    typedef struct {
        TPMI_RH_PROVISION   auth;
        UINT64              newTime;
    } ClockSet_In;
*/
    ClockSet_In in;
    in.newTime=1000*linux_time;
    in.auth=TPM_RH_OWNER;
    rc=TSS_Execute(tss_context,
        NULL,
        (COMMAND_PARAMETERS*)&in,
        NULL,
        TPM_CC_ClockSet,
        session_handle,NULL,session_attrib,0);
    if (rc!=0)
    {
        if (log_ptr->debug_level()>0)
        {
            log_ptr->os() << "provision_pcr: set_tpm_clock: " << get_tpm_error(rc) << std::endl;
        }
        throw(Tpm_error("provision_pcr: set_tpm_clock failed"));        
    }    

    return rc;
}


void provision_pcr(TSS_CONTEXT* tss_context)
{
    TPM_RC rc;
    try
    {
        TPMI_DH_PCR pcr_handle=app_pcr_handle;       
        TPML_PCR_SELECTION pcr_sel;
        pcr_sel.count=1;
        pcr_sel.pcrSelections[0].hash=TPM_ALG_SHA256;
        pcr_sel.pcrSelections[0].sizeofSelect=3; // Minimum size
        pcr_sel.pcrSelections[0].pcrSelect[0]=0;
        pcr_sel.pcrSelections[0].pcrSelect[1]=0;
        pcr_sel.pcrSelections[0].pcrSelect[2]=0;
        pcr_sel.pcrSelections[0].pcrSelect[pcr_handle / 8] = 1 << (pcr_handle % 8);

        PCR_Read_In pcr_read_in;
        PCR_Read_Out pcr_read_out;
        pcr_read_in.pcrSelectionIn=pcr_sel;
        rc=TSS_Execute(tss_context,
            (RESPONSE_PARAMETERS*)&pcr_read_out,
            (COMMAND_PARAMETERS*)&pcr_read_in,
            NULL,
            TPM_CC_PCR_Read,
            TPM_RH_NULL,NULL,0
        );
        if (rc!=0)
        {
            if (log_ptr->debug_level()>0)
                {
                log_ptr->os() << "provision_pcr: PCR_Read: " << get_tpm_error(rc) << std::endl;
            }
            throw(Tpm_error("provision_pcr: PCR_Read failed"));        
        }

        uint32_t pcr_count=pcr_read_out.pcrValues.count;
        if (log_ptr->debug_level()>0)
        {
            log_ptr->os() << "provision_pcr: read " << pcr_count << " PCR values\n";
        }
        if (pcr_count!=1)
        {
            if (log_ptr->debug_level()>0)
            {
                log_ptr->os() << "provision_pcr: read did not return the correct number of PCRs\n";
            }
            throw(Tpm_error("provision_pcr: PCR_Read(1) did not return the correct number of PCRs"));
        }
        Byte_buffer pcr_digest(pcr_read_out.pcrValues.digests[0].t.buffer,pcr_read_out.pcrValues.digests[0].t.size);
        if (log_ptr->debug_level()>0)
        {
            log_ptr->os() << "Digest 1: " << pcr_digest.to_hex_string() << '\n';
        }
        Byte_buffer empty_pcr(pcr_read_out.pcrValues.digests[0].t.size,0);
        if (pcr_digest!=empty_pcr)
        {
            if (log_ptr->debug_level()>0)
            {
                log_ptr->os() << "provision_pcr: read did not return the empty PCR value\n";
            }
            throw(Tpm_error("provision_pcr: PCR_Read(1) read did not return the empty PCR value - reset the TPM"));
        }  
      
        Byte_buffer pcr_input(pcr_str);
        PCR_Extend_In  pcr_extend_in;
        pcr_extend_in.digests.count=1;
        pcr_extend_in.digests.digests[0].hashAlg=TPM_ALG_SHA256;
        // Zero memory for digest up to the maximum possible digest length
        memset((uint8_t *)&pcr_extend_in.digests.digests[0].digest, 0, sizeof(TPMU_HA));
        // Now set the input
        memcpy((uint8_t *)&pcr_extend_in.digests.digests[0].digest,&pcr_input[0],pcr_input.size());
        pcr_extend_in.pcrHandle=pcr_handle;
        rc = TSS_Execute(tss_context,
                NULL, 
                (COMMAND_PARAMETERS *)&pcr_extend_in,
                NULL,
                TPM_CC_PCR_Extend,
                TPM_RS_PW, NULL, 0,
                TPM_RH_NULL, NULL, 0);        
        if (rc!=0)
        {
            if (log_ptr->debug_level()>0)
            {
                log_ptr->os() << "provision_pcr: " << get_tpm_error(rc) << '\n';
            }
            throw(Tpm_error("PCR_Extend failed"));        
        }

        if (!check_pcr_provision(tss_context))
        {
            log_ptr->os() << "check_pcr_provision: check failed\n";
            throw(Tpm_error("check_pcr_provision: failed - try resetting the TPM"));
        }  
    }
    catch(const std::exception& e)
    {
        std::cerr << e.what() << '\n';
    }
}

bool check_pcr_provision(TSS_CONTEXT* tss_context)
{
    bool pcr_ok=true;
    TPM_RC rc;
    try
    {
        TPMI_DH_PCR pcr_handle=app_pcr_handle;       
        TPML_PCR_SELECTION pcr_sel;
        pcr_sel.count=1;
        pcr_sel.pcrSelections[0].hash=TPM_ALG_SHA256;
        pcr_sel.pcrSelections[0].sizeofSelect=3; // Minimum size
        pcr_sel.pcrSelections[0].pcrSelect[0]=0;
        pcr_sel.pcrSelections[0].pcrSelect[1]=0;
        pcr_sel.pcrSelections[0].pcrSelect[2]=0;
        pcr_sel.pcrSelections[0].pcrSelect[pcr_handle / 8] = 1 << (pcr_handle % 8);

        PCR_Read_In pcr_read_in;
        PCR_Read_Out pcr_read_out;
        pcr_read_in.pcrSelectionIn=pcr_sel;
        rc=TSS_Execute(tss_context,
            (RESPONSE_PARAMETERS*)&pcr_read_out,
            (COMMAND_PARAMETERS*)&pcr_read_in,
            NULL,
            TPM_CC_PCR_Read,
            TPM_RH_NULL,NULL,0
        );
        if (rc!=0)
        {
            if (log_ptr->debug_level()>0)
                {
                log_ptr->os() << "check_pcr_provision: PCR_Read: " << get_tpm_error(rc) << std::endl;
            }
            throw(Tpm_error("check_pcr_provision: PCR_Read failed"));        
        }

        uint32_t pcr_count=pcr_read_out.pcrValues.count;
        if (log_ptr->debug_level()>0)
        {
            log_ptr->os() << "check_pcr_provision: read " << pcr_count << " PCR values\n";
        }
        if (pcr_count!=1)
        {
            if (log_ptr->debug_level()>0)
            {
                log_ptr->os() << "check_pcr_provision: read did not return the correct number of PCRs\n";
            }
            throw(Tpm_error("check_pcr_provision: PCR_Read did not return the correct number of PCRs"));
        }
        Byte_buffer pcr_digest(pcr_read_out.pcrValues.digests[0].t.buffer,pcr_read_out.pcrValues.digests[0].t.size);
        if (log_ptr->debug_level()>0)
        {
            log_ptr->os() << "Digest read: " << pcr_digest.to_hex_string() << '\n';
        }

        if (pcr_digest!=pcr_expected)
        {
            if (log_ptr->debug_level()>0)
            {
                log_ptr->os() << "check_pcr_provision: read did not return the correct PCR value\n";
            }
            pcr_ok=false;
        }  
    }
    catch(const std::exception& e)
    {
       return false;
    }

    return pcr_ok;
}

bool persistent_key_available(TSS_CONTEXT* tss_context,TPM_HANDLE handle)
{
    TPM_RC rc;
    if (log_ptr->debug_level()>0)
    {
            log_ptr->write_to_log("persistent_key_available\n");
    }

    bool key_available=false;

    Tpm_timer tt;

    GetCapability_In in;
    GetCapability_Out out;         
    in.capability=TPM_CAP_TPM_PROPERTIES;
    in.property=TPM_PT_HR_PERSISTENT;
    in.propertyCount=1;
    rc=TSS_Execute(tss_context,
            (RESPONSE_PARAMETERS*)&out,
            (COMMAND_PARAMETERS*)&in,
            NULL,
            TPM_CC_GetCapability,
            TPM_RH_NULL,NULL,0
    );
    if (rc!=0)
    {
            log_ptr->os() << "persistent_key_available: " << get_tpm_error(rc) << std::endl;
            throw(Tpm_error("GetCapability (TPM_PT_HR_PERSISTENT) failed"));        
    }
    tpm_timings.add("TPM2_GetCapability (TPM_PT_PERSISTENT)", tt.get_duration());

    size_t ph_count=out.capabilityData.data.tpmProperties.tpmProperty[0].value;
    if (ph_count!=0)
    {
            auto handles=retrieve_persistent_handles(tss_context,ph_count);
            for (int i=0;i<handles.size();++i)
            {
                    if (handles[i]==handle)
                    {
                            key_available=true;
                            break;
                    }
            }
    }

    return key_available;
}

std::vector<TPM_HANDLE> retrieve_persistent_handles(TSS_CONTEXT* tss_context, size_t ph_count)
{
    // std::cout << "Tpm_daa::retrieve_persistent_handles " << ph_count << '\n';
    //!!!!!!!Need to fix this for the case where there is more data
    //!!!!!!!Not needed for VANET as we should only have one persistent handle
    TPM_RC rc=0;

    if (log_ptr->debug_level()>0)
    {
            log_ptr->write_to_log("retrieve_persistent_handles\n");
    }

    std::vector<TPM_HANDLE> handles;

    Tpm_timer tt;

    GetCapability_In in;
    GetCapability_Out out;         
    in.capability=TPM_CAP_HANDLES;
    in.property=TPM_HT_PERSISTENT << 24;
    in.propertyCount=ph_count;
    rc=TSS_Execute(tss_context,
            (RESPONSE_PARAMETERS*)&out,
            (COMMAND_PARAMETERS*)&in,
            NULL,
            TPM_CC_GetCapability,
            TPM_RH_NULL,NULL,0
    );
    if (rc!=0)
    {
            log_ptr->os() << "retrieve_persistent_handles: " << get_tpm_error(rc) << std::endl;
            throw(Tpm_error("Tpm_daa: GetCapability (TPM_HT_PERSISTENT) failed"));        
    }
    tpm_timings.add("TPM2_GetCapability (TPM_HT_PERSISTENT)",tt.get_duration());

    size_t h_count=out.capabilityData.data.handles.count;
    for (int i=0;i<h_count;++i)
    {
            handles.push_back(out.capabilityData.data.handles.handle[i]);
    }

    return handles;
}

void setup_primary_ek(TSS_CONTEXT* tss_context)
{
    TPM_RC rc=0;
    if (log_ptr->debug_level()>0)
    {
        log_ptr->write_to_log("setup_primary_ek\n");
    }

    if (!persistent_key_available(tss_context,ek_persistent_handle))
    {
        CreatePrimary_Out out_primary;
        rc=create_primary_rsa_key(tss_context,TPM_RH_ENDORSEMENT,&out_primary);
        if (rc!=0)
        {
            log_ptr->os() << "setup_primary_ek: create primary key: " << get_tpm_error(rc) << std::endl; 
            throw(Tpm_error("setup_primary_ek: creation of primary key failed"));
        }

        make_ek_persistent(tss_context,out_primary.objectHandle);
    }
}

void read_ek_public_data(TSS_CONTEXT* tss_context, TPM2B_PUBLIC& pd)
{
    TPM_RC rc=0;
    if (log_ptr->debug_level()>0)
    {
        log_ptr->write_to_log("Tpm_daa: read_ek_public_data\n");
    }

    Tpm_timer tt;

    ReadPublic_In in;
    ReadPublic_Out out;
    in.objectHandle=ek_persistent_handle;
    rc=TSS_Execute(tss_context,
            (RESPONSE_PARAMETERS*)&out,
            (COMMAND_PARAMETERS*)&in,
            NULL,
            TPM_CC_ReadPublic,
            TPM_RH_NULL,NULL,0
    );
    if (rc!=0)
    {
        log_ptr->os() << "read_ek_public_data: " << get_tpm_error(rc) << std::endl;
        throw(Tpm_error("read_ek_public_data: ReadPublic failed"));        
    }
    tpm_timings.add("TPM2_ReadPublic",tt.get_duration());
    pd=out.outPublic;
}

void read_persistent_key_public_data(
TSS_CONTEXT* tss_context,
TPM_HANDLE handle,
TPM2B_PUBLIC& pd)
{
    TPM_RC rc=0;
    if (log_ptr->debug_level()>0)
    {
        log_ptr->write_to_log("Tpm_daa: read_persistent_key_public_data\n");
    }

    Tpm_timer tt;

    ReadPublic_In in;
    ReadPublic_Out out;
    in.objectHandle=handle;
    rc=TSS_Execute(tss_context,
            (RESPONSE_PARAMETERS*)&out,
            (COMMAND_PARAMETERS*)&in,
            NULL,
            TPM_CC_ReadPublic,
            TPM_RH_NULL,NULL,0
    );
    if (rc!=0)
    {
        log_ptr->os() << "read_persistent_key_public_data: " << get_tpm_error(rc) << std::endl;
        throw(Tpm_error("read_persistent_key_public_data: ReadPublic failed"));        
    }
    tpm_timings.add("TPM2_ReadPublic",tt.get_duration());
    pd=out.outPublic;
}

TPM_RC make_ek_persistent(
TSS_CONTEXT* tss_context,
TPM_HANDLE ek_handle
)
{
    TPM_RC rc=0;
    if (log_ptr->debug_level()>0)
    {
        log_ptr->write_to_log("Tpm_daa: make_ek_persistent\n");
    }

    rc=make_key_persistent(tss_context,TPM_RH_OWNER,ek_handle,ek_persistent_handle);
    if (rc==TPM_RC_NV_DEFINED)
    {
        TPM_RC rc1=remove_persistent_key(tss_context,TPM_RH_OWNER,ek_persistent_handle);
        if (rc1==0) 
        {
            rc=make_key_persistent(tss_context,TPM_RH_OWNER,ek_handle,ek_persistent_handle);
        }
    }
    if (rc!=0)
    {
        log_ptr->os() << "make_ek_persistent: " << get_tpm_error(rc) << std::endl;
        throw(Tpm_error("Unable to make the endorsement key persistent"));
    }
    
    rc=flush_context(tss_context,ek_handle);
    if (rc!=0)
    {
        log_ptr->os() << "make_ek_persistent: flush_context:" << get_tpm_error(rc) << std::endl;
        throw(Tpm_error("Unable to flush the primary key"));
    }

    return rc;
}




