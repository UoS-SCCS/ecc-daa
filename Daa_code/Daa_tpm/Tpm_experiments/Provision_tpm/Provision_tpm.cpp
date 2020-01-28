/*****************************************************************************
* File:        Provision_tpm.cpp
* Description: Program to provisiona TPM after reset
*
* Author:      Chris Newton
*
* Created:     Saturday 25 May 2019
*
* (C) Copyright 2019, University of Surrey, all rights reserved.
*
*****************************************************************************/

#include <iostream>
#include <cstring>
#include "Tss_includes.h"
#include "Tpm_error.h"
#include "Byte_buffer.h"
#include "Logging.h"
#include "Clock_utils.h"
#include "Tpm_param.h"
#include "Tss_setup.h"
#include "Tpm_initialisation.h"
#include "Tpm_utils.h"
#include "Tpm_defs.h"
#include "Sha.h"
#include "Provision_tpm.h"

Tpm_timings tpm_timings;

int main(int argc, char *argv[])
{
    // Used to catch multiple inputs for the device type
    std::string device="null";
    // Option defaults
    int debug_level=0;

    int arg=1;
    while (arg<argc)
    {
        auto search=program_options.find(argv[arg++]);
        if (search==program_options.end())
        {
            usage(std::cerr,argv[0]);
            return EXIT_FAILURE;
        }
        Option o=search->second;
        switch (o)
        {
        case Option::usedev:
            if (device=="null")
            {
                device="T";
            }
            else
            {
                std::cerr << "Only one interface can be selected\n";
                usage(std::cerr,argv[0]);
                return EXIT_FAILURE;
            }
            break;
        case Option::usesim:
            if (device=="null")
            {
                device="S";
            }
            else
            {
                std::cerr << "Only one interface can be selected\n";
                usage(std::cerr,argv[0]);
                return EXIT_FAILURE;
            }
            break;
        case Option::debug:
            {
                if (argc==arg)
                {
                    usage(std::cerr,argv[0]);
                    std::cerr << "Debug options (-g, or --debug) must have a level specified\n";
                    return EXIT_FAILURE;                                
                }
                std::string level(argv[arg]);
                if (level!="0" && level!="1" && level!="2")
                {
                    usage(std::cerr,argv[0]);
                    std::cerr << "Debug levels are 0, 1 or 2\n";
                    return EXIT_FAILURE;            
                }
                debug_level=atoi(argv[arg++]);
            }
            break;
        case Option::help:
            std::cout << code_version << '\n';
            usage(std::cout,argv[0]);
            return EXIT_SUCCESS;
        case Option::version:
            std::cout << code_version << '\n';
            return EXIT_SUCCESS;
        default:
            std::cerr << "Invalid option - " << argv[arg-1] << '\n';
            usage(std::cerr,argv[0]);
        }
    }

    Setup_ptr sp;
    if (device=="null" || device=="S") //  this is the default
    {
        device="S";
        sp.reset(new Simulator_setup);
        sp->data_dir.value=Tss_option::sim_data_dir.value;
    }
	else
	{
        sp.reset(new Device_setup);
        sp->data_dir.value=Tss_option::pi_data_dir.value;
	}

    log_ptr.reset(new Cout_log);
    log_ptr->set_debug_level(debug_level);

    TPM_RC	rc = 0;
    TSS_CONTEXT* tss_context=nullptr;
    // This is a global property, it does not need a context
    TSS_SetProperty(NULL, TPM_TRACE_LEVEL, "1");

    try
    {
        bool hw_tpm_=(sp->t==Tpm_type::device);
        if (!hw_tpm_)
        {
            rc=powerup(*sp);
            if (rc!=0)
            {
    			log_ptr->os() << "powerup: " << get_tpm_error(rc) << std::endl;
                throw(Tpm_error("Simulator powerup failed\n"));
            }
        }

         /* Start a TSS context */
        auto nc=set_new_context(*sp);
        rc=nc.first;
        if (rc!=0)
        {
            std::cerr << get_tpm_error(rc) << '\n';
            throw(Tpm_error("Unable to create a TSS_CONTEXT"));
        }

        tss_context=nc.second;

	    rc=startup(tss_context);
        if (rc==TPM_RC_INITIALIZE)
        {
            log_ptr->write_to_log("startup: TPM2_Startup returned TPM_RC_INITIALIZE\n");
            throw(Tpm_error("TPM2_Startup returned:  TPM_RC_INITIALIZE - reset the TPM module and try again"));
        }
		else if (rc!=0)
		{
			log_ptr->os() << "startup: " << get_tpm_error(rc) << std::endl;
			shutdown(tss_context);
			throw(Tpm_error("TPM startup failed (reset the TPM)"));
		}

        provision_pcr(tss_context);

        setup_primary_key(tss_context);
	}
	catch (Tpm_error &e)
	{
		std::cerr << (e.what()) << '\n';
	}
	catch (...)
	{
		std::cout <<"Failed - trapped an uncaught exception";
	}

    if (tss_context)
    {
        TSS_Delete(tss_context);
    }
    return EXIT_SUCCESS;
}

void usage(std::ostream& os, std::string name)
{
	os << "Usage: " << name << "\n\t-h, --help - this message\n"
                    << "\t-v, --version - the code version\n"
                    << "\t-t, --tpm - use the TPM device\n\t-s, --sim - use the TPM simulator (default)\n"
                    <<  "\t-g, --debug <debug level> - (0,1,2)\n";
}
