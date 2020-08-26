/***************************************************************************
* File:        Daa_signatures.cpp
* Description: Common code for the DAA signatures (sign, certify and quote)
*
* Author:      Chris Newton
*
* Created:     Sunday 2 June 2019
*
* (C) Copyright 2019, University of Surrey.
*
****************************************************************************/

#include "Tpm_param.h"
#include "Daa_signatures.h"

void usage(std::ostream& os, const char* name)
{
    os << code_version << '\n';
	os << "Usage: " << name << "\n\t-h, --help - this message\n"
                    << "\t-v, --version - the code version\n"
                    << "\t-b, --bsn - use a basename\n\t-n, --nobsn - don't use a basename\n"
                    <<  "\t-g, --debug <debug level> - (0,1,2)\n\t-d, --datadir <data directory> - (default .)\n"
                    << "\t<credential filename>\n";
}

Init_result initialise(int argc, char *argv[], std::string const& type, Program_data& pd)
{
    if (argc<2)
    {
        std::cerr << "A credential filename, or help request (-h, or --help, or -v, or --version) must be given\n";
        usage(std::cerr,argv[0]);
		return Init_result::init_failed;        
    }
    std::string first_arg(argv[1]);
    if (argc==2)
    {
        if (first_arg=="-h" || first_arg=="--help")
        { 
            usage(std::cout,argv[0]);
            return Init_result::init_help;
        }
        else if (first_arg=="-v" || first_arg=="--version")
        {
            std::cout << code_version << '\n';
            return Init_result::init_help;
        }
    }
    // The last argument is the credential filename
    pd.credential_filename=std::string(argv[argc-1]);
    // The remaining arguments will be options
    argc--;
    auto pos=pd.credential_filename.find_first_of('_');
    if (pos==std::string::npos)
    {
        std::cerr << "Credential filename: " << pd.credential_filename << " has the wrong format" << '\n';
        return Init_result::init_failed;
    }

    std::string device=pd.credential_filename.substr(pos+1,1);
	if (device=="T")
	{
        pd.sp.reset(new Device_setup);
        pd.sp->data_dir.value=Tss_option::pi_data_dir.value;
	}
	else if (device=="S")
	{
        pd.sp.reset(new Simulator_setup);
        pd.sp->data_dir.value=Tss_option::sim_data_dir.value;
	}
    else
    {
        std::cerr << "Credential filename: " << pd.credential_filename << " has the wrong format" << '\n';
        std::cerr << "It must contain the TPM type after the first _\n";
        return Init_result::init_failed;
    }

   // Used to catch multiple inputs for the bsn type
    std::string bsn_option="null";
    // Option defaults
    int debug_level=0;
    pd.file_basename=".";
 
    int arg=1;
    while (arg<argc)
    {
        auto search=program_options.find(argv[arg++]);
        if (search==program_options.end())
        {
            std::cerr << "Invalid option: " << argv[arg-1] << '\n';
            usage(std::cerr,argv[0]);
            return Init_result::init_failed;
        }
        Option o=search->second;
        switch (o)
        {
        case Option::datadir:
            pd.file_basename=std::string(argv[arg++]);
            break;
        case Option::usebsn:
            if (bsn_option=="null")
            {
                bsn_option="bsn";
            }
            else
            {
                std::cerr << "Only one bsn option can be selected\n";
                usage(std::cerr,argv[0]);
                return Init_result::init_failed;
            }
            break;
        case Option::nobsn:
            if (bsn_option=="null")
            {
                bsn_option="nobsn";
            }
            else
            {
                std::cerr << "Only one bsn option can be selected\n";
                usage(std::cerr,argv[0]);
                return Init_result::init_failed;
            }
            break;
        case Option::debug:
            {
                std::string level(argv[arg]);
                if (level!="0" && level!="1" && level!="2")
                {
                    usage(std::cerr,argv[0]);
                    std::cerr << "Debug levels are 0, 1 or 2 (default 0)\n";
                    return Init_result::init_failed;            
                }
                debug_level=atoi(argv[arg++]);
            }
            break;
        case Option::help:
            usage(std::cout,argv[0]);
            return Init_result::init_help;
        case Option::version:
            std::cout << code_version << '\n';
            return Init_result::init_help;
        default:
            std::cerr << "Invalid option: " << argv[arg-1] << '\n';
            usage(std::cerr,argv[0]);
            return Init_result::init_failed;
        }
    }
    
    if (bsn_option=="null") //  then use default
    {
        std::cerr << "You must select a basename option\n";
        usage(std::cerr,argv[0]);
    }
    pd.use_basename=(bsn_option=="bsn");

    pd.signature_file=pd.credential_filename.substr(0,pos+2)+"_"+type+"_";
    pd.signature_file+=(pd.use_basename)?"bsn_":"no_bsn_";
    pos=pd.credential_filename.find_last_of('_');
    if (pos==std::string::npos)
    {
        std::cerr << "Credential filename: " << pd.credential_filename << " has the wrong format" << '\n';
        return Init_result::init_failed;
    }
    pd.run_number=pd.credential_filename.substr(pos+1);

    std::string filename=pd.file_basename+"/"+pd.signature_file+"log_"+pd.run_number;
    try
	{
		log_ptr.reset(new Timed_file_log(filename));
	}
	catch (std::runtime_error &e)
	{
		std::cerr << e.what() << '\n';
		return Init_result::init_failed;
	}

	log_ptr->set_debug_level(debug_level);

    log_ptr->os() << std::boolalpha << "\nUse basename: " << pd.use_basename
                  << "\nDebug level: " << debug_level << std::endl;

    TPM_RC rc=pd.tpm.setup(*pd.sp);
	if (rc!=0)
	{
		std::cerr << "Setting up the TPM returned: " << pd.tpm.get_last_error() << '\n';
		return Init_result::init_failed;
	}

	return Init_result::init_ok;
}




