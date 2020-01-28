#!/bin/bash -l
export PATH=$PATH:/opt/ibmtss/utils
export TPM_DATA_DIR=$1
bin/tpm_server 
