#!/bin/bash -l

export PATH="$1:$PATH"
export LD_LIBRARY_PATH=/opt/ibmtss/utils

# make sure that we can access the device
source chmod 666 /dev/tpm0
