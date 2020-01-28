TPM Experiments Version 0.3
===========================

The protocols are implemented in a number of separate programs:

**provision_tpm** - this sets up the TPM in preparation. It creates the RSA
endorsement key and makes it persistent. This is particularly important
for the hardware TPM where creating an RSA key is very slow. The program
also writes to PCR 23 (the application PCR) in preparation for the
TPM2_Quote tests. At present no authorisation values are set and so empty
passwords can be used for the different TPM commands. This will be rectified
in Version 1.  

**make_daa_credential** - this starts the process and does the join. The Issuer's
public keys, the DAA_key and its credential are written to a file,
for example, for a program using the simulator: Daa_S_cre_1379369545.
The number is generated from the current time. For a program running on the
Raspberry Pi and using the TPM module the `S` will be replaced with `T`.
The corresponding timings for the program will be in a log file:
`Daa_S_cre_log_1379369545`.

**daa_sign_message** - this reads a credential file and signs a message using
the key and credential stored in the file. The user can select whether to
use a basename, or not. If a basename is used then it is randomly chosen.
The message, basename, points `J` and `K`, the Issuer's public keys, and the
resulting signature with a basename is stored in a file:

```bash
Daa_S_sign_bsn_1379369545,
```

with timings in a log file:

```bash
Daa_S_sign_bsn_log_1379369545.
```

For no basename no values for basename, `J` and `K` are written to the file. The
filenames would be:

```bash
Daa_S_sign_no_bsn_1379369545 and Daa_S_sign_no_bsn_log_1379369545.
```

**verify_daa_signature** - this reads a signature file, verifies the signature
and also checks the randomised credential. Timings are written to a file:
Daa_S_sign_bsn_ver_1379369545 is the file for Daa_S_sign_bsn_1379369545.

**daa_certify_key** - this reads a credential file, creates and loads an ECDSA
key and then generates a certificate for it. The user can select whether to
use a basename, or not. If a basename is used then a basename is randomly
chosen. The key certificate, basename, points J and K, the Issuer's public
keys, the randomised credential and certificate's signature is stored in a
file:

```bash
Daa_S_certify_bsn_1379369545
```

with timings in a log file:

```bash
Daa_S_certify_bsn_log_1379369545
```

For no basename no values of basename, `J` and `K` are written to the file. The
filenames would be:

```bash
Daa_S_certify_no_bsn_1379369545
```

and

```bash
Daa_S_certify_no_bsn_log_1379369545.
```

**daa_quote_pcr** - this reads a credential file, uses TPM2_Quote to read and
sign a set of PCR values. The user can select whether to use a basename, or
not. If a basename is used then a basename is randomly chosen. The PCR
attestation data, basename, points `J` and `K`, the Issuer's public
keys, the randomised credential and attestation data's signature is stored
in a file:

```bash
Daa_S_quote_bsn_1379369545
```

with timings in a log file:

```bash
Daa_S_quote_bsn_log_1379369545
```

For no basename no values of basename, `J` and `K` are written to the file. The
filenames would be:

```bash
Daa_S_quote_no_bsn_1379369545
```

and

```bash
Daa_S_quote_no_bsn_log_1379369545
```

**verify_daa_attest** - this program is used to check the attestation data from
the certify and quote programs. The signature on the attestation data is
verified together with the randomised credential. As for verify_daa_sign the
timings written to a file. So for `Daa_S_quote_bsn_1379369545`, the file is:
`Daa_S_quote_bsn_ver_1379369545`.

Running the code
----------------

Apart from the programs used for verification all of the programs use the
TPM and this needs the environment to be correctly setup. Most of this is
done internally, but there are two scripts for setting things up, one for
using the TPM simulator (`setupForTPMSim.sh`) and one for using the TPM module
on the Raspberry Pi (`setupForTPMDev.sh`). These should be 'sourced' in the
terminal window being used, for example:

```bash
source ./setupForSim.sh
```

The TPM's data files are written to different directories when using the
simulator, (/home/cn0016/TPM_data) or the TPM module on the Raspberry Pi
(/home/pi/Daa_logs). At the moment these are fixed in the programs, but can
be changed by editing the lines

```c
Tss_property const pi_data_dir{TPM_DATA_DIR,"/home/pi/Daa_logs"};
Tss_property const sim_data_dir{TPM_DATA_DIR,"/home/cn0016/TPM_data"};
```

in the file `daa_impl/Daa_code/include/Tss_param.h` and re-compiling.

The different parameters that can be used for each program can be obtained
by running the program with the `-h`, or `--help` option.
