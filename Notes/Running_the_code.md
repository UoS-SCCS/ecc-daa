Running the Code
================

See the [code notes] for a description of the programs.

Before continuing ensure you have followed the [instructions] for installing
the IBM software. The remainder of this document assumes that it is installed
under `/opt`.

Before running the software setup the data directory and compile the code.
In this projects root directory type

```bash
make
```

Then copy the programs to the repository's bin directory

```bash
./copy_programs.sh $(pwd)/bin
```

If using the TPM simulator copy the tpm_server into the repositories `bin`
directory. In a terminal window, start in the repositories root directory.

```bash
cp /opt/ibmtpm/src/tpm_server $(pwd)/bin
```

Set the PATH variable:

```
export PATH=$(pwd)/bin:$PATH
```

Run using the Simulator
-----------------------

To use the simulator run the `startNewTPM.sh` script that starts a fresh
TPM simulator. Alternatively, running `startTPM.sh` resumes a running simulated
TPM. When running a set of tests do not start a fresh TPM as the original
internal parameters used when generating keys will be lost.

The simulator stores its files in the `TPM_DATA_DIR` directory (set inside
the programs, see the [code notes]).

When the our test and code runs, the simulator will print output to the terminal.

To begin the setup for running the tests, start a new terminal window and navigate
to the repository's root directory.

```bash
source ./setupForTPMSim.sh $(pwd)/bin
```

The programs are easily run from a data directory, e.g., `cd ~/Daa_logs`.
The programs can then be run.

Run using a Raspberry Pi and TPM Dev kit
----------------------------------------

Login to the Raspberry Pi and change to the repository's root directory, and
source the setup script

```bash
source ./setupForTPMDev.sh $(pwd)/bin
```

This script requires sudo to access to the TPM device. As the user `pi` there
will usually be no need to enter a password to do this.

```bash
source ./setupForTPMDev.sh $(pwd)/bin
```

The programs are easily run from the data directory, e.g., `cd ~/Daa_logs`
You should now be ready to run the programs.

Running the executables
-----------------------

If run with the parameter `-h`, or `--help` you will get an usage message giving the
parameters needed. For most purposes the programs can be run without setting the
debug parameter (it defaults to 0).

For example, on the Raspberry Pi:

```bash
provision_tpm -t
make_daa_credential -t -d ~/Daa_logs
```

Executing these two steps produced two files: `Daa_T_cre_1385566841` and `Daa_T_cre_log_1385566841`.

```bash
daa_sign_message -d ~/Daa_logs -n Daa_T_cre_1385566841
```

Produces: `Daa_T_sign_no_bsn_1385566841` and `Daa_T_sign_no_bsn_log_1385566841`.

```bash
verify_signature -d ~/Daa_logs Daa_T_sign_no_bsn_1385566841
```

Should return 'Signature OK'.

```bash
daa_certify_key -d ~/Daa_logs -b Daa_T_cre_1385566841
```

Produces: `Daa_T_certify_bsn_1385566841` and `Daa_T_certify_bsn_log_1385566841`.

```bash
verify_daa_attest -d ~/Daa_logs Daa_T_certify_bsn_1385566841
```

Should return 'Certify signature OK'.

<!-- References -->
[code notes]:Code_notes.md
[instructions]:Installing_IBM_software.md