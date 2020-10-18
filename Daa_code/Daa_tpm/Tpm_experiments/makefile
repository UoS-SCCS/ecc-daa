# ==============================
#  Makefile for TPM_experiments
# ==============================

$(info Compiling with $(CXX))

all:
	make -s -C ./Provision_tpm
	make -s -C ./Make_daa_credential	
	make -s -C ./Daa_sign_message
	make -s -C ./Daa_certify_key
	make -s -C ./Daa_quote_pcr
	make -s -C ./Verify_daa_signature
	make -s -C ./Verify_daa_attest

#	./runTests

clean:
	@make clean -s -C ./Provision_tpm
	@make clean -s -C ./Make_daa_credential
	@make clean -s -C ./Daa_sign_message
	@make clean -s -C ./Daa_certify_key
	@make clean -s -C ./Daa_quote_pcr
	@make clean -s -C ./Verify_daa_signature
	@make clean -s -C ./Verify_daa_attest


    
