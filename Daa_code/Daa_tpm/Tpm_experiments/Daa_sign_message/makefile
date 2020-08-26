# =============================================================================
#  Makefile for make_daa_signature
# =============================================================================

# === Uncomment these lines for debuggung ===

#OLD_SHELL := $(SHELL)
#SHELL = $(warning Building $@$(if $<, (from $<))$(if $?, ($? newer)))$(OLD_SHELL) -x

# ============================================

uname_m := $(shell uname -m)
#$(info uname_m=$(uname_m))

# Set paths and flags for VANET_tpm tests
include ../../makefile-tpm

# Set the library & include paths
AMCL_DIR=../../../../Amcl/cpp_$(uname_m)
CPPFLAGS+=-I$(AMCL_DIR)
#$(info AMCL_DIR=$(AMCL_DIR))

# ============================================

# Fudge on the NexCom box to use new libraries
# !! See why they are not shered libraries (.so) !!
# libraries
#LDLIBS=$(LDLIBS_COMMON) $(AMCL_DIR)/amcl.a /lib/i386-linux-gnu/libdl.so.2 /usr/lib/libcrypto.a /usr/lib/libssl.a

# ============================================

# Set executable names
LD=g++
RM=rm -rf

# build flags
CXXFLAGS=$(CPPFLAGS) $(CXXFLAGS_COMMON) -O3 -pg -g
LDFLAGS= -pg -g $(LDFLAGS_COMMON) 

# libraries
LDLIBS=$(LDLIBS_COMMON) -lssl -lcrypto $(AMCL_DIR)/amcl.a

TARGET=daa_sign_message
SRCS=Daa_sign_message.cpp \
	Create_primary_rsa_key.cpp \
	Byte_buffer.cpp \
	Hex_string.cpp \
	Create_daa_key.cpp \
	Create_ecdsa_key.cpp \
	Tpm_error.cpp \
	Tpm_initialisation.cpp \
	Tss_setup.cpp \
	Tpm_daa.cpp \
	Model_hashes.cpp \
	Tpm2_commit.cpp \
	Flush_context.cpp \
	Hmac.cpp \
	KDF_sha256.cpp \
	Key_name_from_public_data.cpp \
	Make_credential.cpp \
	Make_key_persistent.cpp \
	Marshal_public_data.cpp \
	Number_conversions.cpp \
	Openssl_aes.cpp \
	Openssl_utils.cpp \
	Openssl_bn_utils.cpp \
	Openssl_ec_utils.cpp \
	Openssl_bnp256.cpp \
	Openssl_rsa_public.cpp \
	Openssl_verify.cpp \
	Openssl_ec_map_to_point.cpp \
	Daa_sign.cpp \
	Daa_certify.cpp \
	Daa_quote.cpp \
	Sha256.cpp \
	Get_random_bytes.cpp \
	Tpm_keys.cpp \
	Tpm_utils.cpp \
	Io_utils.cpp \
	Host.cpp \
	Credential_issuer.cpp \
	Display_public_data.cpp \
	Clock_utils.cpp \
	Logging.cpp \
	Daa_credential.cpp \
	G1_utils.cpp \
	G2_utils.cpp \
	Issuer_public_keys.cpp \
	Daa_signatures.cpp \
	Amcl_utils.cpp \
	Amcl_pairings.cpp
	 

$(TARGET): $(SRCS:.cpp=.o)
	$(LD) $(TARGET_ARCH) $(LDFLAGS) $(SRCS:.cpp=.o) $(LDLIBS) -o $@

clean:
	$(RM) *.o .d gmon.out *.bin $(TARGET) *~ 

#------------------------------------------------------------------------------
# Makefile method from:
#     http://make.mad-scientist.net/papers/advanced-auto-dependency-generation/
# This implementation places dependency files into a subdirectory named .d.
DEPDIR := .d

# Unfortunately GCC will not create subdirectories, so this line ensures that
# the DEPDIR directory always exists.
$(shell mkdir -p $(DEPDIR) >/dev/null)

# These are the special GCC-specific flags which convince the compiler to
# generate the dependency file. Full descriptions can be found in the GCC
# manual section Options Controlling the Preprocessor
DEPFLAGS = -MT $@ -MMD -MP -MF $(DEPDIR)/$*.Td

COMPILE.c = $(CC) $(DEPFLAGS) $(CFLAGS) $(CPPFLAGS) $(TARGET_ARCH) -c
COMPILE.cc = $(CXX) $(DEPFLAGS) $(CXXFLAGS) $(CPPFLAGS) $(TARGET_ARCH) -c

# First rename the generated temporary dependency file to the real dependency
# file. We do this in a separate step so that failures during the compilation
# won�t leave a corrupted dependency file. Second touch the object file; it�s
# been reported that some versions of GCC may leave the object file older than
#the dependency file, which causes unnecessary rebuilds.
POSTCOMPILE = @mv -f $(DEPDIR)/$*.Td $(DEPDIR)/$*.d && touch $@

# Delete the built-in rules for building object files from .c files, so that our
# rule is used instead. Do the same for the other built-in rules.
%.o : %.c

# Declare the generated dependency file as a prerequisite of the TARGET, so that
# if it�s missing the TARGET will be rebuilt.
%.o : %.c $(DEPDIR)/%.d
	$(COMPILE.c) $(OUTPUT_OPTION) $<
	$(POSTCOMPILE)

%.o : %.cc
%.o : %.cc $(DEPDIR)/%.d
	$(COMPILE.cc) $(OUTPUT_OPTION) $<
	$(POSTCOMPILE)

%.o : %.cpp
%.o : %.cpp $(DEPDIR)/%.d
	$(COMPILE.cc) $(OUTPUT_OPTION) $<
	$(POSTCOMPILE)

# Create a pattern rule with an empty recipe, so that make won't fail if the
# dependency file doesn�t exist.
$(DEPDIR)/%.d: ;

# Mark the dependency files precious to make, so they won't be automatically
# deleted as intermediate files.
.PRECIOUS: $(DEPDIR)/%.d

# include the dependency files that exist: translate each file listed in SRCS
# into its dependency file. Use wildcard to avoid failing on non-existent files.
include $(wildcard $(patsubst %,$(DEPDIR)/%.d,$(basename $(SRCS))))

#------------------------------------------------------------------------------
