# Teleinformatic and Automation Group (GTA, Coppe, UFRJ)
# Author: Guilherme Araujo Thomaz
# Description: generate client and server
# 
# This code was modified following access permissions defined
# by Intel Corporation license, presented as follows
#
# Copyright (C) 2011-2020 Intel Corporation. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
#   * Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#   * Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in
#     the documentation and/or other materials provided with the
#     distribution.
#   * Neither the name of Intel Corporation nor the names of its
#     contributors may be used to endorse or promote products derived
#     from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
#

######## SGX SDK Settings ########

SGX_SDK ?= /opt/intel/sgxsdk
SGX_MODE ?= HW
SGX_ARCH ?= x64
SGX_DEBUG ?= 1
LATENCY ?= 0

HTTPLIB_DIR ?= /home/guiaraujo/cpp-httplib/
export LD_LIBRARY_PATH

ifeq ($(shell getconf LONG_BIT), 32)
	SGX_ARCH := x86
else ifeq ($(findstring -m32, $(CXXFLAGS)), -m32)
	SGX_ARCH := x86
endif

ifeq ($(SGX_ARCH), x86)
	SGX_COMMON_FLAGS := -m32
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x86/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x86/sgx_edger8r
else
	SGX_COMMON_FLAGS := -m64
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib64
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x64/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r
endif

ifeq ($(SGX_DEBUG), 1)
ifeq ($(SGX_PRERELEASE), 1)
$(error Cannot set SGX_DEBUG and SGX_PRERELEASE at the same time!!)
endif
endif

ifeq ($(SGX_DEBUG), 1)
        SGX_COMMON_FLAGS += -O0 -g
else
        SGX_COMMON_FLAGS += -O2
endif

SGX_COMMON_FLAGS += -Wall -Wextra -Winit-self -Wpointer-arith -Wreturn-type \
                    -Waddress -Wsequence-point -Wformat-security \
                    -Wmissing-include-dirs -Wfloat-equal -Wundef -Wshadow \
                    -Wcast-align -Wconversion -Wredundant-decls
SGX_COMMON_CFLAGS := $(SGX_COMMON_FLAGS) -Wjump-misses-init -Wstrict-prototypes -Wunsuffixed-float-constants
SGX_COMMON_CXXFLAGS := $(SGX_COMMON_FLAGS) -Wnon-virtual-dtor -std=c++11

######## Server Settings ########

ifneq ($(SGX_MODE), HW)
	Urts_Library_Name := sgx_urts_sim
else
	Urts_Library_Name := sgx_urts
endif

Server_Cpp_Files := server/server_app/server.cpp \
					server/server_app/server_publish.cpp \
					server/server_app/server_query.cpp \
					server/server_app/register_client.cpp \
					utils/utils.cpp \
					utils/utils_sgx.cpp \
					utils/message_handler.cpp

Server_Include_Paths := -Iutils \
					 	-I$(SGX_SDK)/include \
					 	-I. \
					 	-Iclient \
					 	-Isample_libcrypto \
					 	-Iecp \
					 	-IIAS \
					 	-I$(HTTPLIB_DIR)

Server_C_Flags := -fPIC -Wno-attributes $(Server_Include_Paths) -DLATENCY_MS=$(LATENCY)

# Three configuration modes - Debug, prerelease, release
#   Debug - Macro DEBUG enabled.
#   Prerelease - Macro NDEBUG and EDEBUG enabled.
#   Release - Macro NDEBUG enabled.
ifeq ($(SGX_DEBUG), 1)
        Server_C_Flags += -DDEBUG -UNDEBUG -UEDEBUG
else ifeq ($(SGX_PRERELEASE), 1)
        Server_C_Flags += -DNDEBUG -DEDEBUG -UDEBUG
else
        Server_C_Flags += -DNDEBUG -UEDEBUG -UDEBUG
endif
Server_Cpp_Flags := $(Server_C_Flags)

Server_Link_Flags := -L$(SGX_LIBRARY_PATH) \
					 -L. \
					 -Lserver/server/server_app \
					 -Lutils \
					 -LIAS \
					 -Lsample_libcrypto \
					 -Lecp \
					 -l$(Urts_Library_Name) \
					 -lsgx_ukey_exchange \
					 -lpthread \
					 -lsample_libcrypto \
					 -Wl,-rpath=$(CURDIR)/sample_libcrypto \
					 -Wl,-rpath=$(CURDIR) 

ifneq ($(SGX_MODE), HW)
	Server_Link_Flags += -lsgx_epid_sim -lsgx_quote_ex_sim
else
	Server_Link_Flags += -lsgx_epid -lsgx_quote_ex
endif

Server_Cpp_Objects := $(Server_Cpp_Files:.cpp=.o)

Server_Name := Server

######## Client Settings ########

Client_Cpp_Files := client/cli.cpp \
					client/request_register.cpp \
					client/initialize_communication.cpp \
					client/client_publish.cpp \
					client/client_query.cpp \
					client/encryption.cpp \
					ecp/ecp.cpp \
					IAS/ias_simulation.cpp \
					utils/utils.cpp \
					utils/message_handler.cpp

Client_Include_Paths := -I. \
						-Iclient \
						-Iecp \
						-IIAS \
						-Iutils \
						-Isample_libcrypto \
						-I$(SGX_SDK)/include \
					 	-I$(HTTPLIB_DIR) 

Client_C_Flags := -shared -fPIC -Wno-attributes -I$(SGX_SDK)/include $(Client_Include_Paths) -DLATENCY_MS=$(LATENCY)

Client_Cpp_Flags := $(Client_C_Flags)

Client_Link_Flags := -L$(SGX_LIBRARY_PATH) \
					 -L. \
					 -lsample_libcrypto \
					 -Lsample_libcrypto \
					 -pthread \
					 -l$(Urts_Library_Name) \
					 -lpthread \
					 -Wl,-rpath=$(CURDIR)/sample_libcrypto \
					 -Wl,-rpath=$(CURDIR) \
					 -Lutils \
					 -Lecp

Client_Cpp_Objects := $(Client_Cpp_Files:.cpp=.o)

Client_Name := Client

######## Enclave Settings ########

ifneq ($(SGX_MODE), HW)
	Trts_Library_Name := sgx_trts_sim
	Service_Library_Name := sgx_tservice_sim
else
	Trts_Library_Name := sgx_trts
	Service_Library_Name := sgx_tservice
endif
Crypto_Library_Name := sgx_tcrypto

Enclave_Cpp_Files := server/server_enclave/server_enclave.cpp
Enclave_Include_Paths := -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc -I$(SGX_SDK)/include/libcxx

Enclave_C_Flags := $(Enclave_Include_Paths) -nostdinc -fvisibility=hidden -fpie -ffunction-sections -fdata-sections
CC_BELOW_4_9 := $(shell expr "`$(CC) -dumpversion`" \< "4.9")
ifeq ($(CC_BELOW_4_9), 1)
	Enclave_C_Flags += -fstack-protector
else
	Enclave_C_Flags += -fstack-protector-strong
endif
Enclave_Cpp_Flags := $(Enclave_C_Flags) -nostdinc++

# Enable the security flags
Enclave_Security_Link_Flags := -Wl,-z,relro,-z,now,-z,noexecstack

# To generate a proper enclave, it is recommended to follow below guideline to link the trusted libraries:
#    1. Link sgx_trts with the `--whole-archive' and `--no-whole-archive' options,
#       so that the whole content of trts is included in the enclave.
#    2. For other libraries, you just need to pull the required symbols.
#       Use `--start-group' and `--end-group' to link these libraries.
# Do NOT move the libraries linked with `--start-group' and `--end-group' within `--whole-archive' and `--no-whole-archive' options.
# Otherwise, you may get some undesirable errors.
Enclave_Link_Flags := $(Enclave_Security_Link_Flags) \
    -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L$(SGX_LIBRARY_PATH) \
	-Wl,--whole-archive -l$(Trts_Library_Name) -Wl,--no-whole-archive \
	-Wl,--start-group -lsgx_tstdc -lsgx_tcxx -lsgx_tkey_exchange -l$(Crypto_Library_Name) -l$(Service_Library_Name) -Wl,--end-group \
	-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
	-Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
	-Wl,--defsym,__ImageBase=0 -Wl,--gc-sections   \
	-Wl,--version-script=server/server_enclave/server_enclave.lds 

Enclave_Cpp_Objects := $(Enclave_Cpp_Files:.cpp=.o)

Enclave_Name := server_enclave.so
Signed_Enclave_Name := server_enclave.signed.so
Enclave_Config_File := server/server_enclave/server_enclave.config.xml

ifeq ($(SGX_MODE), HW)
ifeq ($(SGX_DEBUG), 1)
	Build_Mode = HW_DEBUG
else ifeq ($(SGX_PRERELEASE), 1)
	Build_Mode = HW_PRERELEASE
else
	Build_Mode = HW_RELEASE
endif
else
ifeq ($(SGX_DEBUG), 1)
	Build_Mode = SIM_DEBUG
else ifeq ($(SGX_PRERELEASE), 1)
	Build_Mode = SIM_PRERELEASE
else
	Build_Mode = SIM_RELEASE
endif
endif

.PHONY: all run target 
all: .config_$(Build_Mode)_$(SGX_ARCH)
	@$(MAKE) target

ifeq ($(Build_Mode), HW_RELEASE)
target: $(Client_Name) $(Server_Name) $(Enclave_Name) 
	@echo "The project has been built in release hardware mode."
	@echo "Please sign the $(Enclave_Name) first with your signing key before you run the $(App_Name) to launch and access the enclave."
	@echo "To sign the enclave use the command:"
	@echo "   $(SGX_ENCLAVE_SIGNER) sign -key <your key> -enclave $(Enclave_Name) -out <$(Signed_Enclave_Name)> -config $(Enclave_Config_File)"
	@echo "You can also sign the enclave using an external signing tool."
	@echo "To build the project in simulation mode set SGX_MODE=SIM. To build the project in prerelease mode set SGX_PRERELEASE=1 and SGX_MODE=HW."
else
target: $(Client_Name) $(Server_Name) $(Signed_Enclave_Name)
ifeq ($(Build_Mode), HW_DEBUG)
	@echo "The project has been built in debug hardware mode."
else ifeq ($(Build_Mode), SIM_DEBUG)
	@echo "The project has been built in debug simulation mode."
else ifeq ($(Build_Mode), HW_PRERELEASE)
	@echo "The project has been built in pre-release hardware mode."
else ifeq ($(Build_Mode), SIM_PRERELEASE)
	@echo "The project has been built in pre-release simulation mode."
else
	@echo "The project has been built in release simulation mode."
endif
endif

run: all
ifneq ($(Build_Mode), HW_RELEASE)
	@$(CURDIR)/$(Client_Name) 	
	@$(CURDIR)/$(Server_Name) 	
	@$(CURDIR)/$(Enclave_Name) 	
	@echo "RUN  => $(Client_Name) $(Server_Name) [$(SGX_MODE)|$(SGX_ARCH), OK]"
endif

.config_$(Build_Mode)_$(SGX_ARCH):
	@rm -f .config_* \
	$(Server_Name) \
	$(Enclave_Name) \
	$(Signed_Enclave_Name) \
	$(Server_Cpp_Objects) \
	server/server_app/server_enclave_u.* \
	$(Enclave_Cpp_Objects) \
	server/server_enclave/server_enclave_t.* \
	Client.* \
	$(Client_Cpp_Objects)
	@touch .config_$(Build_Mode)_$(SGX_ARCH)

######## Auxiliary Objects ########

utils/%.o: utils/%.cpp 
	@$(CXX) $(SGX_COMMON_CXXFLAGS) $(Server_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

ecp/%.o: ecp/%.cpp utils/utils.cpp
	@$(CXX) $(SGX_COMMON_CXXFLAGS) $(Client_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

IAS/%.o: IAS/%.cpp ecp/ecp.cpp
	@$(CXX) $(SGX_COMMON_CXXFLAGS) $(Client_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

######## Server Objects ########

server/server_app/server_enclave_u.h: $(SGX_EDGER8R) server/server_enclave/server_enclave.edl
	@cd server/server_app && $(SGX_EDGER8R) --untrusted ../server_enclave/server_enclave.edl --search-path ../server_enclave --search-path $(SGX_SDK)/include
	@echo "GEN  =>  $@"

server/server_app/server_enclave_u.c: server/server_app/server_enclave_u.h

server/server_app/server_enclave_u.o: server/server_app/server_enclave_u.c
	@$(CC) $(SGX_COMMON_CFLAGS) $(Server_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

server/server_app/%.o: server/server_app/%.cpp server/server_app/server_enclave_u.h utils/utils.cpp utils/utils_sgx.cpp utils/message_handler.cpp
	@$(CXX) $(SGX_COMMON_CXXFLAGS) $(Server_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"
 
$(Server_Name): server/server_app/server_enclave_u.o $(Server_Cpp_Objects) 
	@$(CXX) $^ -o $@ $(Server_Link_Flags)
	@echo "LINK =>  $@"

######## Client Objects ########

client/%.o: client/%.cpp ecp/ecp.cpp IAS/ias_simulation.cpp
	@$(CXX) $(SGX_COMMON_CXXFLAGS) $(Client_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

$(Client_Name): $(Client_Cpp_Objects)
	@$(CXX) $^ -o $@ $(Client_Link_Flags)
	@echo "LINK =>  $@"

######## Enclave Objects ########

server/server_enclave/server_enclave_t.h: $(SGX_EDGER8R) server/server_enclave/server_enclave.edl
	@cd server/server_enclave && $(SGX_EDGER8R) --trusted ../server_enclave/server_enclave.edl --search-path ../server_enclave --search-path $(SGX_SDK)/include
	@echo "GEN  =>  $@"

server/server_enclave/server_enclave_t.c: server/server_enclave/server_enclave_t.h

server/server_enclave/server_enclave_t.o: server/server_enclave/server_enclave_t.c
	@$(CC) $(SGX_COMMON_CFLAGS) $(Enclave_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

server/server_enclave/%.o: server/server_enclave/%.cpp server/server_enclave/server_enclave_t.h
	@$(CXX) $(SGX_COMMON_CXXFLAGS) $(Enclave_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

$(Enclave_Name): server/server_enclave/server_enclave_t.o $(Enclave_Cpp_Objects)
	@$(CXX) $^ -o $@ $(Enclave_Link_Flags)
	@echo "LINK =>  $@"

$(Signed_Enclave_Name): $(Enclave_Name)
	@$(SGX_ENCLAVE_SIGNER) sign -key server/server_enclave/server_enclave_private_test.pem -enclave $(Enclave_Name) -out $@ -config $(Enclave_Config_File)
	@echo "SIGN =>  $@"

.PHONY: clean

clean:
	@rm -f .config_* \
	$(Server_Name) \
	$(Client_Name) \
	$(Enclave_Name) \
	$(Signed_Enclave_Name) \
	$(Server_Cpp_Objects) \
	$(Client_Cpp_Objects) \
	$(Enclave_Cpp_Objects) \
	server/server_app/server_enclave_u.* \
	server/server_enclave/server_enclave_t.* 
