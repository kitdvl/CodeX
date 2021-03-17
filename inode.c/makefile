################################################################################
#                                                                              #
#                                                                              #
#                                   PART I                                     #
#                                                                              #
#                                                                              #
################################################################################
################################################################################
#                                                                              #
#                                  COMMON                                      #
#                                                                              #
################################################################################
VERSION         = 2.0.0
RELEASE         = yes
LINUX           = yes
LICENSE        ?= no

CROSS_COMPILE  ?= no

#ARCH_TYPE     ?= WIN32
##ARCH_TYPE     = WINCE
ARCH_TYPE      ?= LINUX32
#ARCH_TYPE     ?= LINUX_ARM
#ARCH_TYPE     ?= LINUX_ARMHF

OUTPUT_TYPE ?= STATIC
#OUTPUT_TYPE ?= SHARED
################################################################################
#                                                                              #
#                                                                              #
#                                 PART II                                      #
#                                                                              #
#                                                                              #
################################################################################
################################################################################
#                                                                              #
#                                 COMPILER                                     #
#                                                                              #
################################################################################
ifeq ($(ARCH_TYPE), x32)
TOOLCHAIN_PATH = /usr
endif
ifeq ($(ARCH_TYPE), x64)
TOOLCHAIN_PATH = /usr
endif
ifeq ($(ARCH_TYPE), a32)
TOOLCHAIN_PATH = /usr/local/ext/toolchain/x64/arm-linux-gnueabihf/
endif
ifeq ($(ARCH_TYPE), a64)
TOOLCHAIN_PATH = /usr/local/ext/toolchain/x64/aarch64-linux-gnu
endif

TOOLCHAIN_BIN  = $(TOOLCHAIN_PATH)/bin/

SYSTEM_ROOT = .

ifdef LINUX
ifeq ($(CROSS_COMPILE), yes)
ifeq ($(ARCH_TYPE), a32)
XCOMPILE- = arm-linux-gnueabihf-
XTARGET   = a32
endif
ifeq ($(ARCH_TYPE), a64)
XCOMPILE- = aarch64-linux-gnu-
XTARGET   = a64
endif
else
ifeq ($(ARCH_TYPE), x32)
XTARGET   = x32
endif
ifeq ($(ARCH_TYPE), x64)
XTARGET   = x64
endif
TOOLCHAIN_BIN  = 
endif
endif


ifdef LINUX
CC     = $(TOOLCHAIN_BIN)$(XCOMPILE-)gcc
else
CC     = cl.exe
endif
AR     = $(TOOLCHAIN_BIN)$(XCOMPILE-)ar
AR_OPT = rcs
RANLIB = $(TOOLCHAIN_BIN)$(XCOMPILE-)ranlib

TOOLCHAIN_LIB = $(TOOLCHAIN_PATH)/lib
ifeq ($(ARCH_TYPE), x64)
TOOLCHAIN_LIB = $(TOOLCHAIN_PATH)/lib64
endif


################################################################################
#                                                                              #
#                                  SUFFIX                                      #
#                                                                              #
################################################################################

C_SUFFIX = .c

ifdef LINUX
O_SUFFIX = .o
else
O_SUFFIX = .obj
endif

ifeq ($(OUTPUT_TYPE), SHARED)
ifdef LINUX
LIB_SUFFIX = .so
else
LIB_SUFFIX = .dll
endif
endif

ifeq ($(OUTPUT_TYPE), STATIC)
ifdef LINUX
LIB_SUFFIX = .a
else
LIB_SUFFIX = .lib
endif
endif


################################################################################
#                                                                              #
#                              COMPILE OPTIONS                                 #
#                                                                              #
################################################################################
ifdef RELEASE
COPT = -O2 -no-integrated-cpp
else
COPT = -g -ggdb -W -Wall -no-integrated-cpp -static-libgcc
endif

ifeq ($(ARCH_TYPE), x32)
COPT += -Dx32
OPT += -m32
endif

ifeq ($(ARCH_TYPE), x64)
COPT += -Dx64
OPT += -m64
endif

ifeq ($(ARCH_TYPE), a32)
COPT += -Da32
xCOPT += -mbig-endian
endif

ifeq ($(ARCH_TYPE), a64)
COPT += -Da64
xCOPT += -mbig-endian
endif

ifdef LINUX
LIBS = -lnsl -lrt
else
LIBS = -lsocket -lnsl -lrt
endif

CPPLIBS = 

RM = rm -rf
CP = cp -rf
MV = mv

#GENLIB = -lm
#CODECLIB = -lfaad -lfaac


COPT += -D__HTTP__=1
COPT += -D__MIME__=1
COPT += -D__SHM__=0
COPT += -D__NIC__=0
COPT += -D__CGI__=0
COPT += -D__XML__=0
COPT += -D__SERIAL__=1
COPT += -D__SOCKET__=1
COPT += -D__PACKET__=1
COPT += -D__DBC__=0
COPT += -D__SHA1__=1
COPT += -D__LIST__=1
COPT += -D__QUEUE__=0
COPT += -D__STACK__=0
COPT += -D__SYSQUEUE__=0
COPT += -D__STATIC_LIB__=1


################################################################################
#                                                                              #
#                                  DEFINITION                                  #
#                                                                              #
################################################################################
OS_TYPE  = -DLINUX
OS_TYPE  += -DBSD_SOCKET
OS_TYPE  += -DPOLLING
#OS_TYPE  += -DRTS
#OS_TYPE  += -DCONSOLE_PRINT
ifeq ($(OUTPUT_TYPE), SHARED)
OS_TYPE  += -DSHARED_LIB
endif
ifeq ($(OUTPUT_TYPE), STATIC)
OS_TYPE  += -DSTATIC_LIB
COPT += -static
endif
ifeq ($(ARCH_TYPE), x32)
OS_TYPE  += -DPACKED
endif

OS  = $(OS_TYPE)

PLATFORM_TYPE = $(ARCH_TYPE)

################################################################################
#                                                                              #
#                                 DIRECTORIES                                  #
#                                                                              #
################################################################################
INC = i
SRC = i
LIB = lib
OBJ = obj
BIN = bin
OUT = out
COM = coms

#OSS_INC = -I/usr/lib/oss/include
#CODEC_INC = -I/usr/local/AAC/include
#CODEC_LIB = -L/usr/local/AAC/lib


################################################################################
################################################################################
#############################                 ##################################
#############################                 ##################################
#############################                 ##################################
#############################                 ##################################
##########################                       ###############################
###########################                     ################################
#############################                 ##################################
###############################             ####################################
#################################         ######################################
###################################     ########################################
##################################### ##########################################
################################################################################

################################################################################
#                                                                              #
#                                                                              #
#                            DIRECTORY INFORMATION                             #
#                                                                              #
#                                                                              #
################################################################################
OUTPUT_NAME = $(notdir $(shell pwd))
_NAME = $(OUTPUT_NAME)

TARGET_PATH = $(OUT)
TARGET_OBJ = $(TARGET_PATH)/$(_NAME).$(OBJ).$(XTARGET)
TARGET_NAME = $(OUTPUT_NAME)
OUTPUT = $(TARGET_NAME).$(XTARGET)

INC  = -I.
INC += -Ii

#                                                                              #
#                                                                              #
################################################################################
##################################### ##########################################
###################################     ########################################
#################################         ######################################
###############################             ####################################
#############################                 ##################################
###########################                     ################################
##########################                       ###############################
#############################                 ##################################
#############################                 ##################################
#############################                 ##################################
#############################                 ##################################
################################################################################
################################################################################

################################################################################
#                                                                              #
#                            SOURCE CONVERTING                                 #
#                                                                              #
################################################################################
C_SRCS  = $(foreach dir, $(SRC), $(wildcard $(dir)/*$(C_SUFFIX)))
CXX_SRCS = $(foreach dir, $(SRC), $(wildcard $(dir)/*$(CXX_SUFFIX)))
OBJS = $(foreach dir, . $(TARGET_OBJ), $(wildcard $(dir)/*$(O_SUFFIX)))
OXXS = $(foreach dir, . $(TARGET_OBJ), $(wildcard $(dir)/*$(OXX_SUFFIX)))


################################################################################
#                                                                              #
#                             COMPILE OBJECT                                   #
#                                                                              #
################################################################################
%$(O_SUFFIX) :
	@echo "################################################################################"
	@echo "#  compile "$@
	@echo "################################################################################"
	$(RM) $(TARGET_OBJ)/$@;
	$(CC) $(INC) $(OS) $(COPT) $(OPT) -static \
	-o $(addprefix $(TARGET_OBJ)/, $(notdir $@)) \
	-fPIC -c $(subst $(O_SUFFIX),$(C_SUFFIX), $@);

%$(OXX_SUFFIX) :
	@echo "################################################################################"
	@echo "#  compile CXX "$@
	@echo "################################################################################"
	$(CXX) $(INC) $(OS) $(COPT) -static \
	-o $(addprefix $(TARGET_OBJ)/, $(notdir $@)) \
	-fpermissive \
	-fPIC -c $(subst $(OXX_SUFFIX),$(CXX_SUFFIX), $@);

################################################################################
#                                                                              #
#                                    BUILD                                     #
#                                                                              #
################################################################################
% :
ifeq ($(OUTPUT_TYPE), SHARED)
	@echo "################################################################################"
	@echo "#  shared object "$@$(LIB_SUFFIX)
	@echo "################################################################################"
	$(CC) -fPIC -shared $(OPT) -o $(TARGET_PATH)/$@$(LIB_SUFFIX) $(OBJS);
endif
ifeq ($(OUTPUT_TYPE), STATIC)
	@echo "################################################################################"
	@echo "#  archive "$@$(LIB_SUFFIX)
	@echo "################################################################################"
	$(AR) $(AR_OPT) $(TARGET_PATH)/$@$(LIB_SUFFIX) $(OBJS);
	$(RANLIB) $(TARGET_PATH)/$@$(LIB_SUFFIX);
endif
ifeq ($(OUTPUT_TYPE), EXECUTE)
	@echo "################################################################################"
	@echo "#  execute "$@
	@echo "################################################################################"
	$(CC) -o $(TARGET_PATH)/$@ $(OBJS) \
		-DLINUX \
		$(INC) $(OS) $(COPT) $(OPT) $(GENLIB) \
    $(exLIBS)
endif

all:
	@echo "################################################################################"
	@echo "#"
	@echo "#"
	@echo "#  Build Start "$(TARGET_NAME)"  ("$(ARCH_TYPE)")"
	@echo "#"
	@echo "#"
	@echo "################################################################################"
	make $(addsuffix $(O_SUFFIX),$(basename $(C_SRCS)));
	@echo "################################################################################"
	@echo "#"
	@echo "#"
	@echo "#  link "$(OUTPUT)
	@echo "#"
	@echo "#"
	@echo "################################################################################"
	make $(OUTPUT);
	@echo "################################################################################"
	@echo "#"
	@echo "#"
	@echo "#  Build Complete "$(TARGET_NAME)"  ("$(ARCH_TYPE)")"
	@echo "#"
	@echo "#"
	@echo "################################################################################"
	@echo " "
	@echo " "
	@echo " "
	@echo " "
	@echo " "
	@echo " "
	@echo " "
	@echo " "
	@echo " "
	@echo " "

################################################################################
#                                                                              #
#                                 BUILD PREFIX                                 #
#                                                                              #
################################################################################
dir:
	mkdir -p $(TARGET_PATH);
	mkdir -p $(TARGET_OBJ);

clean :
	$(RM)  *.o core;
	$(RM)  $(TARGET_OBJ)/*.o;
ifdef VERSION_OUT
	$(RM)  $(TARGET_PATH)/*$(LIB_SUFFIX).$(VERSION);
endif
	$(RM)  $(TARGET_PATH)/$(TARGET_NAME)
ifdef DEPLOY_DIR
	$(RM)  $(DEPLOY_DIR)/core;
	$(RM)  $(DEPLOY_DIR)/$(BIN)/*;
endif

distclean:
	$(RM)  *.o core;
	$(RM)  $(TARGET_PATH)/*;
	$(RM)  $(TARGET_OBJ)/*.o;
	$(RM)  $(TARGET_PATH)/*.$(LIB_SUFFIX);
