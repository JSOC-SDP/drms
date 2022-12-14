# Standard things
sp 		:= $(sp).x
dirstack_$(sp)	:= $(d)
d		:= $(dir)

# Subdirectories, in random order. Directory-specific rules are optional here.
# Remove Perl SWIG from build.
#ifneq ($(JSOC_MACHINE), mac_osx_ppc)
#	ifneq ($(JSOC_MACHINE), mac_osx_ia32)
#		dir	:= $(d)/perl
#		-include		$(SRCDIR)/$(dir)/Rules.mk
#	endif
#endif

# Local variables
LIBSUMSAPI	:= $(d)/libsumsapi.a

USE_RPC :=

ifneq ($(SUMS_USEMTSUMS),1)
	USE_RPC := yes
endif

ifneq ($(SUMS_USEMTSUMS_ALL),1)
	USE_RPC := yes
endif

OBJ_$(d)	:=

ifdef USE_RPC
	OBJ_$(d)	:= $(addprefix $(d)/, key.o keyU.o printkey.o soi_error.o sum_export.o sumopened.o sum_xdr.o)
endif

OBJ_SUMOPEN_$(d)	:= $(addprefix $(d)/, sum_open.o)

CF_TGT_$(d)     := -O0 -Wno-parentheses -fno-strict-aliasing
ADD_TGT_$(d) := -DSUMT120 -DSUMNOAO

ifeq ($(HOST),dcs0.jsoc.Stanford.EDU)
        ADD_TGT_$(d) := -DSUMDC -DDCS0
endif
ifeq ($(HOST),dcs1.jsoc.Stanford.EDU)
        ADD_TGT_$(d) := -DSUMDC -DDCS1
endif
ifeq ($(HOST),dcs2.jsoc.Stanford.EDU)
        ADD_TGT_$(d) := -DSUMDC -DDCS2
endif
ifeq ($(HOST),dcs3.jsoc.Stanford.EDU)
        ADD_TGT_$(d) := -DSUMDC -DDCS3
endif
ifeq ($(HOST),d00.Stanford.EDU)
        ADD_TGT_$(d) := -DSUMT120
endif
ifeq ($(HOST),d02.Stanford.EDU)
        ADD_TGT_$(d) := -DSUMT950
endif
CF_TGT_$(d) := $(CF_TGT_$(d)) $(ADD_TGT_$(d))

LIBSUMSAPI_OBJ	:= $(OBJ_$(d)) $(OBJ_SUMOPEN_$(d))

DEP_$(d)	:= $(OBJ_$(d):%=%.d) $(OBJ_SUMOPEN_$(d):%=%.d)

CLEAN		:= $(CLEAN) $(OBJ_$(d)) $(OBJ_SUMOPEN_$(d)) $(LIBSUMSAPI) $(DEP_$(d))

TGT_LIB		:= $(TGT_LIB) $(LIBSUMSAPI)

S_$(d)		:= $(notdir $(LIBSUMSAPI))

# Local rules
$(OBJ_$(d)):   $(SRCDIR)/$(d)/Rules.mk
$(OBJ_SUMOPEN_$(d)):   $(SRCDIR)/$(d)/Rules.mk

$(OBJ_$(d)):            CF_TGT := $(CF_TGT_$(d))
$(OBJ_SUMOPEN_$(d)):    CF_TGT := -I$(LIBCJSONH) $(CF_TGT_$(d)) -Wstrict-prototypes
$(OBJ_SUMOPEN_$(d)):    $(LIBCJSON)

##endif
$(LIBSUMSAPI):	$(LIBSUMSAPI_OBJ)
		$(ARCHIVE)
		$(SLLIB)

# Shortcuts
.PHONY:	$(S_$(d))
$(S_$(d)):	%:	$(d)/%

# Standard things
-include	$(DEP_$(d))

d		:= $(dirstack_$(sp))
sp		:= $(basename $(sp))
