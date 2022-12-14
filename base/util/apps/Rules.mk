# Standard things
sp 		:= $(sp).x
dirstack_$(sp)	:= $(d)
d		:= $(dir)

# Local variables
CF_$(d)		:= -D$(DBMS)

MODEXE_$(d)	:= $(addprefix $(d)/, create_series describe_series delete_series retrieve_dir retrieve_file set_keys set_info show_info show_keys show_series store_dir store_file plot_keys show_coverage addkey timeslot ingestdata set_suretention drms_keyword_update)
MODEXE_NO_SOCK_$(d) := $(addprefix $(d)/, dscp)

MODEXE		:= $(MODEXE) $(MODEXE_$(d)) $(MODEXE_NO_SOCK_$(d))

MODEXE_SOCK_$(d):= $(MODEXE_$(d):%=%_sock)
MODEXE_SOCK	:= $(MODEXE_SOCK) $(MODEXE_SOCK_$(d))

EXE_$(d)	:= $(MODEXE_$(d)) $(MODEXE_NO_SOCK_$(d))
OBJ_$(d)	:= $(EXE_$(d):%=%.o)
DEP_$(d)	:= $(EXE_$(d):%=%.o.d)
CLEAN		:= $(CLEAN) \
		   $(OBJ_$(d)) \
		   $(EXE_$(d)) \
		   $(MODEXE_SOCK_$(d))\
		   $(DEP_$(d))

TGT_BIN	        := $(TGT_BIN) $(EXE_$(d)) $(MODEXE_SOCK_$(d))

S_$(d)		:= $(notdir $(EXE_$(d)) $(MODEXE_SOCK_$(d)))

# Local rules
$(OBJ_$(d)):	CF_TGT := $(CF_$(d))
$(OBJ_$(d)):	$(SRCDIR)/$(d)/Rules.mk

$(MODEXE_$(d)) $(MODEXE_SOCK_$(d)): $(LIBQDECODER)

# Shortcuts
.PHONY:	$(S_$(d))
$(S_$(d)):	%:	$(d)/%

# Standard things
-include	$(DEP_$(d))

d		:= $(dirstack_$(sp))
sp		:= $(basename $(sp))
