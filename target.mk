# This is used to jump from a source directory to a target directory.

.SUFFIXES:


# Find the target directory(ies).
#
ifndef JSOC_MACHINE
  JSOC_MACHINE := $(shell build/jsoc_machine.csh)
  export JSOC_MACHINE
endif

ifeq ($(MACH),)
MACH = $(JSOC_MACHINE)
endif

OBJDIR 		:= _$(MACH)
PROJOBJDIR	:= $(OBJDIR)/proj

all:    $(PROJOBJDIR) $(OBJDIR)

# Define the rules to build in the target subdirectories.
#
MAKETARGET = $(MAKE) --no-print-directory -C $@ -f $(WORKINGDIR)/Makefile \
		SRCDIR=$(WORKINGDIR) $(MAKECMDGOALS)

.PHONY: $(PROJOBJDIR) $(OBJDIR)

$(PROJOBJDIR)::
	+@[ -d $@ ] || mkdir -p $@

# Create the project-specific directories too, if they exist.
# This supplementary target.mk file is built by the configure script, using either
# configsdp.txt (for a JSOC-SDP checkout) or a custom configuration file as input.
PATH_FILES := $(shell find $(WORKINGDIR)/proj -name paths.mk -printf "%p ")
-include $(PATH_FILES)

$(OBJDIR):
	+@[ -d bin/$(MACH) ] || mkdir -p bin/$(MACH)
	+@[ -d lib/$(MACH) ] || mkdir -p lib/$(MACH)
	+@[ -d $@ ] || mkdir -p $@
	+@[ -d $@/base/drms/apps ] || mkdir -p $@/base/drms/apps
	+@[ -d $@/base/drms/apps/test ] || mkdir -p $@/base/drms/apps/test
	+@[ -d $@/base/drms/libs/api/client ] || mkdir -p $@/base/drms/libs/api/client
	+@[ -d $@/base/drms/libs/api/server ] || mkdir -p $@/base/drms/libs/api/server
	+@[ -d $@/base/drms/libs/api/server-fpic ] || mkdir -p $@/base/drms/libs/api/server-fpic
	+@[ -d $@/base/drms/libs/main/c ] || mkdir -p $@/base/drms/libs/main/c
	+@[ -d $@/base/drms/libs/main/f ] || mkdir -p $@/base/drms/libs/main/f
	+@[ -d $@/base/drms/libs/main/idl ] || mkdir -p $@/base/drms/libs/main/idl
	+@[ -d $@/base/drms/libs/meta ] || mkdir -p $@/base/drms/libs/meta
	+@[ -d $@/base/drms/libs/py ] || mkdir -p $@/base/drms/libs/py
	+@[ -d $@/base/export/apps ] || mkdir -p $@/base/export/apps
	+@[ -d $@/base/export/libs/util ] || mkdir -p $@/base/export/libs/util
	+@[ -d $@/base/export/libs/exportDRMS ] || mkdir -p $@/base/export/libs/exportDRMS
	+@[ -d $@/base/libs/cjson ] || mkdir -p $@/base/libs/cjson
	+@[ -d $@/base/libs/cmdparams/test ] || mkdir -p $@/base/libs/cmdparams/test
	+@[ -d $@/base/libs/db/client ] || mkdir -p $@/base/libs/db/client
	+@[ -d $@/base/libs/db/server ] || mkdir -p $@/base/libs/db/server
	+@[ -d $@/base/libs/db/server-fpic ] || mkdir -p $@/base/libs/db/server-fpic
	+@[ -d $@/base/libs/defs/fpic ] || mkdir -p $@/base/libs/defs/fpic
	+@[ -d $@/base/libs/dstruct/fpic ] || mkdir -p $@/base/libs/dstruct/fpic
	+@[ -d $@/base/libs/json ] || mkdir -p $@/base/libs/json
	+@[ -d $@/base/libs/jsmn ] || mkdir -p $@/base/libs/jsmn
	+@[ -d $@/base/libs/inthandles ] || mkdir -p $@/base/libs/inthandles
	+@[ -d $@/base/libs/qdecoder/md5 ] || mkdir -p $@/base/libs/qdecoder/md5
	+@[ -d $@/base/libs/threads/fpic ] || mkdir -p $@/base/libs/threads/fpic
	+@[ -d $@/base/libs/timeio/fpic ] || mkdir -p $@/base/libs/timeio/fpic
	+@[ -d $@/base/libs/misc/fpic ] || mkdir -p $@/base/libs/misc/fpic
	+@[ -d $@/base/libs/fitsrw/fpic ] || mkdir -p $@/base/libs/fitsrw/fpic
	+@[ -d $@/base/libs/errlog ] || mkdir -p $@/base/libs/errlog
	+@[ -d $@/base/local/libs/dsds ] || mkdir -p $@/base/local/libs/dsds
	+@[ -d $@/base/local/libs/soi ] || mkdir -p $@/base/local/libs/soi
	+@[ -d $@/base/sums/apps ] || mkdir -p $@/base/sums/apps
	+@[ -d $@/base/sums/libs/api ] || mkdir -p $@/base/sums/libs/api
	+@[ -d $@/base/sums/libs/pg ] || mkdir -p $@/base/sums/libs/pg
	+@[ -d $@/base/util/apps ] || mkdir -p $@/base/util/apps
	+@$(MAKETARGET)

# These rules keep make from trying to use the match-anything rule below to
# rebuild the makefiles--ouch!  Obviously, if you don't follow my convention
# of using a `.mk' suffix on all non-standard makefiles you'll need to change
# the pattern rule.
#
Makefile : ;
%.mk :: ;


# Anything we don't know how to build will use this rule.  The command is a
# do-nothing command, but the prerequisites ensure that the appropriate
# recursive invocations of make will occur.
#
% :: $(PROJOBJDIR) $(OBJDIR) ; :


# The clean rule is best handled from the source directory: since we're
# rigorous about keeping the target directories containing only target files
# and the source directory containing only source files, `clean' is as trivial
# as removing the target directories!
#
.PHONY: clean
clean:
	rm -rf $(OBJDIR); rm -rf bin/$(MACH); rm -rf lib/$(MACH)
