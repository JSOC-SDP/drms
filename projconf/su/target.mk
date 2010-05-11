$(PROJOBJDIR):
	+@[ -d $@ ] || mkdir -p $@
	+@[ -d $@/libs/astro ] || mkdir -p $@/libs/astro
	+@[ -d $@/libs/dr ] || mkdir -p $@/libs/dr
	+@[ -d $@/libs/dsputil ] || mkdir -p $@/libs/dsputil
	+@[ -d $@/libs/gapfiller ] || mkdir -p $@/libs/gapfiller
	+@[ -d $@/libs/interpolate ] || mkdir -p $@/libs/interpolate
	+@[ -d $@/libs/json ] || mkdir -p $@/libs/json
	+@[ -d $@/datacapture/apps ] || mkdir -p $@/datacapture/apps
	+@[ -d $@/dsdsmigr/apps ] || mkdir -p $@/dsdsmigr/apps
	+@[ -d $@/util/apps ] || mkdir -p $@/util/apps
	+@[ -d $@/lev0/apps ] || mkdir -p $@/lev0/apps
	+@[ -d $@/lev1/apps ] || mkdir -p $@/lev1/apps
	+@[ -d $@/jpe/apps ] || mkdir -p $@/jpe/apps
	+@[ -d $@/lev1_aia/apps ] || mkdir -p $@/lev1_aia/apps
	+@[ -d $@/lev1_hmi/apps ] || mkdir -p $@/lev1_hmi/apps
	+@[ -d $@/globalhs/apps/ ] || mkdir -p $@/globalhs/apps
	+@[ -d $@/flatfield/apps ] || mkdir -p $@/flatfield/apps
	+@[ -d $@/flatfield/libs/flatfieldlib ] || mkdir -p $@/flatfield/libs/flatfieldlib
	+@[ -d $@/globalhs/apps/src/ ] || mkdir -p $@/globalhs/apps/src
	+@[ -d $@/rings/apps/ ] || mkdir -p $@/rings/apps
	+@[ -d $@/mag/apps/ ] || mkdir -p $@/mag/apps
	+@[ -d $@/mag/pfss/apps ] || mkdir -p $@/mag/pfss/apps

