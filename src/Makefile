# SPDX-License-Identifier: MIT

include $(src)/scripts/utils.mk

OBJS =
OBJS += histograms.o
OBJS += delta.o
OBJS += hash.o

OBJS := $(OBJS:%.o=$(bdir)/%.o)

LIBS = -lm

$(LIBRARY_STATIC): $(OBJS)
	$(Q)$(call do_build_static_lib)

$(LIBRARY_SHARED): $(OBJS)
	$(Q)$(call do_compile_shared_library,$(notdir $(LIBRARY_SHARED_VERSION)))

$(LIBRARY_SHARED_VERSION): $(LIBRARY_SHARED)
	@ln -sf $(<F) $@

$(LIBRARY_SHARED_SO): $(LIBRARY_SHARED_VERSION)
	@ln -sf $(<F) $@

$(LIBRARY_SO): $(LIBRARY_SHARED_SO)

$(bdir)/%.o: %.c
	$(Q)$(call do_fpic_compile)

$(OBJS): | $(bdir)

clean:
	$(Q)$(call do_clean,$(OBJS) .*.d)

-include .*.d

.PHONY: $(LIBRARY_SHARED_SO) $(LIBRARY_STATIC)
