# SPDX-License-Identifier: LGPL-2.1

include $(src)/scripts/utils.mk

TARGETS :=
TARGETS += task-eval

sdir := $(obj)/bin

CFLAGS += `pkg-config --cflags libtracecmd`
LIBRARY_LIBS += `pkg-config --libs libtracecmd`

TARGETS := $(patsubst %,$(sdir)/%,$(TARGETS))

all: $(TARGETS)

$(sdir):
	@mkdir -p $(sdir)

$(TARGETS): $(sdir) $(LIBTRACEEVAL_STATIC)

$(sdir)/%: $(bdir)/%.o
	$(call do_sample_build,$@,$<)

$(bdir)/%.o: $(bdir)/%.c
	$(Q)$(CC) -o $@ -c $< $(CFLAGS) $(INCLUDES)

clean:
	$(Q)$(call do_clean,$(sdir)/*)
