# SPDX-License-Identifier: MIT
# libtraceeval version
TE_VERSION = 0
TE_PATCHLEVEL = 0
TE_EXTRAVERSION = dev
TRACEEVAL_VERSION = $(TE_VERSION).$(TE_PATCHLEVEL).$(TE_EXTRAVERSION)

export TE_VERSION
export TE_PATCHLEVEL
export TE_EXTRAVERSION
export TRACEEVAL_VERSION

VERSION = $(TE_VERSION)
PATCHLEVEL = $(TE_PATCHLEVEL)
EXTRAVERSION = $(TE_EXTRAVERSION)

LIBRARY_VERSION = $(TRACEEVAL_VERSION)

LIB_NAME = traceeval
LIBRARY_NAME = libtraceeval
LIBRARY_SO = $(LIBRARY_NAME).so
LIBRARY_A = $(LIBRARY_NAME).a

export LIBRARY_VERSION LIBRARY_NAME LIBRARY_SO LIBRARY_A

# taken from trace-cmd
MAKEFLAGS += --no-print-directory

# Makefiles suck: This macro sets a default value of $(2) for the
# variable named by $(1), unless the variable has been set by
# environment or command line. This is necessary for CC and AR
# because make sets default values, so the simpler ?= approach
# won't work as expected.
define allow-override
  $(if $(or $(findstring environment,$(origin $(1))),\
            $(findstring command line,$(origin $(1)))),,\
    $(eval $(1) = $(2)))
endef

# Allow setting CC and AR, or setting CROSS_COMPILE as a prefix.
$(call allow-override,CC,$(CROSS_COMPILE)gcc)
$(call allow-override,AR,$(CROSS_COMPILE)ar)
$(call allow-override,PKG_CONFIG,pkg-config)
$(call allow-override,LD_SO_CONF_PATH,/etc/ld.so.conf.d/)
$(call allow-override,LDCONFIG,ldconfig)

EXT = -std=gnu99
INSTALL = install

# Use DESTDIR for installing into a different root directory.
# This is useful for building a package. The program will be
# installed in this directory as if it was the root directory.
# Then the build tool can move it later.
DESTDIR ?=
DESTDIR_SQ = '$(subst ','\'',$(DESTDIR))'

LP64 := $(shell echo __LP64__ | ${CC} ${CFLAGS} -E -x c - | tail -n 1)
ifeq ($(LP64), 1)
  libdir_relative_temp = lib64
else
  libdir_relative_temp = lib
endif

libdir_relative ?= $(libdir_relative_temp)
prefix ?= /usr/local
man_dir = $(prefix)/share/man
man_dir_SQ = '$(subst ','\'',$(man_dir))'
libdir = $(prefix)/$(libdir_relative)
libdir_SQ = '$(subst ','\'',$(libdir))'
includedir_relative ?= include
includedir = $(prefix)/$(includedir_relative)
includedir_SQ = '$(subst ','\'',$(includedir))'
pkgconfig_dir ?= $(word 1,$(shell $(PKG_CONFIG) 		\
			--variable pc_path pkg-config | tr ":" " "))

etcdir ?= /etc
etcdir_SQ = '$(subst ','\'',$(etcdir))'

export man_dir man_dir_SQ html_install html_install_SQ INSTALL
export img_install img_install_SQ
export DESTDIR DESTDIR_SQ

pound := \#

HELP_DIR = -DHELP_DIR=$(html_install)
HELP_DIR_SQ = '$(subst ','\'',$(HELP_DIR))'
#' emacs highlighting gets confused by the above escaped quote.

ifeq ("$(origin V)", "command line")
  VERBOSE = $(V)
endif
ifndef VERBOSE
  VERBOSE = 0
endif

SILENT := $(if $(findstring s,$(filter-out --%,$(MAKEFLAGS))),1)

# $(call test-build, snippet, ret) -> ret if snippet compiles
#                                  -> empty otherwise
test-build = $(if $(shell sh -c 'echo "$(1)" | \
	$(CC) -o /dev/null -c -x c - > /dev/null 2>&1 && echo y'), $2)

ifeq ("$(origin O)", "command line")

  saved-output := $(O)
  BUILD_OUTPUT := $(shell cd $(O) && /bin/pwd)
  $(if $(BUILD_OUTPUT),, \
    $(error output directory "$(saved-output)" does not exist))

else
  BUILD_OUTPUT = $(CURDIR)
endif

srctree		:= $(if $(BUILD_SRC),$(BUILD_SRC),$(CURDIR))
objtree		:= $(BUILD_OUTPUT)
src		:= $(srctree)
obj		:= $(objtree)
bdir		:= $(obj)/lib

export prefix src obj bdir

LIBRARY_STATIC = $(bdir)/$(LIBRARY_A)
LIBRARY_SHARED = $(bdir)/$(LIBRARY_SO).$(LIBRARY_VERSION)

LIBRARY_SHARED_SO = $(bdir)/$(LIBRARY_SO)
LIBRARY_SHARED_VERSION = $(bdir)/$(LIBRARY_SO).$(TE_VERSION)

PKG_CONFIG_SOURCE_FILE = $(LIBRARY_NAME).pc
PKG_CONFIG_FILE := $(addprefix $(obj)/,$(PKG_CONFIG_SOURCE_FILE))

LIBS =

export LIBS
export LIBRARY_STATIC LIBRARY_SHARED
export LIBRARY_SHARED_SO LIBRARY_SHARED_VERSION

export Q SILENT VERBOSE EXT

# Include the utils
include scripts/utils.mk

INCLUDES = -I$(src)/include

# Set compile option CFLAGS if not set elsewhere
CFLAGS ?= -g -Wall
CPPFLAGS ?=
LDFLAGS ?=

CUNIT_INSTALLED := $(shell if (printf "$(pound)include <CUnit/Basic.h>\n void main(){CU_initialize_registry();}" | $(CC) -x c - -lcunit -o /dev/null >/dev/null 2>&1) ; then echo 1; else echo 0 ; fi)
export CUNIT_INSTALLED

export CFLAGS
export INCLUDES

# Append required CFLAGS
override CFLAGS += -D_GNU_SOURCE $(INCLUDES)

all: all_cmd

LIB_TARGET  = $(LIBRARY_A) $(LIBRARY_SO).$(LIBRARY_VERSION)
LIB_INSTALL = $(LIBRARY_A) $(LIBRARY_SO)*
LIB_INSTALL := $(addprefix $(bdir)/,$(LIB_INSTALL))

TARGETS = $(LIBRARY_SO) $(LIBRARY_A)

all_cmd: $(TARGETS) $(PKG_CONFIG_FILE)

$(LIBRARY_A): $(bdir) $(LIBRARY_STATIC)
$(LIBRARY_SO): $(bdir) $(LIBRARY_SHARED)

libs: $(LIBRARY_A) $(LIBRARY_SO)

VALGRIND = $(shell which valgrind)
UTEST_DIR = utest
UTEST_BINARY = trace-utest

test: force $(LIBRARY_STATIC)
ifneq ($(CUNIT_INSTALLED),1)
	$(error CUnit framework not installed, cannot build unit tests))
endif
	$(Q)$(call descend,$(src)/$(UTEST_DIR),$@)

test_mem: test
ifeq (, $(VALGRIND))
	$(error "No valgrind in $(PATH), cannot run memory test")
endif
ifneq ($(shell id -u), 0)
	$(error "The unit test should be run as root, as it requires full access to library")
endif
	CK_FORK=no LD_LIBRARY_PATH=$(bdir) $(VALGRIND) \
		--show-leak-kinds=all --leak-resolution=high \
		--leak-check=full --show-possibly-lost=yes \
		--track-origins=yes -s \
		$(src)/$(UTEST_DIR)/$(UTEST_BINARY)

define find_tag_files
	find $(src) -name '\.pc' -prune -o -name '*\.[ch]' -print -o -name '*\.[ch]pp' \
		! -name '\.#' -print
endef

define do_make_pkgconfig_file
	cp -f ${PKG_CONFIG_SOURCE_FILE}.template ${PKG_CONFIG_FILE};	\
	sed -i "s|INSTALL_PREFIX|${1}|g" ${PKG_CONFIG_FILE}; 		\
	sed -i "s|LIB_VERSION|${LIBRARY_VERSION}|g" ${PKG_CONFIG_FILE}; \
	sed -i "s|LIB_DIR|${libdir_relative}|g" ${PKG_CONFIG_FILE}; \
	sed -i "s|HEADER_DIR|$(includedir_relative)|g" ${PKG_CONFIG_FILE};
endef

BUILD_PREFIX := $(BUILD_OUTPUT)/build_prefix

VERSION_FILE = te_version.h

$(BUILD_PREFIX): force
	$(Q)$(call build_prefix,$(prefix))

$(PKG_CONFIG_FILE) : ${PKG_CONFIG_SOURCE_FILE}.template $(BUILD_PREFIX) $(VERSION_FILE)
	$(Q) $(call do_make_pkgconfig_file,$(prefix))

VIM_TAGS = $(obj)/tags
EMACS_TAGS = $(obj)/TAGS
CSCOPE_TAGS = $(obj)/cscope

$(VIM_TAGS): force
	$(RM) $@
	$(call find_tag_files) | (cd $(obj) && xargs ctags --extra=+f --c-kinds=+px)

$(EMACS_TAGS): force
	$(RM) $@
	$(call find_tag_files) | (cd $(obj) && xargs etags)

$(CSCOPE_TAGS): force
	$(RM) $(obj)/cscope*
	$(call find_tag_files) | cscope -b -q

tags: $(VIM_TAGS)
TAGS: $(EMACS_TAGS)
cscope: $(CSCOPE_TAGS)

ifeq ("$(DESTDIR)", "")
# If DESTDIR is not defined, then test if after installing the library
# and running ldconfig, if the library is visible by ld.so.
# If not, add the path to /etc/ld.so.conf.d/trace.conf and run ldconfig again.
define install_ld_config
	if $(LDCONFIG); then \
		if ! grep -q "^$(libdir)$$" $(LD_SO_CONF_PATH)/* ; then \
			$(CC) -o $(objtree)/test $(srctree)/test.c -I $(includedir_SQ) \
				-L $(libdir_SQ) -l$(LIB_NAME) &> /dev/null; \
			if ! $(objtree)/test &> /dev/null; then \
				$(call print_install, trace.conf, $(LD_SO_CONF_PATH)) \
				echo $(libdir_SQ) >> $(LD_SO_CONF_PATH)/trace.conf; \
				$(LDCONFIG); \
			fi; \
			$(RM) $(objtree)/test; \
		fi; \
	fi
endef
else
# If installing to a location for another machine or package, do not bother
# with running ldconfig.
define install_ld_config
endef
endif # DESTDIR = ""

install_libs: libs install_pkgconfig
	$(Q)$(call do_install,$(LIBRARY_SHARED),$(libdir_SQ)); \
		cp -fpR $(LIB_INSTALL) $(DESTDIR)$(libdir_SQ)
	$(Q)$(call do_install,$(src)/include/$(LIB_NAME).h,$(includedir_SQ),644)
	$(Q)$(call install_ld_config)

install: install_libs

install_pkgconfig: $(PKG_CONFIG_FILE)
	$(Q)$(call , $(PKG_CONFIG_FILE)) \
		$(call do_install_pkgconfig_file,$(prefix))

doc: check_doc
	$(Q)$(call descend,$(src)/Documentation,all)

doc_clean:
	$(Q)$(call descend,$(src)/Documentation,clean)

install_doc:
	$(Q)$(call descend,$(src)/Documentation,install)

check_doc: force
	$(Q)$(src)/check-manpages.sh $(src)/Documentation

define build_uninstall_script
	$(Q)mkdir $(BUILD_OUTPUT)/tmp_build
	$(Q)$(MAKE) -C $(src) DESTDIR=$(BUILD_OUTPUT)/tmp_build/ O=$(BUILD_OUTPUT) $1 > /dev/null
	$(Q)find $(BUILD_OUTPUT)/tmp_build ! -type d -printf "%P\n" > $(BUILD_OUTPUT)/build_$2
	$(Q)$(RM) -rf $(BUILD_OUTPUT)/tmp_build
endef

build_uninstall: $(BUILD_PREFIX)
	$(call build_uninstall_script,install,uninstall)

$(BUILD_OUTPUT)/build_uninstall: build_uninstall

define uninstall_file
	if [ -f $(DESTDIR)/$1 -o -h $(DESTDIR)/$1 ]; then \
		$(call print_uninstall,$(DESTDIR)/$1)$(RM) $(DESTDIR)/$1; \
	fi;
endef

uninstall: $(BUILD_OUTPUT)/build_uninstall
	@$(foreach file,$(shell cat $(BUILD_OUTPUT)/build_uninstall),$(call uninstall_file,$(file)))

PHONY += force
force:

# Declare the contents of the .PHONY variable as phony.  We keep that
# information in a variable so we can use it in if_changed and friends.
.PHONY: $(PHONY)

DEFAULT_TARGET = $(LIBRARY_STATIC)

all: $(DEFAULT_TARGET)

$(bdir):
	@mkdir -p $(bdir)

define make_version.h
  (echo '/* This file is automatically generated. Do not modify. */';		\
   echo \#define VERSION_CODE $(shell						\
   expr $(VERSION) \* 256 + $(PATCHLEVEL));					\
   echo '#define EXTRAVERSION ' $(EXTRAVERSION);				\
   echo '#define VERSION_STRING "'$(VERSION).$(PATCHLEVEL).$(EXTRAVERSION)'"';	\
  ) > $1
endef

define update_version.h
  ($(call make_version.h, $@.tmp);		\
    if [ -r $@ ] && cmp -s $@ $@.tmp; then	\
      rm -f $@.tmp;				\
    else					\
      echo '  UPDATE             $@';		\
      mv -f $@.tmp $@;				\
    fi);
endef

$(VERSION_FILE): force
	$(Q)$(call update_version.h)

$(LIBRARY_STATIC): force
	$(Q)$(call descend,$(src)/src,$@)

$(LIBRARY_SHARED): force
	$(Q)$(call descend,$(src)/src,$(LIBRARY_SO))

#	$(Q)$(call descend_clean,utest)
clean:
	$(Q)$(call descend_clean,src)
	$(Q)$(call do_clean, \
	  $(TARGETS) $(bdir)/*.a $(bdir)/*.so $(bdir)/*.so.* $(bdir)/*.o $(bdir)/.*.d \
	  $(PKG_CONFIG_FILE) \
	  $(VERSION_FILE) \
	  $(BUILD_PREFIX))

.PHONY: clean

# The static and shared targets would concurrently enter the same directory -
# a recipe for collisions.
.NOTPARALLEL:
