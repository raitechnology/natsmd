# natsmd makefile
lsb_dist     := $(shell if [ -f /etc/os-release ] ; then \
                  grep '^NAME=' /etc/os-release | sed 's/.*=[\"]*//' | sed 's/[ \"].*//' ; \
                  elif [ -x /usr/bin/lsb_release ] ; then \
                  lsb_release -is ; else echo Linux ; fi)
lsb_dist_ver := $(shell if [ -f /etc/os-release ] ; then \
		  grep '^VERSION=' /etc/os-release | sed 's/.*=[\"]*//' | sed 's/[ \"].*//' ; \
                  elif [ -x /usr/bin/lsb_release ] ; then \
                  lsb_release -rs | sed 's/[.].*//' ; else uname -r | sed 's/[-].*//' ; fi)
#lsb_dist     := $(shell if [ -x /usr/bin/lsb_release ] ; then lsb_release -is ; else echo Linux ; fi)
#lsb_dist_ver := $(shell if [ -x /usr/bin/lsb_release ] ; then lsb_release -rs | sed 's/[.].*//' ; else uname -r | sed 's/[-].*//' ; fi)
uname_m      := $(shell uname -m)

short_dist_lc := $(patsubst CentOS,rh,$(patsubst RedHatEnterprise,rh,\
                   $(patsubst RedHat,rh,\
                     $(patsubst Fedora,fc,$(patsubst Ubuntu,ub,\
                       $(patsubst Debian,deb,$(patsubst SUSE,ss,$(lsb_dist))))))))
short_dist    := $(shell echo $(short_dist_lc) | tr a-z A-Z)
pwd           := $(shell pwd)
rpm_os        := $(short_dist_lc)$(lsb_dist_ver).$(uname_m)

# this is where the targets are compiled
build_dir ?= $(short_dist)$(lsb_dist_ver)_$(uname_m)$(port_extra)
bind      := $(build_dir)/bin
libd      := $(build_dir)/lib64
objd      := $(build_dir)/obj
dependd   := $(build_dir)/dep

have_rpm  := $(shell if [ -x /bin/rpmquery ] ; then echo true; fi)
have_dpkg := $(shell if [ -x /bin/dpkg-buildflags ] ; then echo true; fi)
default_cflags := -ggdb -O3
# use 'make port_extra=-g' for debug build
ifeq (-g,$(findstring -g,$(port_extra)))
  default_cflags := -ggdb
#  xtra_cflags    := -fanalyzer
endif
ifeq (-a,$(findstring -a,$(port_extra)))
  default_cflags += -fsanitize=address
endif
ifeq (-mingw,$(findstring -mingw,$(port_extra)))
  CC    := /usr/bin/x86_64-w64-mingw32-gcc
  CXX   := /usr/bin/x86_64-w64-mingw32-g++
  mingw := true
endif
ifeq (,$(port_extra))
  ifeq (true,$(have_rpm))
    build_cflags = $(shell /bin/rpm --eval '%{optflags}')
  endif
  ifeq (true,$(have_dpkg))
    build_cflags = $(shell /bin/dpkg-buildflags --get CFLAGS)
  endif
endif
# msys2 using ucrt64
ifeq (MSYS2,$(lsb_dist))
  mingw := true
endif
CC          ?= gcc
CXX         ?= g++
cc          := $(CC) -std=c11
cpp         := $(CXX)
arch_cflags := -mavx -maes -fno-omit-frame-pointer
gcc_wflags  := -Wall -Wextra
#-Werror
# if windows cross compile
ifeq (true,$(mingw))
dll         := dll
exe         := .exe
soflag      := -shared -Wl,--subsystem,windows
fpicflags   := -fPIC -DNATS_SHARED
sock_lib    := -lcares -lws2_32
dynlink_lib := -lpcre2-8 -lz
NO_STL      := 1
else
dll         := so
exe         :=
soflag      := -shared
fpicflags   := -fPIC
thread_lib  := -pthread -lrt
sock_lib    := -lcares
dynlink_lib := -lpcre2-8 -lz
endif
# make apple shared lib
ifeq (Darwin,$(lsb_dist)) 
dll         := dylib
endif
# rpmbuild uses RPM_OPT_FLAGS
#ifeq ($(RPM_OPT_FLAGS),)
CFLAGS ?= $(build_cflags) $(default_cflags)
#else
#CFLAGS ?= $(RPM_OPT_FLAGS)
#endif
cflags := $(gcc_wflags) $(CFLAGS) $(arch_cflags)
lflags := -Wno-stringop-overflow

INCLUDES  ?= -Iinclude
DEFINES   ?=
includes  := $(INCLUDES)
defines   := $(DEFINES)

# if not linking libstdc++
ifdef NO_STL
cppflags  := -std=c++11 -fno-rtti -fno-exceptions
cpplink   := $(CC)
else
cppflags  := -std=c++11
cpplink   := $(CXX)
endif

math_lib    := -lm

# test submodules exist (they don't exist for dist_rpm, dist_dpkg targets)
test_makefile = $(shell if [ -f ./$(1)/GNUmakefile ] ; then echo ./$(1) ; \
                        elif [ -f ../$(1)/GNUmakefile ] ; then echo ../$(1) ; fi)

md_home     := $(call test_makefile,raimd)
dec_home    := $(call test_makefile,libdecnumber)
kv_home     := $(call test_makefile,raikv)
hdr_home    := $(call test_makefile,HdrHistogram_c)

ifeq (,$(dec_home))
dec_home    := $(call test_makefile,$(md_home)/libdecnumber)
endif

lnk_lib     := -Wl,--push-state -Wl,-Bstatic
dlnk_lib    :=
lnk_dep     :=
dlnk_dep    :=

ifneq (,$(md_home))
md_lib      := $(md_home)/$(libd)/libraimd.a
md_dll      := $(md_home)/$(libd)/libraimd.$(dll)
lnk_lib     += $(md_lib)
lnk_dep     += $(md_lib)
dlnk_lib    += -L$(md_home)/$(libd) -lraimd
dlnk_dep    += $(md_dll)
rpath1       = ,-rpath,$(pwd)/$(md_home)/$(libd)
includes    += -I$(md_home)/include
else
lnk_lib     += -lraimd
dlnk_lib    += -lraimd
endif

ifneq (,$(dec_home))
dec_lib     := $(dec_home)/$(libd)/libdecnumber.a
dec_dll     := $(dec_home)/$(libd)/libdecnumber.$(dll)
lnk_lib     += $(dec_lib)
lnk_dep     += $(dec_lib)
dlnk_lib    += -L$(dec_home)/$(libd) -ldecnumber
dlnk_dep    += $(dec_dll)
rpath2       = ,-rpath,$(pwd)/$(dec_home)/$(libd)
dec_includes = -I$(dec_home)/include
else
lnk_lib     += -ldecnumber
dlnk_lib    += -ldecnumber
endif

ifneq (,$(kv_home))
kv_lib      := $(kv_home)/$(libd)/libraikv.a
kv_dll      := $(kv_home)/$(libd)/libraikv.$(dll)
lnk_lib     += $(kv_lib)
lnk_dep     += $(kv_lib)
dlnk_lib    += -L$(kv_home)/$(libd) -lraikv
dlnk_dep    += $(kv_dll)
rpath3       = ,-rpath,$(pwd)/$(kv_home)/$(libd)
includes    += -I$(kv_home)/include
else
lnk_lib     += -lraikv
dlnk_lib    += -lraikv
endif

ifneq (,$(hdr_home))
hdr_lib      := $(hdr_home)/$(libd)/libhdrhist.a
hdr_dll      := $(hdr_home)/$(libd)/libhdrhist.$(dll)
lnk_lib     += $(hdr_lib)
lnk_dep     += $(hdr_lib)
dlnk_lib    += -L$(hdr_home)/$(libd) -lhdrhist
dlnk_dep    += $(hdr_dll)
rpath4       = ,-rpath,$(pwd)/$(hdr_home)/$(libd)
hdr_includes = -I$(hdr_home)/src
else
lnk_lib     += -lhdrhist
dlnk_lib    += -lhdrhist
hdr_includes = -I/usr/include/hdrhist
endif

natsmd_lib := $(libd)/libnatsmd.a
rpath      := -Wl,-rpath,$(pwd)/$(libd)$(rpath1)$(rpath2)$(rpath3)$(rpath4)$(rpath5)$(rpath6)$(rpath7)
lnk_lib    += -Wl,--pop-state

.PHONY: everything
everything: $(kv_lib) $(dec_lib) $(md_lib) $(hdr_lib) all

clean_subs :=
dlnk_dll_depend :=
dlnk_lib_depend :=

# build submodules if have them
ifneq (,$(md_home))
$(md_lib) $(md_dll):
	$(MAKE) -C $(md_home)
.PHONY: clean_md
clean_md:
	$(MAKE) -C $(md_home) clean
clean_subs += clean_md
endif
ifneq (,$(dec_home))
$(dec_lib) $(dec_dll):
	$(MAKE) -C $(dec_home)
.PHONY: clean_dec
clean_dec:
	$(MAKE) -C $(dec_home) clean
clean_subs += clean_dec
endif
ifneq (,$(kv_home))
$(kv_lib) $(kv_dll):
	$(MAKE) -C $(kv_home)
.PHONY: clean_kv
clean_kv:
	$(MAKE) -C $(kv_home) clean
clean_subs += clean_kv
endif
ifneq (,$(hdr_home))
$(hdr_lib) $(hdr_dll):
	$(MAKE) -C $(hdr_home)
.PHONY: clean_hdr
clean_hdr:
	$(MAKE) -C $(hdr_home) clean
clean_subs += clean_hdr
endif

# build depends for rpm spec file
-include build_depends.mak
# copr/fedora build (with version env vars)
# copr uses this to generate a source rpm with the srpm target
-include .copr/Makefile
# debian build (debuild)
# target for building installable deb: dist_dpkg
-include deb/Makefile

# targets filled in below
all_exes    :=
all_libs    :=
all_dlls    :=
all_depends :=
gen_files   :=

ev_nats_defines := -DNATSMD_VER=$(ver_build)
$(objd)/ev_nats.o : .copr/Makefile
$(objd)/ev_nats.fpic.o : .copr/Makefile
libnatsmd_files := ev_nats ev_nats_client
libnatsmd_cfile := $(addprefix src/, $(addsuffix .cpp, $(libnatsmd_files)))
libnatsmd_objs  := $(addprefix $(objd)/, $(addsuffix .o, $(libnatsmd_files)))
libnatsmd_dbjs  := $(addprefix $(objd)/, $(addsuffix .fpic.o, $(libnatsmd_files)))
libnatsmd_deps  := $(addprefix $(dependd)/, $(addsuffix .d, $(libnatsmd_files))) \
                  $(addprefix $(dependd)/, $(addsuffix .fpic.d, $(libnatsmd_files)))
libnatsmd_dlnk  := $(dlnk_lib)
libnatsmd_spec  := $(version)-$(build_num)_$(git_hash)
libnatsmd_ver   := $(major_num).$(minor_num)

$(libd)/libnatsmd.a: $(libnatsmd_objs)
$(libd)/libnatsmd.$(dll): $(libnatsmd_dbjs) $(dlnk_dep)

all_libs    += $(libd)/libnatsmd.a
all_dlls    += $(libd)/libnatsmd.$(dll)
all_depends += $(libnatsmd_deps)

server_defines := -DNATSMD_VER=$(ver_build)
$(objd)/server.o : .copr/Makefile
$(objd)/server.fpic.o : .copr/Makefile
natsmd_server_files := server
natsmd_server_cfile := $(addprefix src/, $(addsuffix .cpp, $(natsmd_server_files)))
natsmd_server_objs  := $(addprefix $(objd)/, $(addsuffix .o, $(natsmd_server_files)))
natsmd_server_deps  := $(addprefix $(dependd)/, $(addsuffix .d, $(natsmd_server_files)))
natsmd_server_libs  := $(natsmd_lib)
natsmd_server_lnk   := $(natsmd_lib) $(lnk_lib)

$(bind)/natsmd_server$(exe): $(natsmd_server_objs) $(natsmd_server_libs) $(lnk_dep)

all_exes    += $(bind)/natsmd_server$(exe)
all_depends += $(natsmd_server_deps)
server_defines := -DNATSMD_VER=$(ver_build)

ping_nats_includes := $(hdr_includes)
ping_nats_defines  := -Wno-unused-function

ping_nats_files := ping_nats
ping_nats_cfile := $(addprefix test/, $(addsuffix .cpp, $(ping_nats_files)))
ping_nats_objs  := $(addprefix $(objd)/, $(addsuffix .o, $(ping_nats_files)))
ping_nats_deps  := $(addprefix $(dependd)/, $(addsuffix .d, $(ping_nats_files)))
ping_nats_libs  :=
ping_nats_lnk   := $(lnk_lib)

$(bind)/ping_nats$(exe): $(ping_nats_objs) $(ping_nats_libs) $(lnk_dep)

all_exes    += $(bind)/ping_nats$(exe)
all_depends += $(ping_nats_deps)

test_map_files := test_map
test_map_cfile := $(addprefix test/, $(addsuffix .cpp, $(test_map_files)))
test_map_objs  := $(addprefix $(objd)/, $(addsuffix .o, $(test_map_files)))
test_map_deps  := $(addprefix $(dependd)/, $(addsuffix .d, $(test_map_files)))
test_map_libs  := $(natsmd_lib)
test_map_lnk   := $(natsmd_lib) $(lnk_lib)

$(bind)/test_map$(exe): $(test_map_objs) $(test_map_libs) $(lnk_dep)

all_exes    += $(bind)/test_map$(exe)
all_depends += $(test_map_deps)

natsmd_client_files := md_client
natsmd_client_cfile := $(addprefix src/, $(addsuffix .cpp, $(natsmd_client_files)))
natsmd_client_objs  := $(addprefix $(objd)/, $(addsuffix .o, $(natsmd_client_files)))
natsmd_client_deps  := $(addprefix $(dependd)/, $(addsuffix .d, $(natsmd_client_files)))
natsmd_client_libs  := $(natsmd_lib)
natsmd_client_lnk   := $(natsmd_lib) $(lnk_lib)

$(bind)/natsmd_client$(exe): $(natsmd_client_objs) $(natsmd_client_libs) $(lnk_dep)

all_exes    += $(bind)/natsmd_client$(exe)
all_depends += $(natsmd_client_deps)

natsmd_pub_files := md_pub
natsmd_pub_cfile := $(addprefix src/, $(addsuffix .cpp, $(natsmd_pub_files)))
natsmd_pub_objs  := $(addprefix $(objd)/, $(addsuffix .o, $(natsmd_pub_files)))
natsmd_pub_deps  := $(addprefix $(dependd)/, $(addsuffix .d, $(natsmd_pub_files)))
natsmd_pub_libs  := $(natsmd_lib)
natsmd_pub_lnk   := $(natsmd_lib) $(lnk_lib)

$(bind)/natsmd_pub$(exe): $(natsmd_pub_objs) $(natsmd_pub_libs) $(lnk_dep)

all_exes    += $(bind)/natsmd_pub$(exe)
all_depends += $(natsmd_pub_deps)

all_dirs := $(bind) $(libd) $(objd) $(dependd)

# the default targets
.PHONY: all
all: $(all_libs) $(all_dlls) $(all_exes) cmake

.PHONY: cmake
cmake: CMakeLists.txt

.ONESHELL: CMakeLists.txt
CMakeLists.txt: .copr/Makefile
	@cat <<'EOF' > $@
	cmake_minimum_required (VERSION 3.9.0)
	if (POLICY CMP0111)
	  cmake_policy(SET CMP0111 OLD)
	endif ()
	project (natsmd)
	include_directories (
	  include
	  $${CMAKE_SOURCE_DIR}/raimd/include
	  $${CMAKE_SOURCE_DIR}/raikv/include
	  $${CMAKE_SOURCE_DIR}/libdecnumber/include
	  $${CMAKE_SOURCE_DIR}/raimd/libdecnumber/include
	)
	if (CMAKE_SYSTEM_NAME STREQUAL "Windows")
	  add_definitions(/DPCRE2_STATIC)
	  if ($$<CONFIG:Release>)
	    add_compile_options (/arch:AVX2 /GL /std:c11 /wd5105)
	  else ()
	    add_compile_options (/arch:AVX2 /std:c11 /wd5105)
	  endif ()
	  if (NOT TARGET pcre2-8-static)
	    add_library (pcre2-8-static STATIC IMPORTED)
	    set_property (TARGET pcre2-8-static PROPERTY IMPORTED_LOCATION_DEBUG ../pcre2/build/Debug/pcre2-8-staticd.lib)
	    set_property (TARGET pcre2-8-static PROPERTY IMPORTED_LOCATION_RELEASE ../pcre2/build/Release/pcre2-8-static.lib)
	    include_directories (../pcre2/build)
	  else ()
	    include_directories ($${CMAKE_BINARY_DIR}/pcre2)
	  endif ()
	  if (NOT TARGET raikv)
	    add_library (raikv STATIC IMPORTED)
	    set_property (TARGET raikv PROPERTY IMPORTED_LOCATION_DEBUG ../raikv/build/Debug/raikv.lib)
	    set_property (TARGET raikv PROPERTY IMPORTED_LOCATION_RELEASE ../raikv/build/Release/raikv.lib)
	  endif ()
	  if (NOT TARGET raimd)
	    add_library (raimd STATIC IMPORTED)
	    set_property (TARGET raimd PROPERTY IMPORTED_LOCATION_DEBUG ../raimd/build/Debug/raimd.lib)
	    set_property (TARGET raimd PROPERTY IMPORTED_LOCATION_RELEASE ../raimd/build/Release/raimd.lib)
	  endif ()
	  if (NOT TARGET decnumber)
	    add_library (decnumber STATIC IMPORTED)
	    set_property (TARGET decnumber PROPERTY IMPORTED_LOCATION_DEBUG ../raimd/libdecnumber/build/Debug/decnumber.lib)
	    set_property (TARGET decnumber PROPERTY IMPORTED_LOCATION_RELEASE ../raimd/libdecnumber/build/Release/decnumber.lib)
	  endif ()
	else ()
	  add_compile_options ($(cflags))
	  if (TARGET pcre2-8-static)
	    include_directories ($${CMAKE_BINARY_DIR}/pcre2)
	  endif ()
	  if (NOT TARGET raikv)
	    add_library (raikv STATIC IMPORTED)
	    set_property (TARGET raikv PROPERTY IMPORTED_LOCATION ../raikv/build/libraikv.a)
	  endif ()
	  if (NOT TARGET raimd)
	    add_library (raimd STATIC IMPORTED)
	    set_property (TARGET raimd PROPERTY IMPORTED_LOCATION ../raimd/build/libraimd.a)
	  endif ()
	  if (NOT TARGET decnumber)
	    add_library (decnumber STATIC IMPORTED)
	    set_property (TARGET decnumber PROPERTY IMPORTED_LOCATION ../raimd/libdecnumber/build/libdecnumber.a)
	  endif ()
	endif ()
	add_library (natsmd STATIC $(libnatsmd_cfile))
	if (CMAKE_SYSTEM_NAME STREQUAL "Windows")
	  link_libraries (natsmd raikv raimd decnumber pcre2-8-static ws2_32)
	else ()
	  if (TARGET pcre2-8-static)
	    link_libraries (natsmd raikv raimd decnumber pcre2-8-static -lcares -lpthread -lrt)
	  else ()
	    link_libraries (natsmd raikv raimd decnumber -lpcre2-8 -lcares -lpthread -lrt)
	  endif ()
	endif ()
	add_definitions(-DNATSMD_VER=$(ver_build))
	add_executable (natsmd_server $(natsmd_server_cfile))
	add_executable (natsmd_client $(natsmd_client_cfile))
	add_executable (natsmd_pub $(natsmd_pub_cfile))
	add_executable (test_map $(test_map_cfile))
	EOF


.PHONY: dnf_depend
dnf_depend:
	sudo dnf -y install make gcc-c++ git redhat-lsb openssl-devel pcre2-devel chrpath c-ares-devel

.PHONY: yum_depend
yum_depend:
	sudo yum -y install make gcc-c++ git redhat-lsb openssl-devel pcre2-devel chrpath c-ares-devel

.PHONY: deb_depend
deb_depend:
	sudo apt-get install -y install make g++ gcc devscripts libpcre2-dev chrpath git lsb-release libssl-dev c-ares-dev

# create directories
$(dependd):
	@mkdir -p $(all_dirs)

# remove target bins, objs, depends
.PHONY: clean
clean: $(clean_subs)
	rm -r -f $(bind) $(libd) $(objd) $(dependd)
	if [ "$(build_dir)" != "." ] ; then rmdir $(build_dir) ; fi

.PHONY: clean_dist
clean_dist:
	rm -rf dpkgbuild rpmbuild

.PHONY: clean_all
clean_all: clean clean_dist

# force a remake of depend using 'make -B depend'
.PHONY: depend
depend: $(dependd)/depend.make

$(dependd)/depend.make: $(dependd) $(all_depends)
	@echo "# depend file" > $(dependd)/depend.make
	@cat $(all_depends) >> $(dependd)/depend.make

.PHONY: dist_bins
dist_bins: $(all_libs) $(all_dlls) $(bind)/natsmd_server$(exe) $(bind)/natsmd_client$(exe) $(bind)/natsmd_pub$(exe) $(bind)/ping_nats$(exe)
	chrpath -d $(libd)/libnatsmd.$(dll)
	chrpath -d $(bind)/natsmd_server$(exe)
	chrpath -d $(bind)/natsmd_client$(exe)
	chrpath -d $(bind)/natsmd_pub$(exe)
	chrpath -d $(bind)/ping_nats$(exe)

.PHONY: dist_rpm
dist_rpm: srpm
	( cd rpmbuild && rpmbuild --define "-topdir `pwd`" -ba SPECS/natsmd.spec )

# dependencies made by 'make depend'
-include $(dependd)/depend.make

ifeq ($(DESTDIR),)
# 'sudo make install' puts things in /usr/local/lib, /usr/local/include
install_prefix = /usr/local
else
# debuild uses DESTDIR to put things into debian/natsmd/usr
install_prefix = $(DESTDIR)/usr
endif

install: dist_bins
	install -d $(install_prefix)/lib $(install_prefix)/bin
	install -d $(install_prefix)/include/natsmd
	for f in $(libd)/libnatsmd.* ; do \
	if [ -h $$f ] ; then \
	cp -a $$f $(install_prefix)/lib ; \
	else \
	install $$f $(install_prefix)/lib ; \
	fi ; \
	done
	install -m 755 $(bind)/natsmd_server$(exe) $(install_prefix)/bin
	install -m 755 $(bind)/natsmd_client$(exe) $(install_prefix)/bin
	install -m 755 $(bind)/natsmd_pub$(exe) $(install_prefix)/bin
	install -m 755 $(bind)/ping_nats$(exe) $(install_prefix)/bin
	install -m 644 include/natsmd/*.h $(install_prefix)/include/natsmd

$(objd)/%.o: src/%.cpp
	$(cpp) $(cflags) $(xtra_cflags) $(cppflags) $(includes) $(defines) $($(notdir $*)_includes) $($(notdir $*)_defines) -c $< -o $@

$(objd)/%.o: src/%.c
	$(cc) $(cflags) $(xtra_cflags) $(includes) $(defines) $($(notdir $*)_includes) $($(notdir $*)_defines) -c $< -o $@

$(objd)/%.fpic.o: src/%.cpp
	$(cpp) $(cflags) $(xtra_cflags) $(fpicflags) $(cppflags) $(includes) $(defines) $($(notdir $*)_includes) $($(notdir $*)_defines) -c $< -o $@

$(objd)/%.fpic.o: src/%.c
	$(cc) $(cflags) $(xtra_cflags) $(fpicflags) $(includes) $(defines) $($(notdir $*)_includes) $($(notdir $*)_defines) -c $< -o $@

$(objd)/%.o: test/%.cpp
	$(cpp) $(cflags) $(xtra_cflags) $(cppflags) $(includes) $(defines) $($(notdir $*)_includes) $($(notdir $*)_defines) -c $< -o $@

$(objd)/%.o: test/%.c
	$(cc) $(cflags) $(xtra_cflags) $(includes) $(defines) $($(notdir $*)_includes) $($(notdir $*)_defines) -c $< -o $@

$(libd)/%.a:
	ar rc $@ $($(*)_objs)

ifeq (Darwin,$(lsb_dist))
$(libd)/%.dylib:
	$(cpplink) -dynamiclib $(cflags) $(lflags) -o $@.$($(*)_dylib).dylib -current_version $($(*)_dylib) -compatibility_version $($(*)_ver) $($(*)_dbjs) $($(*)_dlnk) $(sock_lib) $(math_lib) $(thread_lib) $(malloc_lib) $(dynlink_lib) && \
	cd $(libd) && ln -f -s $(@F).$($(*)_dylib).dylib $(@F).$($(*)_ver).dylib && ln -f -s $(@F).$($(*)_ver).dylib $(@F)
else
$(libd)/%.$(dll):
	$(cpplink) $(soflag) $(rpath) $(cflags) $(lflags) -o $@.$($(*)_spec) -Wl,-soname=$(@F).$($(*)_ver) $($(*)_dbjs) $($(*)_dlnk) $(sock_lib) $(math_lib) $(thread_lib) $(malloc_lib) $(dynlink_lib) && \
	cd $(libd) && ln -f -s $(@F).$($(*)_spec) $(@F).$($(*)_ver) && ln -f -s $(@F).$($(*)_ver) $(@F)
endif

$(bind)/%$(exe):
	$(cpplink) $(cflags) $(lflags) $(rpath) -o $@ $($(*)_objs) -L$(libd) $($(*)_lnk) $(cpp_lnk) $(sock_lib) $(math_lib) $(thread_lib) $(malloc_lib) $(dynlink_lib)

$(dependd)/%.d: src/%.cpp
	$(cpp) $(arch_cflags) $(defines) $(includes) $($(notdir $*)_includes) $($(notdir $*)_defines) -MM $< -MT $(objd)/$(*).o -MF $@

$(dependd)/%.d: src/%.c
	$(cc) $(arch_cflags) $(defines) $(includes) $($(notdir $*)_includes) $($(notdir $*)_defines) -MM $< -MT $(objd)/$(*).o -MF $@

$(dependd)/%.fpic.d: src/%.cpp
	$(cpp) $(arch_cflags) $(defines) $(includes) $($(notdir $*)_includes) $($(notdir $*)_defines) -MM $< -MT $(objd)/$(*).fpic.o -MF $@

$(dependd)/%.fpic.d: src/%.c
	$(cc) $(arch_cflags) $(defines) $(includes) $($(notdir $*)_includes) $($(notdir $*)_defines) -MM $< -MT $(objd)/$(*).fpic.o -MF $@

$(dependd)/%.d: test/%.cpp
	$(cpp) $(arch_cflags) $(defines) $(includes) $($(notdir $*)_includes) $($(notdir $*)_defines) -MM $< -MT $(objd)/$(*).o -MF $@

$(dependd)/%.d: test/%.c
	$(cc) $(arch_cflags) $(defines) $(includes) $($(notdir $*)_includes) $($(notdir $*)_defines) -MM $< -MT $(objd)/$(*).o -MF $@

