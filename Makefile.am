if FLYN
# For local development use only.
include /etc/fctk/config.mk
endif

SUBDIRS = \
	doc \
	src \
	tools

DIST_SUBDIRS = \
	doc \
	src \
	tools

pcfiles = libguestrace-@API_VERSION@.pc

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = $(pcfiles)

EXTRA_DIST = autogen.sh
