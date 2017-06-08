bin_PROGRAMS = \
	guestrace \
	test-pendantic \
	test-segv

lib_LTLIBRARIES = libguestrace-0.0.la

AM_CPPFLAGS = \
	-I$(top_srcdir) \
	$(CAPSTONE_CFLAGS) \
	$(GLIB_CFLAGS) \
	$(JSON_C_CFLAGS) \
	$(LIBVMI_CFLAGS)

AM_CFLAGS = \
	-Wall

AM_LDFLAGS = \
	$(CAPSTONE_LIBS) \
	$(GLIB_LIBS) \
	$(JSON_C_LIBS) \
	$(LIBVMI_LIBS)

libguestrace_0_0_la_SOURCES = \
	early-boot.c \
	functions-linux.c \
	functions-windows.c \
	gt-rekall.c \
	gt-rekall-private.c \
	state-stacks.c \
	gt.c

libguestraceincludedir = \
	$(includedir)/libguestrace-@API_VERSION@/libguestrace

libguestraceinclude_HEADERS = \
	gt.h \
	gt-rekall.h

generated-linux.c: ../tools/gen-syscall-code-linux
	../tools/gen-syscall-code-linux

generated-windows.c: ../tools/gen-syscall-code-windows
	../tools/gen-syscall-code-windows

guestrace_SOURCES = \
	guestrace.c \
	generated-linux.c \
	generated-windows.c

guestrace_LDADD = \
	libguestrace-0.0.la

test_pendantic_SOURCES = \
	test-pendantic.c

test_pendantic_LDADD = \
	libguestrace-0.0.la

test_segv_SOURCES = \
	test-segv.c

test_segv_LDADD = \
	libguestrace-0.0.la

noinst_HEADERS = \
	early-boot.h \
	functions-linux.h \
	functions-windows.h \
	generated-windows.h \
	generated-linux.h \
	gt-private.h \
	gt-rekall-private.h \
	state-stacks.h
