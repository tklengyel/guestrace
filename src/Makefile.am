bin_PROGRAMS = \
	guestrace

lib_LTLIBRARIES = libguestrace-0.0.la

AM_CPPFLAGS = \
	-I$(top_srcdir) \
	$(CAPSTONE_CFLAGS) \
	$(GLIB_CFLAGS) \
	$(LIBVMI_CFLAGS)

AM_CFLAGS = \
	-Wall

AM_LDFLAGS = \
	$(CAPSTONE_LIBS) \
	$(GLIB_LIBS) \
	$(LIBVMI_LIBS)

libguestrace_0_0_la_SOURCES = \
	functions-linux.c \
	functions-windows.c \
	trace-syscalls.c

libguestraceincludedir = \
	$(includedir)/libguestrace-@API_VERSION@/libguestrace

libguestraceinclude_HEADERS = \
	guestrace.h

guestrace_SOURCES = \
	guestrace.c \
	generated-linux.c \
	generated-windows.c

guestrace_LDADD = \
	libguestrace-0.0.la

noinst_HEADERS = \
	functions-linux.h \
	functions-windows.h \
	guestrace-private.h
