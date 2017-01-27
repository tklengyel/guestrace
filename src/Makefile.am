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

bin_PROGRAMS = \
	guestrace

guestrace_SOURCES = \
	guestrace.c \
	functions_linux.c \
	functions_windows.c \
	generated_linux.c \
	trace_syscalls.c

noinst_HEADERS = \
	functions_linux.h \
	functions_windows.h \
	trace_syscalls.h \
	trace_syscalls_private.h
