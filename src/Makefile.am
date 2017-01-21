AM_CPPFLAGS = \
	-I$(top_srcdir) \
	$(GLIB_CFLAGS) \
	$(LIBVMI_CFLAGS)

AM_CFLAGS = \
	-Wall

AM_LDFLAGS = \
	$(GLIB_LIBS) \
	$(LIBVMI_LIBS)

bin_PROGRAMS = \
	guestrace

guestrace_SOURCES = \
	generated_linux.c \
	functions_linux.c \
	functions_windows.c \
	trace_syscalls.c

noinst_HEADERS = \
	functions_linux.h \
	functions_windows.h \
	trace_syscalls.h
