AM_CPPFLAGS = \
	-I$(top_srcdir) \
	$(GLIB_CFLAGS) \
	$(LIBVMI_CFLAGS) \
	$(CAPSTONE_CFLAGS)

AM_CFLAGS = \
	-Wall

AM_LDFLAGS = \
	$(GLIB_LIBS) \
	$(LIBVMI_LIBS) \
	$(CAPSTONE_LIBS)

bin_PROGRAMS = \
	guestrace

guestrace_SOURCES = \
	trace_syscalls.c \
	functions_windows.c

noinst_HEADERS = \
	syscall_enum.h \
	functions_windows.h
