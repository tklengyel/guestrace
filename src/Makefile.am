AM_CPPFLAGS = \
	-I$(top_srcdir) \
	$(LIBVMI_CFLAGS)

AM_CFLAGS = \
	-Wall

AM_LDFLAGS = \
	$(LIBVMI_LIBS)

bin_PROGRAMS = \
	guestrace

guestrace_SOURCES = \
	trace_syscalls.c \
	translate_syscalls.c

noinst_HEADERS = \
	syscall_enum.h \
	translate_syscalls.h
