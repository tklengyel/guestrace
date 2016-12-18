AC_INIT(src/trace_syscalls.c)

MAJOR_VERSION=0
MINOR_VERSION=0
MICRO_VERSION=4
AM_INIT_AUTOMAKE(guestrace, $MAJOR_VERSION.$MINOR_VERSION.$MICRO_VERSION)

AM_CONFIG_HEADER(config.h)

AM_MAINTAINER_MODE
AC_SUBST(ACLOCAL_AMFLAGS, "-I m4")

AC_PROG_CC
AC_PROG_LIBTOOL

AC_CHECK_PROG(HAVE_PKGCONFIG, pkg-config, yes, no)
if test "x$HAVE_PKGCONFIG" = "xno"; then
  AC_MSG_ERROR(you need to have pkgconfig installed !)
fi

PKG_PROG_PKG_CONFIG

PKG_CHECK_MODULES(LIBVMI, libvmi, HAVE_LIBVMI=yes, HAVE_LIBVMI=no)

if test "x$HAVE_LIBVMI" = "xno"; then
  AC_MSG_ERROR(you need libvmi 0.11.0+ installed)
fi

AC_SUBST(LIBVMI_CFLAGS)
AC_SUBST(LIBVMI_LIBS)

AC_DEFINE(HAVE_LIBVMI, 1, [Defined when libvmi was found])

PKG_CHECK_MODULES(CAPSTONE, capstone, HAVE_CAPSTONE=yes, HAVE_CAPSTONE=no)

if test "x$HAVE_CAPSTONE" = "xno"; then
  AC_MSG_ERROR(you need capstone installed)
fi

AC_SUBST(CAPSTONE_CFLAGS)
AC_SUBST(CAPSTONE_LIBS)

AC_DEFINE(HAVE_CAPSTONE, 1, [Defined when capstone was found])

PKG_CHECK_MODULES(GLIB, glib-2.0, HAVE_GLIB=yes, HAVE_GLIB=no)

if test "x$HAVE_GLIB" = "xno"; then
  AC_MSG_ERROR(you need glib installed)
fi

AC_SUBST(GLIB_CFLAGS)
AC_SUBST(BLIG_LIBS)

AC_DEFINE(HAVE_GLIB, 1, [Defined when glib was found])

AM_CONDITIONAL(FLYN, test "$FLYN")

AC_OUTPUT([
Makefile
src/Makefile
])
