AC_INIT(src/guestrace.c)

MAJOR_VERSION=0
MINOR_VERSION=0
MICRO_VERSION=7
AM_INIT_AUTOMAKE(guestrace, $MAJOR_VERSION.$MINOR_VERSION.$MICRO_VERSION)

API_VERSION=0.0
AC_SUBST(API_VERSION)

AM_CONFIG_HEADER(config.h)

AM_MAINTAINER_MODE
AC_SUBST(ACLOCAL_AMFLAGS, "-I m4")

AC_PROG_CC
AC_PROG_LIBTOOL

GTK_DOC_CHECK(1.0)
AC_CONFIG_MACRO_DIR(m4)

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

PKG_CHECK_MODULES(GLIB, glib-2.0, HAVE_GLIB=yes, HAVE_GLIB=no)

if test "x$HAVE_GLIB" = "xno"; then
  AC_MSG_ERROR(you need glib installed)
fi

AC_SUBST(GLIB_CFLAGS)
AC_SUBST(BLIG_LIBS)

AC_DEFINE(HAVE_GLIB, 1, [Defined when glib was found])

PKG_CHECK_MODULES(JSON_C, json-c, HAVE_JSON_C=yes, HAVE_JSON_C=no)

if test "x$HAVE_JSON_C" = "xno"; then
  AC_MSG_ERROR(you need json-c installed)
fi

AC_SUBST(JSON_C_CFLAGS)
AC_SUBST(JSON_C_LIBS)

AC_DEFINE(HAVE_JSON_C, 1, [Defined when json-c was found])

AC_CHECK_LIB(xenlight, libxl_name_to_domid, , AC_MSG_ERROR(You are missing libxenlight))
AC_CHECK_LIB(xenctrl, xc_altp2m_create_view, , AC_MSG_ERROR(You are missing libxenctrl))

AM_CONDITIONAL(FLYN, test "$FLYN")

AC_OUTPUT([
doc/Makefile
src/Makefile
tools/Makefile
Makefile
libguestrace-${API_VERSION}.pc
])
