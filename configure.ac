AC_INIT(crackxls2003, 0)

dnl Get definition of pkg-config macros
m4_include(aclocal.m4)

# Define CC and CXX
AC_PROG_CC
AC_PROG_CXX

AC_SUBST(OPT_LIBS)
AC_SUBST(OPT_OBJS)

AC_ARG_WITH([algo], [--with-algo - Choice of algorithm])

if test "x$with_algo" = xasm; then
	AC_DEFINE([USE_ASM], [1], [Choice of algorithm])
	OPT_OBJS="$OPT_OBJS asm-md5/md5-fast.o"
else
	AC_DEFINE([USE_REGULAR], [1], [Choice of algorithm])
	OPT_OBJS="$OPT_OBJS solar-md5/md5.o"
fi

AC_CHECK_LIB(crypto, MD5_Init, ,AC_MSG_ERROR([OpenSSL is required to build]))

# Used for uint8_t etc.
AC_PROG_CC_C99
if test "x$ac_cv_prog_cc_c99" = xno; then
	AC_MSG_ERROR([C99 is required to build])
fi

# Used to calculate key testing rate
# libgmp symbols begin with __gmp
AC_CHECK_LIB(gmp, __gmpz_add)

AC_ARG_WITH([libgsf],
    [--without-libgsf - Disable use of libgsf to decrypt files],,
    with_libgsf=yes)

# Check for libgsf
# Sets LIBGSF_CFLAGS and LIBGSF_LIBS
PKG_CHECK_MODULES(LIBGSF, [libgsf-1 >= 0],,
  AC_MSG_NOTICE([libgsf not found: support for decrypting disabled])
  with_libgsf=no)

PKG_CHECK_MODULES(LIBXML2, [libxml-2.0 >= 0],,
  AC_MSG_NOTICE([libxml2 not found: suppport for decrypting disabled])
  with_libgsf=no)

if test "x$with_libgsf" = xyes; then
	OPT_OBJS="$OPT_OBJS decrypt.o"
	AC_DEFINE([HAVE_LIBGSF], 1, [libgsf])
fi

AC_C_BIGENDIAN(AC_MSG_ERROR([A little-endian machine architecture is required]))

AC_CHECK_HEADERS([signal.h])

AC_CONFIG_HEADERS(config.h)
AC_CONFIG_FILES(Makefile)
AC_OUTPUT 
