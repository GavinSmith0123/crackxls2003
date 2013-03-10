AC_INIT(crackxls2003, 0)

dnl Get definition of pkg-config macros
m4_include(aclocal.m4)

AC_ARG_WITH([algo], [--with-algo - Choice of algorithm])

if test "x$with_algo" = xsolar; then
	AC_DEFINE([USE_SOLAR], [1], [Choice of algorithm])
	AC_SUBST([ALGO_FILES], [solar-md5/md5.c])
elif test "x$with_algo" = xasm; then
	AC_DEFINE([USE_ASM], [1], [Choice of algorithm])
	AC_SUBST([ALGO_FILES], [asm-md5/md5-fast.S])
else
	AC_DEFINE([USE_REGULAR], [1], [Choice of algorithm])
fi

AC_CHECK_LIB(ssl, MD5_Init, ,AC_MSG_ERROR([OpenSSL is required to build]))

# Used for uint8_t etc.
AC_PROG_CC_C99
if test "x$ac_cv_prog_cc_c99" = xno; then
	AC_MSG_ERROR([C99 is required to build])
fi

# Used to calculate key testing rate
# libgmp symbols begin with __gmp
AC_CHECK_LIB(gmp, __gmpz_add)

# Check for libgsf
AC_CHECK_LIB(gsf-1, gsf_input_size)
PKG_CHECK_MODULES(LIBGSF, [libgsf-1 >= 0])

AC_C_BIGENDIAN(AC_MSG_ERROR([A little-endian machine architecture is required]))

AC_CONFIG_HEADERS(config.h)
AC_CONFIG_FILES(Makefile)
AC_OUTPUT 
