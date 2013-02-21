AC_INIT(crackxls2003, 0)

AC_ARG_WITH([algo], [--with-algo - Choice of algorithm])

if test "x$with_algo" = xsolar; then
	AC_DEFINE([USE_SOLAR], [1], [Choice of algorithm])
	AC_SUBST([ALGO_FILES], [solar-md5/md5.c])
elif test "x$with_algo" = xasm; then
	AC_DEFINE([USE_ASM], [1], [Choice of algorithm])
	AC_SUBST([ALGO_FILES], [asm-md5/md5-fast.S])
else
	:
fi

dnl AC_CHECK_LIB(gomp, )
dnl AC_C_BIGENDIAN
dnl AC_OPENMP
dnl check endianness, can we use x86 assembler, etc.

AC_CONFIG_HEADERS(config.h)
AC_CONFIG_FILES(Makefile)
AC_OUTPUT 
