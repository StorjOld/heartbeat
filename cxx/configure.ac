#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

m4_include([AX_CXX_COMPILE_STDCXX_11.m4])

AC_PREREQ([2.68])
AC_INIT([heartbeat_cxx], [0.1], [jameswt@gmail.com])
AC_CONFIG_AUX_DIR(config)
AM_INIT_AUTOMAKE([foreign -Wall -Werror])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile])

# Checks for programs.
AC_PROG_CXX

AX_CXX_COMPILE_STDCXX_11

# Checks for libraries.

# Checks for header files.

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL

# Checks for library functions.

AC_CHECK_FUNCS(__builtin_clz,[HAVE_GNU_CLZ=1],[HAVE_GNU_CLZ=0])
AC_CHECK_FUNCS(__lzcnt,[HAVE_VS_LZCNT=1],[HAVE_VS_LZCNT=0])

AC_OUTPUT