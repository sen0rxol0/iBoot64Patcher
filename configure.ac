AC_PREREQ([2.69])
AC_INIT([iBoot64Patcher], [1.0])

AC_CANONICAL_HOST
AM_INIT_AUTOMAKE([subdir-objects foreign])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIRS([m4])

LT_PREREQ([2.4])
LT_INIT([static])

AC_DEFINE([VERSION_COMMIT_COUNT], "m4_esyscmd([git rev-list --count HEAD | tr -d '\n'])", [Git commit count])
AC_DEFINE([VERSION_COMMIT_SHA],   "m4_esyscmd([git rev-parse HEAD | tr -d '\n'])",          [Git commit sha])
AC_SUBST([VERSION_COMMIT_COUNT],  ["m4_esyscmd([git rev-list --count HEAD | tr -d '\n'])"])
AC_SUBST([VERSION_COMMIT_SHA],    ["m4_esyscmd([git rev-parse HEAD | tr -d '\n'])"])

# Checks for programs.
AC_PROG_CXX([clang++])
AC_PROG_CC([clang])

# CXXFLAGS="$CXXFLAGS -std=c++17 -O3 -fPIC"
# CFLAGS="$CFLAGS -std=c11 -fPIC"
GLOBAL_CXXFLAGS="-std=c++17 -O3 -fPIC"
GLOBAL_CFLAGS="-std=c11 -fPIC"
AC_SUBST([GLOBAL_CFLAGS])
AC_SUBST([GLOBAL_CXXFLAGS])

# Checks for libraries.
LIBGENERAL_REQUIRES_STR="libgeneral >= 75"
LIBPATCHFINDER_REQUIRES_STR="libpatchfinder >= 148"

PKG_CHECK_MODULES(libgeneral,      [$LIBGENERAL_REQUIRES_STR])
PKG_CHECK_MODULES(libpatchfinder,  [$LIBPATCHFINDER_REQUIRES_STR])

AC_CONFIG_FILES([Makefile
                 iBoot64Patcher/Makefile])

AC_OUTPUT

echo "
Configuration for $PACKAGE-$VERSION:
-------------------------------------------

  install prefix ..........: $prefix
  compiler ................: ${CC}

  Now type 'make' to build $PACKAGE-$VERSION,
  and then 'make install' for installation.
"
