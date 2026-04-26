AC_PREREQ([2.69])
AC_INIT([iBoot64Patcher], m4_esyscmd([git rev-list --count HEAD | tr -d '\n']), [tihmstar@gmail.com])

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
AC_PROG_CXX
AC_PROG_CC

AM_CXXFLAGS="-std=c++17"
AM_CFLAGS="-std=c11"
AC_SUBST([AM_CXXFLAGS])
AC_SUBST([AM_CFLAGS])

# Checks for libraries.
LIBGENERAL_REQUIRES_STR="libgeneral >= 75"
LIBINSN_REQUIRES_STR="libinsn >= 1"
IMG3TOOL_REQUIRES_STR="img3tool >= 1"
IMG4TOOL_REQUIRES_STR="img4tool >= 1"
LIBPATCHFINDER_REQUIRES_STR="libpatchfinder >= 148"

PKG_CHECK_MODULES(libgeneral,      [$LIBGENERAL_REQUIRES_STR])
PKG_CHECK_MODULES(libinsn,         [$LIBINSN_REQUIRES_STR])
PKG_CHECK_MODULES(img3tool,        [$IMG3TOOL_REQUIRES_STR])
PKG_CHECK_MODULES(img4tool,        [$IMG4TOOL_REQUIRES_STR])
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
