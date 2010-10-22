dnl Process this file with autoconf to create configure.

AC_INIT([libmnl], [1.0.0-beta0])
AC_CANONICAL_TARGET
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([foreign dist-bzip2 1.6 subdir-objects])

AC_PROG_CC
AM_PROG_CC_C_O
AC_EXEEXT
AC_DISABLE_STATIC
LT_INIT
AC_SUBST(LIBTOOL_DEPS)

case $target in 
*-*-linux*) ;;
*) AC_MSG_ERROR([Linux only, dude!]);;
esac

AC_CONFIG_FILES([Makefile src/Makefile include/Makefile include/libmnl/Makefile examples/Makefile examples/genl/Makefile examples/netfilter/Makefile examples/rtnl/Makefile libmnl.pc doxygen.cfg])
AC_OUTPUT
