AC_INIT([Gencore], [0.1], [jananive@linux.vnet.ibm.com], [gencore], [])
LT_INIT()
AM_INIT_AUTOMAKE([-Wall -Werror foreign])
AC_CONFIG_HEADERS([config.h])
AC_PROG_CC
AC_CONFIG_FILES(Makefile gencore.spec libgencore.pc)
AM_CONDITIONAL(HAVE_SYSTEMD_SOCKET_SUPPORT, test "have_systemd_socket_support" = false)
AC_OUTPUT(src/Makefile doc/Makefile)
