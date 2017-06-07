AC_INIT([mtraceroute], [0.7], [rlca@dcc.ufmg.br])
AM_INIT_AUTOMAKE([foreign -Wall -Werror])

AC_GNU_SOURCE

AC_PROG_CC
AC_PROG_CC_STDC
# AC_PROG_INSTALL
# AC_PROG_LN_S

AC_CHECK_LIB([pthread], [pthread_create], [], [exit 1;])
AC_CHECK_LIB([pthread], [pthread_mutex_init], [], [exit 1;])
AC_CHECK_LIB([pcap], [pcap_loop], [], [exit 1;])

AC_CHECK_HEADERS([stdlib.h stddef.h stdio.h string.h unistd.h], [], [exit 1;])
AC_CHECK_HEADERS([time.h pthread.h limits.h fcntl.h], [], [exit 1;])
AC_CHECK_HEADERS([assert.h inttypes.h], [], [exit 1;])
AC_CHECK_HEADERS([arpa/inet.h], [], [exit 1;])
AC_CHECK_HEADERS([sys/resource.h], [], [exit 1;])
AC_CHECK_HEADERS([asm/types.h], [], [exit 1;])
AC_CHECK_HEADERS([linux/rtnetlink.h], [], [exit 1;])
AC_CHECK_HEADERS([linux/netlink.h], [], [exit 1;])

AC_CHECK_FUNCS([strchr strdup strerror], [], [exit 1;])
AC_CHECK_FUNCS([memset], [], [exit 1;])

AC_FUNC_MALLOC

AC_TYPE_UINT8_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_SIZE_T
AC_TYPE_OFF_T

AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile src/Makefile])

AC_OUTPUT
