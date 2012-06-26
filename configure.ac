#
# Copyright (C) 2005 Axis Communications AB
#
# This file is part of Mini DHCP6.
#
# mdhcp6 is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# (at your option) any later version.
#
# mdhcp6 is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with mdhcp6.  If not, see <http://www.gnu.org/licenses/>. 
#
# Authors: Edgar E. Iglesias <edgar@axis.com>
#

AC_INIT([mdhcp6],
        [0.2.24],
        [Edgar E. Iglesias edgar.iglesias@axis.com],
        [mdhcp6}])
AC_CONFIG_AUX_DIR(config)
AM_CONFIG_HEADER(src/config.h)
AM_INIT_AUTOMAKE([dist-bzip2])

AC_PROG_CC

AC_ARG_VAR(CC_FOR_BUILD,[build system C compiler])
# Check for environment variable CC_FOR_BUILD before overwriting it
if test -z "$CC_FOR_BUILD"; then
	CC_FOR_BUILD=$CC
fi
AC_SUBST(CC_FOR_BUILD) 

AC_PROG_INSTALL
AC_AIX
AC_ISC_POSIX
AC_MINIX
AC_STDC_HEADERS
AC_PROG_RANLIB

dnl sysinfo() may exist but not be Linux compatible
AC_MSG_CHECKING(for sysinfo)
AC_TRY_COMPILE(
[
#include <sys/types.h>
#include <sys/sysinfo.h>
],
[	struct sysinfo sinfo;
	int t;

	(void)sysinfo(&sinfo);
	t = sinfo.totalram;
	],
	AC_MSG_RESULT(yes); AC_DEFINE([HAVE_SYSINFO], [1], [has sysinfo]),
	AC_MSG_RESULT(not usable))

AC_MSG_CHECKING(for netlink)
AC_TRY_COMPILE(
[
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>
],
[	int s;
	s = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	],
	AC_MSG_RESULT(yes); AC_DEFINE([HAVE_NETLINK], [1], [has netlink]),
	AC_MSG_RESULT(not usable))

AC_MSG_CHECKING(for SIOCGIFHWADDR)
AC_TRY_COMPILE(
[
#include <stdio.h>
#include <sys/ioctl.h>
],
[
        int i = SIOCGIFHWADDR;
	],
	AC_MSG_RESULT(yes); AC_DEFINE([HAVE_SIOCGIFHWADDR], [1], 
				      [has SIOCGIFHWADDR]),
	AC_MSG_RESULT(not usable))


dnl check for getifaddrs
AC_MSG_CHECKING(for getifaddrs)
AC_TRY_COMPILE(
[
#include <sys/types.h>
#include <sys/socket.h>
#include <ifaddrs.h>
],
[
	struct ifaddrs *ifa;
	getifaddrs(&ifa);
	],
	AC_MSG_RESULT(yes); AC_DEFINE([HAVE_GETIFADDRS], [1], 
				      [has getifaddrs]),
	AC_MSG_RESULT(not usable))

dnl check for sockaddr_dl
AC_MSG_CHECKING(for sockaddr_dl)
AC_TRY_COMPILE(
[
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if_dl.h>
],
[
	struct sockaddr_dl sa;
	],
	AC_MSG_RESULT(yes); 
	AC_DEFINE([HAVE_SOCKADDR_DL], [1], [has sockaddr_dl]),
	AC_MSG_RESULT(not usable))

# check for libcheck
# how?
have_check=no
dnl check for check
PKG_CHECK_MODULES(CHECK, check >= "0.9.4",
[
	have_check=yes
	AC_SUBST(CHECK_CFLAGS)
	AC_SUBST(CHECK_LIBS)
],
[ 
	AC_MSG_WARN([check $CHECK_REQUIRED or greater not found, unit tests will be disabled.])
])
AM_CONDITIONAL(HAVE_CHECK, test x"$have_check" = "xyes")

AC_CONFIG_FILES([
   Makefile
   README
   doc/Makefile
   m4/Makefile
   src/Makefile
   testsuite/Makefile
])

AC_OUTPUT
