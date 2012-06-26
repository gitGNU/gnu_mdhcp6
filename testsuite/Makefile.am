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

CC = @CC_FOR_BUILD@
HAVE_CHECK = @HAVE_CHECK@
AM_CPPFLAGS = -DOVERRIDE_DH6_CLOSE=1
CFLAGS = @CFLAGS@ -UNDEBUG

# set it here to avoid duplicating it
INCLUDES = @CHECK_CFLAGS@

if HAVE_CHECK
MDHCP6_SOURCES    = $(top_srcdir)/src/mdhcp6.c $(top_srcdir)/src/mdhcp6.h
LEASE_SOURCES     = $(top_srcdir)/src/lease.c $(top_srcdir)/src/lease.h
OMAP_SOURCES      = $(top_srcdir)/src/optionmap.c $(top_srcdir)/src/optionmap.h
MSGBUF_SOURCES    = $(top_srcdir)/src/msgbuf.c $(top_srcdir)/src/msgbuf.h
RANDOM_SOURCES    = $(top_srcdir)/src/random.c $(top_srcdir)/src/random.h
PTIME_SOURCES     = $(top_srcdir)/src/ptime.c $(top_srcdir)/src/ptime.h
DHCPV6_SOURCES    = dhcpv6_instr.c $(top_srcdir)/src/dhcpv6.h
#IF_SOURCES        = $(top_srcdir)/src/if.c $(top_srcdir)/src/if.h
IF_INSTR_SOURCES  = if_instr.c if.h
NOTIFY_INSTR_SOURCES  = notify_instr.c notify.h
NETLINK_SOURCES   = $(top_srcdir)/src/netlink.c $(top_srcdir)/src/netlink.h
NET_INSTR_SOURCES = net_instr.c $(top_srcdir)/src/net.h

# we need access to the actual code in src
INCLUDES += -I. -I$(top_srcdir)/src/

# tests to run
TESTS  = check_mdhcp6
TESTS += check_msgbuf
TESTS += check_lease
TESTS += check_dhcpv6

# define sources for each testcase
check_msgbuf_SOURCES  = check_msgbuf.c
check_msgbuf_SOURCES += $(MSGBUF_SOURCES)
check_msgbuf_LDADD    = @CHECK_LIBS@

check_lease_SOURCES  = check_lease.c
check_lease_SOURCES += $(LEASE_SOURCES)
check_lease_SOURCES += $(OMAP_SOURCES)
check_lease_SOURCES += $(DHCPV6_SOURCES)
check_lease_SOURCES += $(NET_INSTR_SOURCES)
check_lease_SOURCES += $(IF_INSTR_SOURCES)
check_lease_SOURCES += $(MSGBUF_SOURCES)
check_lease_SOURCES += $(PTIME_SOURCES)
check_lease_SOURCES += $(RANDOM_SOURCES)
check_lease_LDADD    = @CHECK_LIBS@

check_dhcpv6_SOURCES  = check_dhcpv6.c
check_dhcpv6_SOURCES += $(DHCPV6_SOURCES) $(MSGBUF_SOURCES) $(RANDOM_SOURCES)
check_dhcpv6_SOURCES += $(IF_INSTR_SOURCES) $(NETLINK_SOURCES) $(PTIME_SOURCES)
check_dhcpv6_SOURCES += $(NET_INSTR_SOURCES)
check_dhcpv6_LDADD    = @CHECK_LIBS@

check_mdhcp6_SOURCES  = check_mdhcp6.c
check_mdhcp6_SOURCES += $(MDHCP6_SOURCES) $(LEASE_SOURCES) 
check_mdhcp6_SOURCES += $(OMAP_SOURCES) $(NET_INSTR_SOURCES)
check_mdhcp6_SOURCES += $(DHCPV6_SOURCES) $(MSGBUF_SOURCES) $(RANDOM_SOURCES)
check_mdhcp6_SOURCES += $(IF_INSTR_SOURCES) $(NETLINK_SOURCES) $(PTIME_SOURCES)
check_mdhcp6_SOURCES += $(NOTIFY_INSTR_SOURCES)
check_mdhcp6_LDADD    = @CHECK_LIBS@

# dont install any test-cases
noinst_PROGRAMS = $(TESTS)

else
check check-TESTS: check-not-installed
.PHONY: check-not-installed
check-not-installed:
	echo "Install check >= 0.9.4 to run the testsuite."
	@false
endif
