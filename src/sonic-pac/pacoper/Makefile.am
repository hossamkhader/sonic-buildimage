INCLUDES =  -I $(top_srcdir)/pacoper -I $(top_srcdir)/authmgr/common -I $(top_srcdir)/authmgr/mapping/include -I $(top_srcdir)/authmgr/protocol/include -I $(top_srcdir)/fpinfra/inc

lib_LTLIBRARIES = libpacoper.la 

if DEBUG
DBGFLAGS = -ggdb -DDEBUG
else
DBGFLAGS = -g -DNDEBUG
endif


libpacoper_la_SOURCES = $(top_srcdir)/pacoper/pacoper.cpp $(top_srcdir)/authmgr/protocol/ipv6_profile.c

# CFLAGS_COMMON carries C++-only options (-std=c++11, -Wno-reorder), so it
# must not reach the C source (ipv6_profile.c) in this library.
AM_CPPFLAGS = $(DBGFLAGS) $(SONIC_COMMON_CFLAGS) -I/usr/include/libnl3 -I/usr/include/swss
AM_CXXFLAGS = $(CFLAGS_COMMON)
AM_CFLAGS = -Wall -Werror -fPIC
#libipacoper_la_CPPFLAGS = $(DBGFLAGS) $(CFLAGS_COMMON)

libpacoper_la_LIBADD = -lswsscommon -lnl-3 -lnl-route-3 -lhiredis $(SONIC_COMMON_LDFLAGS) -L$(top_srcdir)/fpinfra -lfpinfra
