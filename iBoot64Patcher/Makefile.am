AM_CFLAGS = $(GLOBAL_CFLAGS) $(libgeneral_CFLAGS) $(libpatchfinder_CFLAGS) $(libplist_CFLAGS)
AM_CXXFLAGS = $(AM_CFLAGS) $(GLOBAL_CXXFLAGS)
AM_LDFLAGS = $(libgeneral_LIBS) $(libpatchfinder_LIBS) $(libplist_LIBS)

bin_PROGRAMS = iBoot64Patcher

iBoot64Patcher_CFLAGS = $(AM_CFLAGS)
iBoot64Patcher_CXXFLAGS = $(AM_CXXFLAGS)
iBoot64Patcher_LDFLAGS = $(AM_LDFLAGS)
iBoot64Patcher_SOURCES = 	main.cpp
