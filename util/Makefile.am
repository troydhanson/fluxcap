srcdir = @srcdir@

bin_PROGRAMS = ramdisk watch_copy
ramdisk_SOURCES = ramdisk.c
ramdisk_CPPFLAGS = -I$(srcdir)/../lib/libut/include 
watch_copy_SOURCES = watch_copy.c

if HAVE_PCRE
if HAVE_ZLIB
bin_PROGRAMS += ffcp
ffcp_SOURCES = ffcp.c
ffcp_CPPFLAGS = -I$(srcdir)/../lib/libut/include
ffcp_LDADD = -L../lib -lut -lshr -lpcre -lz
endif
endif

if HAVE_NCURSES
endif

if HAVE_SQLITE3
endif

bin_PROGRAMS += fpcap-replay
fpcap_replay_SOURCES = fpcap-replay.c
fpcap_replay_CPPFLAGS = -I$(srcdir)/../lib/libut/include -I$(srcdir)/../lib/flatner
fpcap_replay_LDADD = -L../lib -lflatner -lut -lshr

bin_PROGRAMS += fprune
fprune_SOURCES = fprune.c
fprune_CPPFLAGS = -I$(srcdir)/../lib/libut/include
fprune_LDADD = -L../lib -lut -lshr
