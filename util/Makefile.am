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
bin_PROGRAMS += fluxtop
fluxtop_SOURCES = fluxtop.c
fluxtop_CPPFLAGS = -I$(srcdir)/../lib/libut/include -I$(srcdir)/../lib/tpl/src
fluxtop_LDADD = -L../lib -lut -ltpl -lncurses -lshr
endif

if HAVE_SQLITE3
bin_PROGRAMS += fprune ffpcap
fprune_SOURCES = fprune.c
fprune_CPPFLAGS = -I$(srcdir)/../lib/libut/include -I$(srcdir)/../lib/tpl/src
fprune_LDADD = -L../lib -lut -lshr -ltpl -lsqlite3
ffpcap_SOURCES = ffpcap.c
ffpcap_CPPFLAGS =
ffpcap_LDADD = -lshr -lsqlite3
endif
