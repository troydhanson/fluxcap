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

if HAVE_PCRE
bin_PROGRAMS += fwalk
fwalk_SOURCES = fwalk.c
fwalk_CPPFLAGS = -I$(srcdir)/../lib/libut/include
fwalk_LDADD = -L../lib -lut -lshr -lpcre
endif

if HAVE_ZLIB
bin_PROGRAMS += fpcap-push
fpcap_push_SOURCES = fpcap-push.c
fpcap_push_CPPFLAGS = -I$(srcdir)/../lib/libut/include
fpcap_push_LDADD = -L../lib -lut -lshr -lz
endif

bin_PROGRAMS += fprune
fprune_SOURCES = fprune.c
fprune_CPPFLAGS = -I$(srcdir)/../lib/libut/include
fprune_LDADD = -L../lib -lut -lshr

if HAVE_NCURSES
endif

if HAVE_SQLITE3
endif

