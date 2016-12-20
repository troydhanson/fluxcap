srcdir = @srcdir@

bin_PROGRAMS = ramdisk
ramdisk_SOURCES = ramdisk.c
ramdisk_CPPFLAGS = -I$(srcdir)/../lib/uthash/libut/include 

if HAVE_NCURSES
bin_PROGRAMS += fluxtop
fluxtop_SOURCES = fluxtop.c
fluxtop_CPPFLAGS = -I$(srcdir)/../lib/shr -I$(srcdir)/../lib/uthash/libut/include -I$(srcdir)/../lib/tpl/src
fluxtop_LDADD = -L../lib -lut -ltpl -L../lib/shr -lshr -lncurses
endif
