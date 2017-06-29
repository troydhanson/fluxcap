srcdir = @srcdir@

bin_PROGRAMS = ramdisk watch_copy
ramdisk_SOURCES = ramdisk.c
ramdisk_CPPFLAGS = -I$(srcdir)/../lib/libut/include 

watch_copy_SOURCES = watch_copy.c

if HAVE_NCURSES
bin_PROGRAMS += fluxtop
fluxtop_SOURCES = fluxtop.c
fluxtop_CPPFLAGS = -I$(srcdir)/../lib/libut/include -I$(srcdir)/../lib/tpl/src
fluxtop_LDADD = -L../lib -lut -ltpl -lncurses -lshr
endif
