srcdir = @srcdir@

SUBDIRS=lib util

bin_PROGRAMS = fluxcap

fluxcap_SOURCES = fluxcap.c
fluxcap_CPPFLAGS = -I$(srcdir)/lib/shr -I$(srcdir)/lib/uthash/libut/include
fluxcap_LDADD = -Llib -lut -Llib/shr -lshr
