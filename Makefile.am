srcdir = @srcdir@

SUBDIRS=lib util

bin_PROGRAMS = fluxcap

fluxcap_SOURCES = fluxcap.c
fluxcap_CPPFLAGS = -I$(srcdir)/lib/shr/src -I$(srcdir)/lib/libut/include
fluxcap_LDADD = -Llib -lut -Llib/shr/src -lshr
