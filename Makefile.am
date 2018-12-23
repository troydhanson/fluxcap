srcdir = @srcdir@

SUBDIRS=lib util

bin_PROGRAMS = fluxcap

fluxcap_SOURCES = fluxcap.c bb.c fluxcap.h
fluxcap_CPPFLAGS = -I$(srcdir)/lib/libut/include
fluxcap_LDADD = -Llib -lut -lshr -lm
