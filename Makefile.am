srcdir = @srcdir@

SUBDIRS=lib util

bin_PROGRAMS = fluxcap

fluxcap_SOURCES = fluxcap.c fluxcap.h
fluxcap_CPPFLAGS = -I$(srcdir)/lib/libut/include
fluxcap_LDADD = -Llib -lut -lshr

if HAVE_NCURSES
fluxcap_SOURCES += fviewer-ncurses.c
fluxcap_LDADD += -lncurses
else
fluxcap_SOURCES += fviewer-text.c
endif
