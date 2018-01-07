srcdir = @srcdir@

SUBDIRS=

# build these external libraries as convenience libs

noinst_LIBRARIES = libut.a libtpl.a libflatner.a

libut_a_CFLAGS = -Wall -Wextra
libut_a_CPPFLAGS = -I$(srcdir)/libut/include
libut_a_SOURCES = libut/src/libut.c    \
                  libut/src/utvector.c \
                  libut/src/utmm.c     \
                  libut/src/ringbuf.c

libtpl_a_CFLAGS = -Wall 
libtpl_a_CPPFLAGS = -I$(srcdir)/tpl/src
libtpl_a_SOURCES = tpl/src/tpl.c

libflatner_a_CFLAGS = -Wall -Wextra
libflatner_a_CPPFLAGS = -I$(srcdir)/libut/include
libflatner_a_SOURCES = flatner/flatner.c
