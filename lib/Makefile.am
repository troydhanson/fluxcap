srcdir = @srcdir@

SUBDIRS=shr

# build these external libraries as convenience libs

noinst_LIBRARIES = libut.a libtpl.a

libut_a_CFLAGS = -Wall -Wextra
libut_a_CPPFLAGS = -I$(srcdir)/uthash/libut/include
libut_a_SOURCES = uthash/libut/src/libut.c    \
                  uthash/libut/src/utvector.c \
                  uthash/libut/src/utmm.c     \
                  uthash/libut/src/ringbuf.c

libtpl_a_CFLAGS = -Wall 
libtpl_a_CPPFLAGS = -I$(srcdir)/tpl/src
libtpl_a_SOURCES = tpl/src/tpl.c
