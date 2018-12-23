srcdir = @srcdir@

SUBDIRS=

# build these external libraries as convenience libs

noinst_LIBRARIES = libut.a

libut_a_CFLAGS = -Wall -Wextra
libut_a_CPPFLAGS = -I$(srcdir)/libut/include
libut_a_SOURCES = libut/src/libut.c    \
                  libut/src/utvector.c \
                  libut/src/utmm.c     \
                  libut/src/ringbuf.c

