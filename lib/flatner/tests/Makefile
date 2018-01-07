SRCS=$(wildcard test*.c)
PROGS=$(patsubst %.c,%,  $(SRCS))
OBJS= $(patsubst %.c,%.o,$(SRCS))

all: $(PROGS) tests

CFLAGS  = -I../
CFLAGS += -g
LDFLAGS = -L ../libut -lut

$(OBJS): %.o: %.c
	$(CC) -c $(CFLAGS) $<

$(PROGS): %: %.o
	$(CC) -o $@ $(CFLAGS) $< ../flatner.o $(LDFLAGS)


.PHONY: clean tests

tests:
	perl ./do_tests

clean:
	rm -f $(OBJS) $(PROGS) *.out
