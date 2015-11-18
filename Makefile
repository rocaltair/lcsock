LIB = lcsock.so
OBJS = lcsock.o

LLIBS = -llua
CFLAGS = -c -O3 -Wall -fPIC
LDFLAGS = -O3 --shared

all : $(LIB)

$(LIB): $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS) $(LLIBS)

$(OBJS) : %.o : %.c
	$(CC) -o $@ $(CFLAGS) $<

clean : 
	rm -f $(OBJS) $(LIB)

.PHONY : clean

