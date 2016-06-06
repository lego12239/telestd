TARGET := telestd
OBJ :=  xmalloc.o dframe.o main.o

export STRIP ?= strip
export CFLAGS += -Wall

ifdef DEBUG
	CFLAGS += -g3 -DDEBUG -ggdb
	STRIP := echo
endif


all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) -static -o $@ $^ $(LDFLAGS)
#	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)
	$(STRIP) $@

clean-all: clean
	rm -f $(TARGET)

clean:
	rm -f *~ $(OBJ)

%.o: %.c
	$(CC) $(CFLAGS) -o $@ -c $<

