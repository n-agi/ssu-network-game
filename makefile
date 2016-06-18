CC = gcc
OBJS = main.o
TARGET = game_server

.SUFFIXES = .c .o
all : $(TARGET)
$(TARGET): $(OBJS)
	     $(CC) -O3 -o $@ $(OBJS) -lsqlite3 -lcrypto -ljson
clean :
	rm -f $(OBJS) $(TARGET) 
