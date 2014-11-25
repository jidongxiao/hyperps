DIR_INC = ./include
DIR_SRC = ./src
DIR_OBJ = ./obj
DIR_BIN = ./bin
 
SRC = $(wildcard ${DIR_SRC}/*.c)
OBJ = $(patsubst %.c,${DIR_OBJ}/%.o,$(notdir ${SRC})) 

TARGET = main

BIN_TARGET = ${DIR_BIN}/${TARGET}

CC = gcc
LDADD = -lrt
CFLAGS = -g -Wall -I${DIR_INC} -fomit-frame-pointer -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64 -DDEBUG

${BIN_TARGET}:${OBJ}
	$(CC) $(OBJ)  -o $@ $(LDADD)
     
${DIR_OBJ}/%.o:${DIR_SRC}/%.c
	$(CC) $(CFLAGS) -c  $< -o $@

.PHONY:clean
clean:
	find ./obj -name *.o | xargs rm -f
