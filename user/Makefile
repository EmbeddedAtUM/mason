
CFLAGS += -I../kernel/include/
CFLAGS += -Wall

all: masond masonloopd

masond: masond.c
	${CC} ${CFLAGS} -o masond masond.c

masonloopd: masonloopd.c
	${CC} ${CFLAGS} -o masonloopd masonloopd.c

clean:
	rm -rf masond
	rm -rf masonloopd
