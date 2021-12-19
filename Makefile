
CC ?= cc -g -O2

LIBSRC = pam_sqlite.c
LIBOBJ = pam_sqlite.o pam_get_pass.o pam_std_option.o pam_get_service.o
LIBLIB = pam_sqlite.so

LDLIBS = -lcrypt -lpam -lsqlite3 -lpam_misc

INCLUDE = -I/usr/include

CFLAGS = -fPIC -DPIC -Wall -D_GNU_SOURCE ${INCLUDE}

${LIBLIB}: ${LIBOBJ}
	${CC} ${CFLAGS} ${INCLUDE} -shared -o $@ ${LIBOBJ} ${LDLIBS} 

test: test.c
	${CC} ${CFLAGS} -o $@ test.c ${LDLIBS}

clean:
	rm -f ${LIBOBJ} ${LIBLIB} core test *~ 
