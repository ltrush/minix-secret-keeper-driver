# Makefile for the secret driver.
PROG=	secret
SRCS=	secret.c

DPADD+=	${LIBDRIVER} ${LIBSYS}
LDADD+=	-ldriver -lsys

MAN=

BINDIR?= /usr/sbin

.include <bsd.prog.mk>
