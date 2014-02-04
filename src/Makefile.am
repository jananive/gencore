AUTOMAKE_OPTIONS = foreign
HAVE_SYSTEMD_SOCKET_SUPPORT = 0
SOCKET_PATH = /var/run/gencored.socket
CFLAGS += -I. -DHAVE_SYSTEMD_SOCKET_SUPPORT='$(HAVE_SYSTEMD_SOCKET_SUPPORT)' -DSOCKET_PATH='"$(SOCKET_PATH)"'

include_HEADERS = gencore.h
lib_LTLIBRARIES = libgencore.la
libgencore_la_LDFLAGS = -fPIC
libgencore_la_SOURCES = client.c

bin_PROGRAMS = gencore
gencore_SOURCES = coredump.c proc.c elf32.c elf64.c

