AUTOMAKE_OPTIONS = foreign
SUBDIRS = src doc

EXTRA_DIST = src/coredump.h src/elf.c src/elf-compat.h doc/gencore.1 doc/gencore.3 Changelog COPYING.LIBGENCORE

if HAVE_SYSTEMD_SOCKET_SUPPORT 
EXTRA_DIST += gencore.socket gencore@.service
else
EXTRA_DIST += gencore.service
endif

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libgencore.pc

systemddir = /usr/lib/systemd
systemdir = /usr/lib/systemd/system

if HAVE_SYSTEMD_SOCKET_SUPPORT
system_DATA = gencore@.service gencore.socket
else
system_DATA = gencore.service
endif
