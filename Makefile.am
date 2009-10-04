SUBDIRS = etc

sbin_PROGRAMS = ipguardd

bin_PROGRAMS = ipguard-test

ipguardd_SOURCES = ipguard-server.c ipguard-rbtree.c ipguard-server.h
ipguardd_LDADD = -lpthread

ipguard_test_SOURCES = ipguard-test.c ipguard-client.c ipguard.h
ipguard_test_CFLAGS = -DIPGUARD_PTHREADS=1 -DIPGUARD_TEST_CLIENT=1
ipguard_test_LDADD = -lpthread

install-data-hook:
	$(INSTALL) -d $(DESTDIR)$(localstatedir)/cache/ipguard
	$(INSTALL) -d $(DESTDIR)$(localstatedir)/lib/ipguard
	$(INSTALL) -m 0644 blocklist.p2p $(DESTDIR)$(localstatedir)/lib/ipguard

EXTRA_DIST =	ipguard.spec \
				blocklist.p2p \
				mod_ipguard.c \
				mod_ipguard.conf \
				autogen.sh

