
IPG_VERSION = 0.7
NGX_VERSION = 1.2.0
VENDOR = vitki
VERSION = $(NGX_VERSION)-$(IPG_VERSION)-$(VENDOR)
TARBALL = nginx_http_ipguard-$(VERSION).tar.gz
SOURCES = \
	ngx_http_ipguard_module.c

dist: CHANGES README LICENSE config $(SOURCES)
	cd .. && f=`readlink -f ../$(TARBALL)` && tar czf $$f --exclude .svn * && echo $$f

