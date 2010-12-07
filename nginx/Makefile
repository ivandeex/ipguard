
IPG_VERSION = 0.6
NGX_VERSION = 0.8.52
VENDOR = vitki
VERSION = $(NGX_VERSION)-$(IPG_VERSION)-$(VENDOR)
TARBALL = nginx_http_ipguard-$(VERSION).tar.gz
SOURCES = \
	ngx_http_ipguard_module.c

dist: CHANGES README LICENSE config $(SOURCES)
	cd .. && f=`readlink -f ../$(TARBALL)` && tar czf $$f --exclude .svn * && echo $$f

