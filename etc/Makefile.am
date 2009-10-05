nobase_dist_sysconf_DATA = \
	cron.daily/ipguard.cron \
	logrotate.d/ipguard \
	ipguard/blocklists \
	ipguard/whitelist \
	ipguard/localblocklist \
	rc.d/init.d/ipguard

install-data-hook:
	chmod +x $(DESTDIR)$(sysconfdir)/cron.daily/ipguard.cron
	chmod +x $(DESTDIR)$(sysconfdir)/rc.d/init.d/ipguard
