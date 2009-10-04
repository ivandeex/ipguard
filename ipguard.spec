%global rhel %((head -1 /etc/redhat-release 2>/dev/null || echo 0) | tr -cd 0-9 | cut -c1)
%define rdist .vitki01%{?dist}%{!?dist:.el%{rhel}}

Name:           ipguard
Version:        0.4
Release:        1%{rdist}
Summary:        Blocks connections from/to hosts listed by PeerGuardian etc.

Group:          System Environment/Daemons
License:        GPL
URL:            http://www.vitki.net/
Source0:        ipguard-%{version}.tar.gz
BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires:  httpd-devel
Requires:       httpd-mmn = %([ -a %{_includedir}/httpd/.mmn ] && %{__cat} %{_includedir}/httpd/.mmn || echo missing)

%description
ipguard lets client applications block connections from/to hosts listed in a file
in peerguardian format (guarding.p2p).

%prep
%setup -q

%build
%configure
make %{?_smp_mflags}
/usr/sbin/apxs -c mod_ipguard.c

%install
rm -rf %{buildroot}
%makeinstall
mkdir -p %{buildroot}%{_libdir}/httpd/modules 
mkdir -p %{buildroot}%{_sysconfdir}/httpd/conf.d
/usr/sbin/apxs -i -S LIBEXECDIR=%{buildroot}%{_libdir}/httpd/modules mod_ipguard.la
cp -p mod_ipguard.conf %{buildroot}%{_sysconfdir}/httpd/conf.d/ipguard.conf

%clean
rm -rf %{buildroot}

%post
if [ "$1" -eq 1 ]; then
	/sbin/chkconfig --add moblock
        /sbin/chkconfig --level 2345 moblock off
	/etc/cron.daily/moblock.cron download &> /dev/null &
fi

%preun
if [ "$1" -eq 0 ]; then
	/sbin/service moblock stop &> /dev/null
	/sbin/chkconfig --del moblock
        rm -rf %{_localstatedir}/lib/%{name}/*
        rm -rf %{_localstatedir}/cache/%{name}/*
        rm -rf %{_localstatedir}/log/%{name}*
        rm -f  %{_localstatedir}/log/MoBlock.stats
fi

%postun
if [ "$1" -ge 1 ]; then
	/sbin/service moblock condrestart &> /dev/null
fi

%files
%defattr(-,root,root,-)

%doc AUTHORS ChangeLog COPYING INSTALL NEWS README
%dir %{_sysconfdir}/%{name}
%config(noreplace) %{_sysconfdir}/%{name}/blocklists
%config(noreplace) %{_sysconfdir}/%{name}/whitelist
%attr(0755,root,root) %{_sysconfdir}/rc.d/init.d/%{name}
%attr(0755,root,root) %{_sysconfdir}/cron.daily/%{name}.cron
%{_sysconfdir}/logrotate.d/%{name}
%{_localstatedir}/lib/%{name}
%{_localstatedir}/lib/%{name}/blocklist.p2p
%{_localstatedir}/cache/%{name}
%{_libexecdir}/%{name}

%{_libdir}/httpd/modules/mod_ipguard.so
%config(noreplace) %{_sysconfdir}/httpd/conf.d/ipguard.conf

%changelog
* Sun Sep 27 2009  RPM Admin <rpmadmin@vitki.net> 0.9rc2-1.vitki01
- Port 0.9rc2 to CentOS

* Thu Aug 23 2007  Akihiro TSUKADA <atsukada AT users.sourceforge.net> 0.8-2
- fiexed error in cron.daily/moblock.cron script, loglotate.d/moblock

* Mon Aug 20 2007  Akihiro TSUKADA <atsukada AT users.sourceforge.net> 0.8-1
- initial release
- changed the locations of supporting files (cache etc.)
- moved the rules for allowing lo <-> lo communications to MOBLOCK chain
- surpressed errors for missing blocklist, allowing it to be created afterward
- removed some log outputs from blocklist merging
