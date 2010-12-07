%global rhel %((head -1 /etc/redhat-release 2>/dev/null || echo 0) | tr -cd 0-9 | cut -c1)
%define rdist .vitki.02%{?dist}%{!?dist:.el%{rhel}}

%global apxs %{_sbindir}/apxs

Name:           ipguard
Version:        0.5
Release:        %{rdist}
Summary:        Blocks connections from/to hosts listed by PeerGuardian etc.

Group:          System Environment/Daemons
License:        GPL
URL:            http://www.vitki.net/
Source0:        ipguard-%{version}.tar.gz
BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires:  httpd-devel
Requires:       p7zip
Requires:       httpd-mmn = %([ -a %{_includedir}/httpd/.mmn ] && %{__cat} %{_includedir}/httpd/.mmn || echo missing)

%description
ipguard lets client applications block connections from/to hosts listed in a file
in peerguardian format (guarding.p2p).

%prep
%setup -q

%build
%configure
make %{?_smp_mflags}
%apxs -Wc,-Wall -Wc,-Werror -c mod_ipguard.c

%install
rm -rf %{buildroot}
%makeinstall
mkdir -p %{buildroot}%{_libdir}/httpd/modules 
mkdir -p %{buildroot}%{_sysconfdir}/httpd/conf.d
%apxs -i -S LIBEXECDIR=%{buildroot}%{_libdir}/httpd/modules mod_ipguard.la
cp -p mod_ipguard.conf %{buildroot}%{_sysconfdir}/httpd/conf.d/ipguard.conf

%clean
rm -rf %{buildroot}

%post
if [ "$1" -eq 1 ]; then
    /sbin/chkconfig --add ipguard
    /sbin/chkconfig --level 2345 ipguard off
    /etc/cron.daily/ipguard.cron download &> /dev/null &
fi

%preun
if [ "$1" -eq 0 ]; then
    /sbin/service ipguard stop &> /dev/null
    /sbin/chkconfig --del ipguard
    rm -rf %{_localstatedir}/lib/%{name}/*
    rm -rf %{_localstatedir}/cache/%{name}/*
    rm -rf %{_localstatedir}/log/%{name}*
    rm -f  %{_localstatedir}/log/%{name}.stats
fi

%postun
if [ "$1" -ge 1 ]; then
    /sbin/service ipguard condrestart &> /dev/null
fi

%files
%defattr(-,root,root,-)

%doc AUTHORS ChangeLog COPYING INSTALL NEWS README
%dir %{_sysconfdir}/%{name}
%config(noreplace) %{_sysconfdir}/%{name}/blocklists
%config(noreplace) %{_sysconfdir}/%{name}/whitelist
%config(noreplace) %{_sysconfdir}/%{name}/localblocklist
%attr(0755,root,root) %{_sysconfdir}/rc.d/init.d/%{name}
%attr(0755,root,root) %{_sysconfdir}/cron.daily/%{name}.cron
%{_sysconfdir}/logrotate.d/%{name}
%{_localstatedir}/lib/%{name}
%config(noreplace) %{_localstatedir}/lib/%{name}/blocklist.p2p
%{_localstatedir}/cache/%{name}
%{_bindir}/%{name}-test
%{_sbindir}/%{name}d

%{_libdir}/httpd/modules/mod_ipguard.so
%config(noreplace) %{_sysconfdir}/httpd/conf.d/ipguard.conf

%changelog
* Tue Dec  7 2010  vitki <vitki@vitki.net> 0.9rc2-vitki.02
- add nginx module

* Sun Oct  4 2009  RPM Admin <rpmadmin@vitki.net> 0.9rc2-1.vitki01
- port to centos

* Mon Aug 20 2007  Akihiro TSUKADA <atsukada AT users.sourceforge.net> 0.8-1
- initial release

