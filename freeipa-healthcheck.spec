%global project freeipa
%global projectname FreeIPA
%global shortname healthcheck
%global longname ipa%{shortname}
%global debug_package %{nil}
%global python3dir %{_builddir}/python3-%{name}-%{version}-%{release}
%{!?python3_sitelib: %global python3_sitelib %(%{__python3} -c "from distutils.sysconfig import get_python_lib; print(get_python_lib())")}


Name:           %{project}-%{shortname}
Version:        0.5
Release:        1%{?dist}
Summary:        Health check tool for %{projectname}
BuildArch:      noarch
License:        GPLv3
URL:            https://github.com/freeipa/freeipa-healthcheck
Source0:        https://github.com/freeipa/freeipa-healthcheck/archive/%{version}.tar.gz#/%{project}-%{shortname}-%{version}.tar.gz
Source1:        %{longname}.conf
Requires:       %{project}-server
Requires:       python3-ipalib
Requires:       python3-ipaserver
# cronie-anacron provides anacron
Requires:       anacron
Requires:       logrotate
Requires(post): systemd-units
Requires:       %{name}-core = %{version}-%{release}
BuildRequires:  python3-devel
BuildRequires:  systemd-devel
%{?systemd_requires}
# packages for make check
BuildRequires:  python3-pytest-runner
BuildRequires:  python3-ipalib
BuildRequires:  python3-ipaserver
BuildRequires:  python3-lib389
BuildRequires:  python3-libsss_nss_idmap


%description
The FreeIPA health check tool provides a set of checks to
proactively detect defects in a FreeIPA cluster.


%package -n %{name}-core
Summary: Core plugin system for healthcheck


%description -n %{name}-core
Core files


%prep
%autosetup -p1 -n %{project}-%{shortname}-%{version}


%build
%py3_build


%install
%py3_install

mkdir -p %{buildroot}%{_sysconfdir}/%{longname}
install -m644 %{SOURCE1} %{buildroot}%{_sysconfdir}/%{longname}

mkdir -p %{buildroot}/%{_unitdir}
install -p -m644 %{_builddir}/%{project}-%{shortname}-%{version}/systemd/ipa-%{shortname}.service %{buildroot}%{_unitdir}
install -p -m644 %{_builddir}/%{project}-%{shortname}-%{version}/systemd/ipa-%{shortname}.timer %{buildroot}%{_unitdir}

mkdir -p %{buildroot}/%{_libexecdir}/ipa
install -p -m755 %{_builddir}/%{project}-%{shortname}-%{version}/systemd/ipa-%{shortname}.sh %{buildroot}%{_libexecdir}/ipa/

mkdir -p %{buildroot}%{_sysconfdir}/logrotate.d
install -p -m644 %{_builddir}/%{project}-%{shortname}-%{version}/logrotate/%{longname} %{buildroot}%{_sysconfdir}/logrotate.d

mkdir -p %{buildroot}/%{_localstatedir}/log/ipa/%{shortname}

mkdir -p %{buildroot}/%{_mandir}/man5
mkdir -p %{buildroot}/%{_mandir}/man8

install -p -m644 %{_builddir}/%{project}-%{shortname}-%{version}/man/man5/%{longname}.conf.5  %{buildroot}%{_mandir}/man5/
install -p -m644 %{_builddir}/%{project}-%{shortname}-%{version}/man/man8/ipa-%{shortname}.8  %{buildroot}%{_mandir}/man8/

(cd %{buildroot}/%{python3_sitelib}/ipahealthcheck && find . -type f  | \
    grep -v '^./core' | \
    grep -v 'opt-1' | \
    sed -e 's,\.py.*$,.*,g' | sort -u | \
    sed -e 's,\./,%%{python3_sitelib}/ipahealthcheck/,g' ) >healthcheck.list


%check
%{__python3} setup.py test


%post
%systemd_post ipa-%{shortname}.service


%preun
%systemd_preun ipa-%{shortname}.service


%postun
%systemd_postun_with_restart ipa-%{shortname}.service


%files -f healthcheck.list
%{!?_licensedir:%global license %%doc}
%license COPYING
%doc README.md
%{_bindir}/ipa-%{shortname}
%dir %{_sysconfdir}/%{longname}
%dir %{_localstatedir}/log/ipa/%{shortname}
%config(noreplace) %{_sysconfdir}/%{longname}/%{longname}.conf
%config(noreplace) %{_sysconfdir}/logrotate.d/%{longname}
%{python3_sitelib}/%{longname}-%{version}-*.egg-info/
%{python3_sitelib}/%{longname}-%{version}-*-nspkg.pth
%{_unitdir}/*
%{_libexecdir}/*
%{_mandir}/man5/*
%{_mandir}/man8/*


%files -n %{name}-core
%{!?_licensedir:%global license %%doc}
%license COPYING
%doc README.md
%{python3_sitelib}/%{longname}/core/


%changelog
* Thu Jan  2 2020 Rob Crittenden <rcritten@redhat.com> - 0.5-1
- Update to upstream 0.5

* Mon Dec 2 2019 François Cami <fcami@redhat.com> - 0.4-2
- Create subpackage to split out core processing (#1771710)

* Mon Dec 2 2019 François Cami <fcami@redhat.com> - 0.4-1
- Update to upstream 0.4
- Change Source0 to something "spectool -g" can use. 
- Correct URL (#1773512)
- Errors not translated to strings (#1752849)
- JSON output not indented by default (#1729043)
- Add dependencies to checks to avoid false-positives (#1727900)
- Verify expected DNS records (#1695125

* Thu Oct 03 2019 Miro Hrončok <mhroncok@redhat.com> - 0.3-3
- Rebuilt for Python 3.8.0rc1 (#1748018)

* Mon Aug 19 2019 Miro Hrončok <mhroncok@redhat.com> - 0.3-2
- Rebuilt for Python 3.8

* Thu Jul 25 2019 François Cami <fcami@redhat.com> - 0.3-1
- Update to upstream 0.3
- Add logrotate configs + depend on anacron and logrotate

* Thu Jul 25 2019 François Cami <fcami@redhat.com> - 0.2-6
- Fix permissions

* Thu Jul 25 2019 Fedora Release Engineering <releng@fedoraproject.org> - 0.2-5
- Rebuilt for https://fedoraproject.org/wiki/Fedora_31_Mass_Rebuild

* Thu Jul 11 2019 François Cami <fcami@redhat.com> - 0.2-4
- Fix ipa-healthcheck.sh installation path (rhbz#1729188)
- Create and own log directory (rhbz#1729188)

* Tue Apr 30 2019 François Cami <fcami@redhat.com> - 0.2-3
- Add python3-lib389 to BRs

* Tue Apr 30 2019 François Cami <fcami@redhat.com> - 0.2-2
- Fix changelog

* Thu Apr 25 2019 Rob Crittenden <rcritten@redhat.com> - 0.2-1
- Update to upstream 0.2

* Thu Apr 4 2019 François Cami <fcami@redhat.com> - 0.1-2
- Explicitly list dependencies

* Tue Apr 2 2019 François Cami <fcami@redhat.com> - 0.1-1
- Initial package import
