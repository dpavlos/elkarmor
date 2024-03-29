%{!?__python2: %global __python2 /usr/bin/python2}
%{!?python2_sitelib: %global python2_sitelib %(%{__python2} -c "from distutils.sysconfig import get_python_lib; print(get_python_lib())")}

%define revision 1

Name:       elkarmor
Version:    1.0
Release:    %{revision}%{?dist}
Summary:    Transparent proxy for securing Elasticsearch
Group:      System Environment/Daemons
License:    GPLv2+
URL:        https://www.netways.org/projects/elkarmor
Source0:    %{name}-%{version}.tar.gz
Vendor:     NETWAYS GmbH <info@netways.de>
Packager:   NETWAYS GmbH <info@netways.de>

BuildArch:      noarch
BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}
BuildRequires:  python-setuptools

Requires(post):     /sbin/chkconfig
Requires(preun):    /sbin/chkconfig
Requires(postun):   /sbin/service
Requires(preun):    /sbin/service
Requires:           python-ldap
Requires:           python-netifaces

%define configdir %{_sysconfdir}/%{name}


%description
The ELK Armor is a transparent HTTP proxy for securing
Elasticsearch by permitting specific users to access only
specific data.

%prep
%setup -q

%build

%install
%{__python2} setup.py install --prefix=%{_prefix} --root=%{buildroot}
mkdir -p %{buildroot}%{_initddir}
mkdir -p %{buildroot}%{configdir}
cp elkarmor.init %{buildroot}%{_initddir}/%{name}
cp etc/elkarmor.ini %{buildroot}%{configdir}/config.ini
cp etc/restrictions.ini %{buildroot}%{configdir}/restrictions.ini

%post
/sbin/chkconfig --add %{name}

%preun
if [ $1 -eq 0 ] ; then
    /sbin/service %{name} stop >/dev/null 2>&1
    /sbin/chkconfig --del %{name}
fi

%postun
if [ "$1" -ge "1" ] ; then
    /sbin/service %{name} condrestart >/dev/null 2>&1 || :
fi

%clean
rm -rf %{buildroot}

%files
%defattr(-,root,root)
%doc AUTHORS COPYING
%{python2_sitelib}
%attr(0700,root,root) %config(noreplace) %dir %{configdir}
%attr(0600,root,root) %config(noreplace) %{configdir}/config.ini
%attr(0600,root,root) %config(noreplace) %{configdir}/restrictions.ini
%attr(0755,root,root) %{_initddir}/%name
