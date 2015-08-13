%{!?__python2: %global __python2 /usr/bin/python2}
%{!?python2_sitelib: %global python2_sitelib %(%{__python2} -c "from distutils.sysconfig import get_python_lib; print(get_python_lib())")}
%{!?python2_sitearch: %global python2_sitearch %(%{__python2} -c "from distutils.sysconfig import get_python_lib; print(get_python_lib(1))")}

%define name elkproxy
%define summary a transparent proxy for securing Elasticsearch
%define version 0.0
%define release 1%{?dist}

Name: %{name}
Summary: %{summary}
Version: %{version}
Release: %{release}
Source0: %{name}-%{version}.tar.gz
License: GPLv2+
Group: System Environment/Daemons
BuildRequires: python-setuptools
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-buildroot
Requires: python-netifaces
BuildArch: noarch
Vendor: NETWAYS GmbH <info@netways.de>
Url: https://project.netways.de/projects/elk-proxy

%description
The ELK Proxy is a transparent HTTP proxy for securing
Elasticsearch by permitting specific users to access only
specific data.

%prep
%setup -q

%build
%{__python2} setup.py build

%install
%{__python2} setup.py install -O1 --skip-build --root $RPM_BUILD_ROOT --prefix=%{_prefix}
install -d -m 0700 ${RPM_BUILD_ROOT}/etc/elkproxyd
install -m 0600 .puppet/files/elkproxyd.ini ${RPM_BUILD_ROOT}/etc/elkproxyd/config.ini
install -d ${RPM_BUILD_ROOT}/etc/rc.d/init.d
install -m 0744 .puppet/files/init.d-elkproxy ${RPM_BUILD_ROOT}/etc/rc.d/init.d/elkproxy

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root)
%doc AUTHORS COPYING
%{python2_sitelib}
%dir /etc/elkproxyd
%config(noreplace) /etc/elkproxyd/config.ini
/etc/rc.d/init.d/elkproxy
