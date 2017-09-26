%define name pam_sqlite
%define version 0.4
%define release 3

Name: %{name}
Summary: PAM module using SQLite database
Version: %{version}
Release: %{release}
Source: %{name}-%{version}-%{release}.tar.gz
Group: System Environment/Base
Prereq: sqlite
URL: https://www.ledav.net/public/dev/sources/browser/c/pam_sqlite
License: GPL
Vendor: Edin Kadribasic
Packager: David De Grave <david@ledav.net>

BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root

%description
pam_sqlite allows developers to authenticate users against a table
in an SQLite database. It supports checking account information
(pam_acct_expired, new_authtok_reqd) and updating authentication tokens.
It now also support pam sessions...

%prep
%setup -q -n %{name}-%{version}-%{release}

%build
./configure
make

%install
install -d $RPM_BUILD_ROOT/etc
install -d $RPM_BUILD_ROOT/lib/security
install -d $RPM_BUILD_ROOT/var/lib/pam_sqlite
install -d $RPM_BUILD_ROOT/usr/share/doc/%{name}-%{version}-%{release}

install -m 0644    $RPM_BUILD_DIR/%{name}-%{version}-%{release}/README          $RPM_BUILD_ROOT/usr/share/doc/%{name}-%{version}-%{release}
install -m 0644    $RPM_BUILD_DIR/%{name}-%{version}-%{release}/NEWS            $RPM_BUILD_ROOT/usr/share/doc/%{name}-%{version}-%{release}
install -m 0644    $RPM_BUILD_DIR/%{name}-%{version}-%{release}/pam_sqlite.sql  $RPM_BUILD_ROOT/usr/share/doc/%{name}-%{version}-%{release}
install -m 0644    $RPM_BUILD_DIR/%{name}-%{version}-%{release}/pam_sqlite.pam  $RPM_BUILD_ROOT/usr/share/doc/%{name}-%{version}-%{release}
install -m 0644    $RPM_BUILD_DIR/%{name}-%{version}-%{release}/pam_sqlite.conf $RPM_BUILD_ROOT/usr/share/doc/%{name}-%{version}-%{release}
install -m 0755 -s $RPM_BUILD_DIR/%{name}-%{version}-%{release}/pam_sqlite.so   $RPM_BUILD_ROOT/lib/security
install -m 0644    $RPM_BUILD_DIR/%{name}-%{version}-%{release}/pam_sqlite.conf $RPM_BUILD_ROOT/etc

%clean
rm -fr $RPM_BUILD_ROOT

%files
%defattr(-, root, root)
%dir /var/lib/pam_sqlite
/lib/security/pam_sqlite.so
%docdir /usr/share/doc/%{name}-%{version}-%{release}
/usr/share/doc/%{name}-%{version}-%{release}
%config /etc/pam_sqlite.conf
