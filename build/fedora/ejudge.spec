Name: ejudge
Version: 3.0
Release: 1%{?dist}
Summary: A programming contest management system
Source: %{name}-%{version}.tgz
License: GPL
URL: http://ejudge.ru
BuildArch: i386
BuildArch: x86_64
BuildRequires: make gcc glibc-devel glibc-static bison flex gawk sed zlib zlib-devel ncurses ncurses-devel expat expat-devel libzip libzip-devel gettext gettext-devel mysql-libs mysql mysql-devel libcurl libcurl-devel libuuid libuuid-devel elfutils-libelf-devel elfutils-libelf-devel-static elfutils-libelf libdwarf-devel libdwarf-static libdwarf libdwarf-tools
Requires: make gcc glibc-devel glibc-static bison flex gawk sed zlib zlib-devel ncurses ncurses-devel expat expat-devel libzip libzip-devel gettext gettext-devel mysql-libs mysql mysql-devel libcurl libcurl-devel libuuid libuuid-devel elfutils-libelf-devel elfutils-libelf-devel-static elfutils-libelf libdwarf-devel libdwarf-static libdwarf libdwarf-tools
Requires(pre): shadow-utils

%global _enable_debug_package 0
%global debug_package %{nil}
%global __os_install_post /usr/lib/rpm/brp-compress %{nil}

%description
A programming contest management system. http://ejudge.ru

%prep
%autosetup -n %{name}

%build
%configure --enable-charset=utf-8 --with-httpd-cgi-bin-dir=/var/www/cgi-bin --with-httpd-htdocs-dir=/var/www/html --enable-ajax --enable-local-dir=/var/lib/ejudge --enable-hidden-server-bins --disable-rpath
export EJUDGE_NO_CHECK_PATH=1
make %{?_smp_mflags}

%install
%make_install
%{buildroot}/%{_bindir}/ejudge-upgrade-web --copy --sandbox --destdir %{buildroot}/
cp -p %{buildsubdir}/init.d/ejudge %{buildroot}/%{_sysconfdir}/init.d/ejudge
export DONT_STRIP=1

%files
%{_bindir}/*
%{_libdir}/*
%{_datadir}/%{name}/
%{_libexecdir}/%{name}/
%{_includedir}/%{name}/
%{_datadir}/locale/ru_RU.UTF-8/LC_MESSAGES/ejudgecheckers.mo
%{_datadir}/locale/ru_RU.UTF-8/LC_MESSAGES/ejudge.mo
/var/www/html/ejudge/
/var/www/cgi-bin/*
%{_sysconfdir}/init.d/ejudge

%pre
getent group ejudge >/dev/null || groupadd -r ejudge
getent passwd ejudge >/dev/null || useradd -r -g ejudge -d ejudge -s /bin/bash -c "Ejudge programming contest management system" ejudge
exit 0

%post
/sbin/ldconfig

%postun
/sbin/ldconfig
