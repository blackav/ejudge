Name: ejudge
Version: 3.0.2
Release: 1%{?dist}
Summary: A programming contest management system
Source: %{name}-%{version}.tgz
License: GPL
URL: http://ejudge.ru
BuildRequires: make gcc glibc-devel glibc-static bison flex gawk sed zlib zlib-devel ncurses ncurses-devel expat expat-devel libzip libzip-devel gettext gettext-devel mysql-libs mysql mysql-devel libcurl libcurl-devel libuuid libuuid-devel elfutils-libelf-devel elfutils-libelf-devel-static elfutils-libelf libdwarf-devel libdwarf-static libdwarf libdwarf-tools
Requires: make gcc glibc-devel glibc-static bison flex gawk sed zlib zlib-devel ncurses ncurses-devel expat expat-devel libzip libzip-devel gettext gettext-devel mysql-libs mysql mysql-devel libcurl libcurl-devel libuuid libuuid-devel elfutils-libelf-devel elfutils-libelf-devel-static elfutils-libelf libdwarf-devel libdwarf-static libdwarf libdwarf-tools gcc-c++ libstdc++-static fpc ruby python python3 php php-common php-cli perl gprolog ghc mono-core mono-basic gcc-gfortran libgfortran-static gcc-go libgo-static mono-extras mono-locale-extras valgrind nasm vim screen wget ncftp mc fuse-sshfs patch kernel-tools kernel-devel gcc strace subversion gdb openssl openssl-devel java-1.8.0-openjdk java-1.8.0-openjdk-headless java-1.8.0-openjdk-devel
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
%{buildroot}%{_bindir}/ejudge-upgrade-web --copy --sandbox --destdir %{buildroot}/
mkdir -p %{buildroot}%{_sysconfdir}/init.d
cp -p %{_builddir}/%{name}/init.d/ejudge %{buildroot}%{_sysconfdir}/init.d/ejudge
if [ -f %{_builddir}/%{name}/build/fedora/%{_arch}/ejudge-install.sh ]
then
  cp -p %{_builddir}/%{name}/build/fedora/%{_arch}/ejudge-install.sh %{buildroot}%{_bindir}
fi
export DONT_STRIP=1

%files
%{_bindir}/*
%{_libdir}/*
%{_prefix}/lib/*
%{_datadir}/%{name}/
%{_libexecdir}/%{name}/
%{_includedir}/%{name}/
%{_datadir}/locale/
/var/www/html/ejudge/
/var/www/cgi-bin/*
%{_sysconfdir}/init.d/ejudge

%pre
getent group ejudge >/dev/null || groupadd ejudge
getent passwd ejudge >/dev/null || useradd -g ejudge -d /home/ejudge -s /bin/bash -c "Ejudge programming contest management system" ejudge
exit 0

%post
/sbin/ldconfig

%postun
/sbin/ldconfig
