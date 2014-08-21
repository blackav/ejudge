Name: ejudge
Version: 3.0
Release: 1%{?dist}
Summary: A programming contest management system
Source: %{name}-%{version}.tgz
License: GPL
URL: http://ejudge.ru
ExcludeArch: x86_64
#BuildArch: i386
#BuildArch: x86_64
#BuildRequires:
#Requires:

%description
A programming contest management system. http://ejudge.ru

%prep
%autosetup -n %{name}

%build
%configure
make %{?_smp_mflags}

%install
%make_install
