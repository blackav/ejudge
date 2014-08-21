Name: ejudge
Version: 3
Release: 1
Summary: A programming contest management system
Source0: ejudge.tgz
License: GPL
Group: ejudge
BuildArch: i386
BuildArch: x86_64
BuildRoot: %{_tmppath}/%{name}-buildroot
BuildRequires:
Requires:

%description
A programming contest management system. http://ejudge.ru

%prep
%setup -q

%build

%install
