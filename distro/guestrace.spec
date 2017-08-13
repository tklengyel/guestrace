Name:           guestrace
Version:        0.0.9
Release:        1%{?dist}
Summary:        A whole-system system-call tracer for VM guests

License:        LGPLv2.1
URL:            https://www.flyn.org/projects/%name/
Source0:        https://www.flyn.org/projects/%name/%{name}-%{version}.tar.gz

BuildRequires:  libvmi-devel, xen-devel, json-c-devel, glib2-devel

%description
A properly-configured guestrace will print as they occur the system
calls which processes invoke within a Xen domain. This resembles strace,
but provides the activity of every running process. The guestrace utility
relies on libvmi to perform virtual-machine introspection. Guestrace can
trace both Linux and Windows, and it requires no modifications to the
target aside from running the target on Xen.

%package        devel
Summary:        Development files for %{name}
Requires:       %{name}%{?_isa} = %{version}-%{release}

%description    devel
The %{name}-devel package contains libraries and header files for
developing applications that use %{name}.

%prep
%autosetup

%build
%configure --disable-static
%make_build

%install
rm -rf $RPM_BUILD_ROOT
%make_install
find $RPM_BUILD_ROOT -name '*.la' -exec rm -f {} ';'
rm -f $RPM_BUILD_ROOT/usr/bin/test-*

%post -p /sbin/ldconfig

%postun -p /sbin/ldconfig

%files
%license COPYING
%doc README
%{_libdir}/*.so.*
%{_bindir}/guestrace

%files devel
%{_includedir}/*
%{_libdir}/*.so
%{_libdir}/pkgconfig/libguestrace-0.0.pc
%{_datadir}/gtk-doc/html/libguestrace-0.0/

%changelog
* Sun Aug 13 2017 W. Michael Petullo <mike@flyn.org> - 0.0.9-1
- Initial package for Fedora
