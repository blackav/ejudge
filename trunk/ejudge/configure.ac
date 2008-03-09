dnl $Id$
dnl Copyright (C) 2004-2008 Alexander Chernov <cher@ejudge.ru>

AC_INIT(ejudge,2.2)
AC_PREREQ(2.59)
AC_REVISION($Revision$)

AC_PREFIX_DEFAULT([$HOME/inst-ejudge])
AC_PROG_INSTALL

AC_GNU_SOURCE
AC_PROG_CC
AC_PROG_CC_C_O
AC_PROG_CPP

AC_C_BACKSLASH_A
AC_C_BIGENDIAN
AC_C_CONST
AC_C_RESTRICT
AC_C_VOLATILE
AC_C_INLINE
AC_C_CHAR_UNSIGNED
AC_C_LONG_DOUBLE
AC_C_STRINGIZE
AC_C_PROTOTYPES

AC_ARG_WITH([libcap], AC_HELP_STRING([--with-libcap=LIBCAP-DIR],[use the linux capability library]),[ac_cv_libcap_root=$withval])
AC_ARG_WITH([libcap-include-dir], AC_HELP_STRING([--with-libcap-include-dir],[specify non-standard location of <sys/capability.h> [[LIBCAP-DIR/include]]]),[ac_cv_libcap_include_dir=$withval])
AC_ARG_WITH([libcap-lib-dir], AC_HELP_STRING([--with-libcap-lib-dir],[specify non-standard location for -lcap [[LIBCAP-DIR/lib]]]), [ac_cv_libcap_lib_dir=$withval])

AC_ARG_WITH([expat], AC_HELP_STRING([--with-expat=EXPAT-DIR],[specify non-standard path to expat library]),[ac_cv_expat_root=$withval])
AC_ARG_WITH([expat-include-dir],AC_HELP_STRING([--with-expat-include-dir],[specify non-standard location of <expat.h> [[EXPAT-DIR/include]]]),[ac_cv_expat_include_dir=$withval])
AC_ARG_WITH([expat-lib-dir],AC_HELP_STRING([--with-expat-lib-dir],[specify non-standard location of -lexpat [[EXPAT-DIR/lib]]]),[ac_cv_expat_lib_dir=$withval])

AC_ARG_WITH([mysql], AC_HELP_STRING([--with-mysql=MYSQL-DIR],[specify the path to the mysql installation directory]),[ac_cv_mysql_root="$withval"])

AC_ARG_WITH([reuse], AC_HELP_STRING([--with-reuse=REUSE-DIR],[specify the path to reuse library]),[ac_cv_reuse_root=$withval])
AC_ARG_WITH([reuse-include-dir],AC_HELP_STRING([--with-reuse-include-dir],[specify the location of reuse include directories [[REUSE-DIR/include]]]),[ac_cv_reuse_include_dir=$withval])
AC_ARG_WITH([reuse-lib-dir],AC_HELP_STRING([--with-reuse-lib-dir],[specify the location of reuse library directories [[REUSE-DIR/lib]]]),[ac_cv_reuse_lib_dir=$withval])
AC_ARG_WITH([reuse-conf-dir],AC_HELP_STRING([--with-reuse-conf-dir],[specify the location of reuse configuration directories [[REUSE-DIR/etc]]]),[ac_cv_reuse_conf_dir=$withval])
AC_ARG_WITH([reuse-config],AC_HELP_STRING([--with-reuse-config],[specify the configuration name]),[ac_cv_reuse_config=$withval])

AC_ARG_ENABLE([cgi-suffix], AC_HELP_STRING([--enable-cgi-suffix],[append the given suffix to the CGI programs]),[ac_cv_cgi_suffix=$enableval],[ac_cv_cgi_suffix=""])
AC_ARG_ENABLE([cgi-bin-dir], AC_HELP_STRING([--enable-cgi-bin-dir],[specify the destination CGI script directory [[\${prefix}/libexec/ejudge/cgi-bin]]]),[cgibindir=$enableval], [cgibindir='${libexecdir}/ejudge/cgi-bin'])
AC_ARG_ENABLE([static], AC_HELP_STRING([--enable-static],[link programs statically]),[ac_cv_static=1],[ac_cv_static=""])
AC_ARG_ENABLE([rpath], AC_HELP_STRING([--disable-rpath],[do not use -rpath feature]),[ac_cv_rpath="$enableval"])
AC_ARG_ENABLE([nls], AC_HELP_STRING([--disable-nls],[disable localization]),[ac_cv_nls=$enableval],[ac_cv_nls=""])
AC_ARG_ENABLE([charset],AC_HELP_STRING([--enable-charset],[specify the default charset]),[ac_cv_charset="$enableval"],[ac_cv_charset=""])
AC_ARG_ENABLE([socket-path],AC_HELP_STRING([--enable-socket-path],[specify the default userlist-server socket path]),[ac_cv_socket_path="$enableval"],[ac_cv_socket_path=""])
AC_ARG_ENABLE([super-serve-socket],AC_HELP_STRING([--enable-super-serve-socket],[specify the default super-serve socket path]),[ac_cv_super_serve_socket="$enableval"],[ac_cv_super_serve_socket=""])
AC_ARG_ENABLE([new-server-socket],AC_HELP_STRING([--enable-new-server-socket],[specify the default new-server socket path]),[ac_cv_new_server_socket="$enableval"],[ac_cv_new_server_socket=""])
AC_ARG_ENABLE([conf-dir], AC_HELP_STRING([--enable-conf-dir=CONF-DIR],[specify the ejudge configuration directory]),[ac_cv_conf_dir="$enableval"],[ac_cv_conf_dir=""])
AC_ARG_ENABLE([cgi-conf-dir], AC_HELP_STRING([--enable-cgi-conf-dir],[specify path to CGI configuration files]),[ac_cv_cgi_conf_dir="$enableval"],[ac_cv_cgi_conf_dir=""])
AC_ARG_ENABLE([ejudge-xml],AC_HELP_STRING([--enable-ejudge-xml],[specify the default location of ejudge.xml]),[ac_cv_ejudge_xml="$enableval"],[ac_cv_ejudge_xml=""])
AC_ARG_ENABLE([contests-dir],AC_HELP_STRING([--enable-contests-dir],[specify the default path to the contest configuration directory]),[ac_cv_contests_dir="$enableval"],[ac_cv_contests_dir=""])
AC_ARG_ENABLE([contests-home-dir],AC_HELP_STRING([--enable-contests-home-dir],[specify the default path to the contests home directory]),[ac_cv_contests_home_dir="$enableval"],[ac_cv_contests_home_dir=""])
AC_ARG_ENABLE([local-dir],AC_HELP_STRING([--enable-local-dir],[specify the default path to the local state directory]),[ac_cv_local_dir="$enableval"],[ac_cv_local_dir=""])
AC_ARG_ENABLE([ajax],AC_HELP_STRING([--enable-ajax],[enable use of the ajax technology for the client web interface]),[ac_cv_ajax="$enableval"],[ac_cv_ajax=""])
AC_ARG_ENABLE([style-prefix],AC_HELP_STRING([--enable-style-prefix],[specify the prefix for HTML style files]),[ac_cv_style_prefix="$enableval"],[ac_cv_style_prefix=""])
AC_ARG_ENABLE([hidden-server-bins],AC_HELP_STRING([--enable-hidden-server-bins],[do not install the server binaries into bin directory]),[ac_cv_hidden_bins=1],[ac_cv_hidden_bins=])
AC_ARG_ENABLE([werror],AC_HELP_STRING([--enable-werror],[enable -Werror compilation flag]),[ac_cv_werror_flag=-Werror],[ac_cv_werror_flag=])

AC_ARG_WITH([httpd-cgi-bin-dir],AC_HELP_STRING([--with-httpd-cgi-bin-dir],[specify the path to the web serve CGI directory]),[ac_cv_httpd_cgi_bin_dir="${withval}"])
AC_ARG_WITH([httpd-htdocs-dir],AC_HELP_STRING([--with-httpd-htdocs-dir],[specify the path to the web server HTML directory]),[ac_cv_httpd_htdocs_dir="${withval}"])

AC_ARG_WITH([gcc],AC_HELP_STRING([--with-gcc],[specify the GNU C compiler to use in contests]),[ac_cv_contest_gcc=$withval])
AC_ARG_WITH([gpp],AC_HELP_STRING([--with-gpp],[specify the GNU C++ compiler to use in contests]),[ac_cv_contest_gpp=$withval])
AC_ARG_WITH([fpc],AC_HELP_STRING([--with-fpc],[specify the Free Pascal compiler to use in contests]),[ac_cv_contest_fpc=$withval])
AC_ARG_WITH([gpc],AC_HELP_STRING([--with-gpc],[specify the GNU Pascal compiler to use in contests]),[ac_cv_contest_gpc=$withval])
AC_ARG_WITH([gcj],AC_HELP_STRING([--with-gcj],[specify the GNU Java (GCJ) compiler to use in contests]),[ac_cv_contest_gcj=$withval])
AC_ARG_WITH([g77],AC_HELP_STRING([--with-g77],[specify the GNU Fortran 77 compiler to use in contests]),[ac_cv_contest_g77=$withval])
AC_ARG_WITH([gfortran],AC_HELP_STRING([--with-gfortran],[specify the GNU Fortran 90 compiler to use in contests]),[ac_cv_contest_gfortran=$withval])
AC_ARG_WITH([dcc],AC_HELP_STRING([--with-dcc],[specify the Borland Delphi compiler to use in contests]),[ac_cv_contest_dcc=$withval])
AC_ARG_WITH([yabasic],AC_HELP_STRING([--with-yabasic],[specify the Yabasic interpreter to use in contests]),[ac_cv_contest_yabasic=$withval])
AC_ARG_WITH([scheme],AC_HELP_STRING([--with-scheme],[specify the MzScheme interpreter to use in contests]),[ac_cv_contest_mzscheme=$withval])
AC_ARG_WITH([python],AC_HELP_STRING([--with-python],[specify the Python interpreter to use in contests]),[ac_cv_contest_python=$withval])
AC_ARG_WITH([perl],AC_HELP_STRING([--with-perl],[specify the Perl interpreter to use in contests]),[ac_cv_contest_perl=$withval])
AC_ARG_WITH([prolog],AC_HELP_STRING([--with-prolog],[specify the GNU Prolog compiler to use in contests]),[ac_cv_contest_gprolog=$withval])
AC_ARG_WITH([festival],AC_HELP_STRING([--with-festival],[specify the home directory of the festival speech generator]),[ac_cv_festival_home="$withval"])
AC_ARG_WITH([javac],AC_HELP_STRING([--with-javac],[specify the Java2 SDK javac path to use in contests]),[ac_cv_contest_javac="$withval"])
AC_ARG_WITH([mcs],AC_HELP_STRING([--with-mcs],[specify the C-sharp Mono mcs path to use in contests]),[ac_cv_contest_mcs="$withval"])
AC_ARG_WITH([mbas],AC_HELP_STRING([--with-mbas],[specify the Visual Basic Mono mbas path to use in contests]),[ac_cv_contest_mbas="$withval"])

dnl setup default values
[[ x"${ac_cv_local_dir}" = xyes ]] && ac_cv_local_dir="/var/lib/ejudge"
if [[ x"${ac_cv_local_dir}" != x ]]
then
  [[ x"${ac_cv_socket_path}" = x -o x"${ac_cv_socket_path}" = xyes ]] && ac_cv_socket_path="${ac_cv_local_dir}/sockets/userlist"
  [[ x"${ac_cv_super_serve_socket}" = x -o x"${ac_cv_super_serve_socket}" = xyes ]] && ac_cv_super_serve_socket="${ac_cv_local_dir}/sockets/super-serve"
  [[ x"${ac_cv_new_server_socket}" = x -o x"${ac_cv_new_server_socket}" = xyes ]] && ac_cv_new_server_socket="${ac_cv_local_dir}/sockets/new-server"
else
  [[ x"${ac_cv_socket_path}" = x -o x"${ac_cv_socket_path}" = xyes ]] && ac_cv_socket_path="/tmp/userlist-socket"
  [[ x"${ac_cv_super_serve_socket}" = x -o x"${ac_cv_super_serve_socket}" = xyes ]] && ac_cv_super_serve_socket="/tmp/super-serve-socket"
  [[ x"${ac_cv_new_server_socket}" = x -o x"${ac_cv_new_server_socket}" = xyes ]] && ac_cv_new_server_socket="/tmp/new-server-socket"
fi

[[ x"${ac_cv_contests_home_dir}" = x -o x"${ac_cv_contests_home_dir}" = xyes ]] && ac_cv_contests_home_dir="/home/judges"
[[ x"${ac_cv_conf_dir}" = x -o x"${ac_cv_conf_dir}" = xyes ]] && ac_cv_conf_dir="/home/judges/data"
[[ x"${ac_cv_cgi_conf_dir}" = x -o x"${ac_cv_cgi_conf_dir}" = xyes ]] && ac_cv_cgi_conf_dir="../cgi-data"
[[ x"${ac_cv_style_prefix}" = x -o x"${ac_cv_style_prefix}" = xyes ]] && ac_cv_style_prefix="/ejudge/"

case "${host}" in
  x86_64-*linux*)
    libdir='${exec_prefix}/lib64'
    ;;
esac

dnl choose an arch type
AC_MSG_CHECKING([for arch type])
case "${target}" in
  *-*-mingw*)
    ac_cv_ejudge_arch=win32
    ac_cv_exe_suffix=.exe
    CFLAGS="${CFLAGS} -mno-cygwin"
    LDFLAGS="${LDFLAGS} -mno-cygwin"
    AC_MSG_RESULT([win32])
    ;;
  *)
    ac_cv_ejudge_arch=unix
    ac_cv_exe_suffix=
    AC_MSG_RESULT([unix])
    ;;
esac

if [[ x"${ac_cv_ejudge_arch}" != xwin32 ]]
then
AC_CHECK_HEADERS([termios.h])
fi

dnl Expat checking stuff
ac_cv_has_expat=1
[[ x"${ac_cv_expat_root}" = xno ]] && ac_cv_has_expat=""

if [[ x"${ac_cv_expat_root}" = x -o x"${ac_cv_expat_root}" = xyes ]]
then
  [[ x"${ac_cv_expat_include_dir}" = x -o x"${ac_cv_expat_include_dir}" = xyes -o x"${ac_cv_expat_include_dir}" = xno ]] && ac_cv_expat_include_dir=""
  [[ x"${ac_cv_expat_lib_dir}" = x -o x"${ac_cv_expat_lib_dir}" = xyes -o x"${ac_cv_expat_lib_dir}" = xno ]] && ac_cv_expat_lib_dir=""
else
  [[ x"${ac_cv_expat_include_dir}" = x -o x"${ac_cv_expat_include_dir}" = xyes -o x"${ac_cv_expat_include_dir}" = xno ]] && ac_cv_expat_include_dir="${ac_cv_expat_root}/include"
  [[ x"${ac_cv_expat_lib_dir}" = x -o x"${ac_cv_expat_lib_dir}" = xyes -o x"${ac_cv_expat_lib_dir}" = xno ]] && ac_cv_expat_lib_dir="${ac_cv_expat_root}/lib"
fi

ac_cv_expat_include_opt=
[[ x"${ac_cv_expat_include_dir}" != x ]] && ac_cv_expat_include_opt="-I${ac_cv_expat_include_dir}"
ac_cv_expat_lib_opt=
[[ x"${ac_cv_expat_lib_dir}" != x ]] && ac_cv_expat_lib_opt="-L${ac_cv_expat_lib_dir}"

saved_CFLAGS="${CFLAGS}"
saved_CPPFLAGS="${CPPFLAGS}"
saved_LDFLAGS="${LDFLAGS}"
saved_LIBS="${LIBS}"
CFLAGS="${CFLAGS} ${ac_cv_expat_include_opt}"
CPPFLAGS="${CPPFLAGS} ${ac_cv_expat_include_opt}"
LDFLAGS="${LDFLAGS} ${ac_cv_expat_lib_opt}"
LIBS="-lexpat ${LIBS}"

if [[ x"${ac_cv_has_expat}" = x1 ]]
then
  AC_CHECK_HEADER([expat.h],[ac_cv_has_expat=1],[ac_cv_has_expat=""])
fi

if [[ x"${ac_cv_has_expat}" = x1 ]]
then
  AC_CHECK_LIB([expat],[XML_ExpatVersionInfo],[ac_cv_has_expat=1],[ac_cv_has_expat=""])
fi

if [[ x"${ac_cv_has_expat}" = x1 ]]
then
  AC_MSG_CHECKING([that version of the expat library >= 1.95])
  AC_RUN_IFELSE(
[[
#include <expat.h>
#include <stdio.h>
int main(void)
{
  XML_Expat_Version v;
  v = XML_ExpatVersionInfo();
  if (v.major > 1) return 0;
  if (v.minor >= 95) return 0;
  return 1;
}
]],[
AC_MSG_RESULT([yes])
ac_cv_has_expat=1
],[
AC_MSG_RESULT([no])
ac_cv_has_expat=""
])
fi

CFLAGS="${saved_CFLAGS}"
CPPFLAGS="${saved_CPPFLAGS}"
LDFLAGS="${saved_LDFLAGS}"
LIBS="${saved_LIBS}"

if [[ x"${ac_cv_has_expat}" = x -a x"${ac_cv_ejudge_arch}" != xwin32 ]]
then
AC_MSG_FAILURE([expat XML parsing library missing])
fi

dnl check zlib library
AC_CHECK_HEADER([zlib.h],[ac_cv_has_zlib=1],[ac_cv_has_zlib=0])
if [[ x"${ac_cv_has_zlib}" != x1 ]]
then
  AC_MSG_FAILURE([zlib.h is missing, please install zlib development package])
fi

AC_CHECK_LIB([z],[compressBound],[ac_cv_has_zlib=1],[ac_cv_has_zlib=0])
if [[ x"${ac_cv_has_zlib}" != x1 ]]
then
  AC_MSG_FAILURE([zlib is too old or unusable, please update zlib])
fi

AC_MSG_CHECKING([that version of zlib >= 1.2])
AC_RUN_IFELSE(
[[
#include <zlib.h>
#include <stdio.h>
int main(void)
{
  if (ZLIB_VERNUM >= 0x1200) return 0;
  return 1;
}
]],[
AC_MSG_RESULT([yes])
ac_cv_has_zlib=1
],[
AC_MSG_RESULT([no])
ac_cv_has_zlib=0
])
if [[ x"${ac_cv_has_zlib}" != x1 ]]
then
  AC_MSG_FAILURE([zlib is too old or unusable, please update zlib])
fi

dnl check ncurses library
AC_CHECK_HEADER([ncurses.h],[ac_cv_has_ncurses=1],[ac_cv_has_ncurses=0])
if [[ x"${ac_cv_has_ncurses}" != x1 ]]
then
  AC_MSG_FAILURE([ncurses.h is missing, please install ncurses development package])
fi

dnl Libcap checking stuff

ac_cv_has_libcap=1
if [[ x"${ac_cv_libcap_root}" = xno ]]
then
ac_cv_has_libcap=
fi

if [[ x"${ac_cv_libcap_root}" = x -o x"${ac_cv_libcap_root}" = xyes ]]
then
  [[ x"${ac_cv_libcap_include_dir}" = x -o x"${ac_cv_libcap_include_dir}" = xyes -o x"${ac_cv_libcap_include_dir}" = xno ]] && ac_cv_libcap_include_dir=""
  [[ x"${ac_cv_libcap_lib_dir}" = x -o x"${ac_cv_libcap_lib_dir}" = xyes -o x"${ac_cv_libcap_lib_dir}" = xno ]] && ac_cv_libcap_lib_dir=""
else
  [[ x"${ac_cv_libcap_include_dir}" = x -o x"${ac_cv_libcap_include_dir}" = xyes -o x"${ac_cv_libcap_include_dir}" = xno ]] && ac_cv_libcap_include_dir="${ac_cv_libcap_root}/include"
  [[ x"${ac_cv_libcap_lib_dir}" = x -o x"${ac_cv_libcap_lib_dir}" = xyes -o x"${ac_cv_libcap_lib_dir}" = xno ]] && ac_cv_libcap_lib_dir="${ac_cv_expat_root}/lib"
fi

ac_cv_libcap_include_opt=
[[ x"${ac_cv_libcap_include_dir}" != x ]] && ac_cv_libcap_include_opt="-I${ac_cv_libcap_include_dir}"
ac_cv_libcap_lib_opt=
[[ x"${ac_cv_libcap_lib_dir}" != x ]] && ac_cv_libcap_lib_opt="-L${ac_cv_libcap_lib_dir}"

saved_CFLAGS="${CFLAGS}"
saved_CPPFLAGS="${CPPFLAGS}"
saved_LDFLAGS="${LDFLAGS}"
saved_LIBS="${LIBS}"
CFLAGS="${CFLAGS} ${ac_cv_libcap_include_opt}"
CPPFLAGS="${CPPFLAGS} ${ac_cv_libcap_include_opt}"
LDFLAGS="${LDFLAGS} ${ac_cv_libcap_lib_opt}"
LIBS="-lcap ${LIBS}"

if [[ x"${ac_cv_has_libcap}" = x1 ]]
then
  AC_CHECK_HEADER([sys/capability.h],
                [ac_cv_has_libcap=1],
                [ac_cv_has_libcap=""],
[
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
])
fi

if [[ x"${ac_cv_has_libcap}" = x1 ]]
then
  AC_CHECK_LIB([cap], [cap_get_proc],
               [ac_cv_has_libcap=1],
               [ac_cv_has_libcap=""])
fi

if [[ x"${ac_cv_has_libcap}" = x1 ]]
then
  AC_MSG_CHECKING([for CAP_SYS_OPERATIONS bit])
  AC_LINK_IFELSE(
[[
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <sys/capability.h>
int main(void)
{
  cap_t old_caps, new_caps;
  int   setcaps[] = { CAP_SYS_OPERATIONS };
  
  old_caps = cap_get_proc();
  new_caps = cap_dup(old_caps);
  cap_set_flag(new_caps, CAP_EFFECTIVE, 1, setcaps, CAP_CLEAR);
  cap_set_flag(new_caps, CAP_PERMITTED, 1, setcaps, CAP_CLEAR);
  cap_set_flag(new_caps, CAP_INHERITABLE, 1, setcaps, CAP_CLEAR);
  cap_set_proc(new_caps);
  return 0;
}
]],
[
AC_MSG_RESULT([supported])
ac_cv_has_libcap=1
],
[
AC_MSG_RESULT([missing])
ac_cv_has_libcap=""
])
fi

if [[ x"${ac_cv_has_libcap}" = x1 ]]
then
  AC_MSG_CHECKING([for support of CAP_SYS_OPERATIONS bit in the running kernel])
  AC_RUN_IFELSE(
[[
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <sys/capability.h>
int main(void)
{
  cap_t old_caps, new_caps;
  int   setcaps[] = { CAP_SYS_OPERATIONS };
  int   p;
  
  old_caps = cap_get_proc();
  new_caps = cap_dup(old_caps);
  cap_set_flag(new_caps, CAP_EFFECTIVE, 1, setcaps, CAP_CLEAR);
  cap_set_flag(new_caps, CAP_PERMITTED, 1, setcaps, CAP_CLEAR);
  cap_set_flag(new_caps, CAP_INHERITABLE, 1, setcaps, CAP_CLEAR);
  if (cap_set_proc(new_caps) < 0) return 1;
  if ((p = fork()) < 0 && errno == EPERM) return 0;
  if (p < 0) return 1;
  if (!p) _exit(1);
  return 1;
}
]],
[
AC_MSG_RESULT([supported])
ac_cv_has_runtime_libcap=1
],
[
AC_MSG_RESULT([not supported])
ac_cv_has_runtime_libcap=""
])
fi

CFLAGS="${saved_CFLAGS}"
CPPFLAGS="${saved_CPPFLAGS}"
LDFLAGS="${saved_LDFLAGS}"
LIBS="${saved_LIBS}"

AC_MSG_CHECKING([for new secure execution interface in the running kernel])
  AC_RUN_IFELSE(
[[
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <sys/ptrace.h>
int main(void)
{
  int p;
  
  if (ptrace(0x4281, 0, 0, 0) < 0) _exit(1);
  if ((p = fork()) < 0 && errno == EPERM) return 0;
  if (p < 0) return 1;
  if (!p) _exit(1);
  return 1;
}
]],
[
AC_MSG_RESULT([supported])
ac_cv_has_new_secure_exec=1
],
[
AC_MSG_RESULT([not supported])
ac_cv_has_new_secure_exec=""
])

#if [[ x"${ac_cv_has_libcap}" = x -a x"${ac_cv_has_new_secure_exec}" = x ]]
#then
#ac_cv_no_kernel=1
#else
#ac_cv_no_kernel=
#fi

dnl MySQL checking stuff

ac_cv_has_mysql=1
if [[ x"${ac_cv_mysql_root}" = xno ]]
then
ac_cv_has_mysql=
fi

if [[ x"${ac_cv_mysql_root}" = xyes ]]
then
ac_cv_mysql_root=
fi

if [[ x"${ac_cv_has_mysql}" = x1 ]]
then
  if [[ x"${ac_cv_mysql_root}" = x ]]
  then
    mysqlconfig="mysql_config"
  else
    mysqlconfig="${ac_cv_mysql_root}/bin/mysql_config"
  fi
  AC_MSG_CHECKING([for mysql library])
  mysqlversion=`"${mysqlconfig}" --version 2>/dev/null`
  if [[ $? != 0 -o x"${mysqlversion}" = x ]]
  then
    AC_MSG_RESULT([none])
    ac_cv_has_mysql=
  else
    AC_MSG_RESULT([version "${mysqlversion}"])
  fi
fi

if [[ x"${ac_cv_has_mysql}" = x1 ]]
then
  AC_MSG_CHECKING([for mysql compilation flags ])

  ac_cv_mysql_include_opt=`"${mysqlconfig}" --cflags 2>/dev/null`
  if [[ $? != 0 ]]
  then
    ac_cv_has_mysql=
  fi

  tmp_libs=`"${mysqlconfig}" --libs 2>/dev/null`
  if [[ $? != 0 ]]
  then
    ac_cv_has_mysql=
  fi
  dnl split --libs output into library paths, adding -rpath specs

  if [[ x"${ac_cv_has_mysql}" = x1 ]]
  then
    for xx in ${tmp_libs}
    do
      case "$xx" in
        -L*)
          [[ x"${ac_cv_mysql_lib_opt}" != x ]] && ac_cv_mysql_lib_opt="${ac_cv_mysql_lib_opt} "
          tmp_rpath=`echo "$xx" | sed s+-L+-Wl,-rpath,+`
          ac_cv_mysql_lib_opt="${ac_cv_mysql_lib_opt}${xx} ${tmp_rpath}"
          ;;
        -l*)
          [[ x"${ac_cv_mysql_libs}" != x ]] && ac_cv_mysql_libs="${ac_cv_mysql_libs} "
          ac_cv_mysql_libs="${ac_cv_mysql_libs}${xx}"
          ;;
        *)
          [[ x"${ac_cv_mysql_lib_opt}" != x ]] && ac_cv_mysql_lib_opt="${ac_cv_mysql_lib_opt} "
          ac_cv_mysql_lib_opt="${ac_cv_mysql_lib_opt}${xx}"
          ;;
      esac
    done
  fi

  if [[ x"${ac_cv_has_mysql}" = x1 ]]
  then
    AC_MSG_RESULT([ok])
  else
    AC_MSG_RESULT([failed])
  fi
fi

saved_CFLAGS="${CFLAGS}"
saved_CPPFLAGS="${CPPFLAGS}"
saved_LDFLAGS="${LDFLAGS}"
saved_LIBS="${LIBS}"
CFLAGS="${CFLAGS} ${ac_cv_mysql_include_opt}"
CPPFLAGS="${CPPFLAGS} ${ac_cv_mysql_include_opt}"
LDFLAGS="${LDFLAGS} ${ac_cv_mysql_lib_opt}"
LIBS="${ac_cv_mysql_libs} ${LIBS}"

if [[ x"${ac_cv_has_mysql}" = x1 ]]
then
  AC_CHECK_HEADER([mysql.h],
                [ac_cv_has_mysql=1],
                [ac_cv_has_mysql=""],
[
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
])
fi

if [[ x"${ac_cv_has_mysql}" = x1 ]]
then
  AC_CHECK_LIB([mysqlclient], [mysql_real_connect],
               [ac_cv_has_mysql=1],
               [ac_cv_has_mysql=""])
fi


CFLAGS="${saved_CFLAGS}"
CPPFLAGS="${saved_CPPFLAGS}"
LDFLAGS="${saved_LDFLAGS}"
LIBS="${saved_LIBS}"

dnl compiler warning checking
saved_CC="${CC}"
AC_MSG_CHECKING([for annoying gcc warnings])
CC="${CC} -Wall -Werror"
AC_COMPILE_IFELSE([[
#include <string.h>
#include <stdio.h>
int main(void)
{
  unsigned char *str = "zzz";
  int v = strlen(str);
  printf("%d\n", v);
  return 0;
}
]],[
AC_MSG_RESULT([no])
],[
AC_MSG_RESULT([yes])
ac_cv_annoying_warning=1
])
if [[ x"${ac_cv_annoying_warning}" = x1 ]]
then
  AC_MSG_CHECKING([for -Wno-pointer-sign])
  CC="${saved_CC} -Wno-pointer-sign -Werror"
  AC_COMPILE_IFELSE([[
int main(void)
{
  unsigned char *str = "zzz";
  return 0;
}
]],[
AC_MSG_RESULT([yes])
ac_cv_gcc_wno_pointer_sign=-Wno-pointer-sign
],[
AC_MSG_RESULT([no])
])
fi
CC="${saved_CC}"

dnl reuse checking stuff

ac_cv_has_reuse=1
if [[ x"${ac_cv_reuse_root}" = x -o x"${ac_cv_reuse_root}" = xyes -o x"${ac_cv_reuse_root}" = xno ]]
then
  dnl try reuse-config script
  AC_PATH_PROG([REUSE_CONF_SCRIPT],[reuse-config],[no])
  if [[ x"${REUSE_CONF_SCRIPT}" = xno ]]
  then
    AC_MSG_ERROR([You must specify the reuse directory using --with-reuse])
  fi
  ac_cv_reuse_include_opt=`"${REUSE_CONF_SCRIPT}" --cflags`
  ac_cv_reuse_lib_opt=`"${REUSE_CONF_SCRIPT}" --ldflags`
else
  if [[ -x "${ac_cv_reuse_root}/bin/reuse-config" ]]
  then
    REUSE_CONF_SCRIPT="${ac_cv_reuse_root}/bin/reuse-config"
    [[ x"${ac_cv_reuse_include_dir}" = x -o x"${ac_cv_reuse_include_dir}" = xyes -o x"${ac_cv_reuse_include_dir}" = xno ]] && ac_cv_reuse_include_opt=`"${REUSE_CONF_SCRIPT}" --cflags`
    [[ x"${ac_cv_reuse_lib_dir}" = x -o x"${ac_cv_reuse_lib_dir}" = xyes -o x"${ac_cv_reuse_lib_dir}" = xno ]] && ac_cv_reuse_lib_opt=`"${REUSE_CONF_SCRIPT}" --ldflags`
  else
    [[ x"${ac_cv_reuse_include_dir}" = x -o x"${ac_cv_reuse_include_dir}" = xyes -o x"${ac_cv_reuse_include_dir}" = xno ]] && ac_cv_reuse_include_dir="${ac_cv_reuse_root}/include"
    [[ x"${ac_cv_reuse_lib_dir}" = x -o x"${ac_cv_reuse_lib_dir}" = xyes -o x"${ac_cv_reuse_lib_dir}" = xno ]] && ac_cv_reuse_lib_dir="${ac_cv_reuse_root}/lib"

    if [[ x"${ac_cv_reuse_config}" = x -o x"${ac_cv_reuse_config}" = xyes -o x"${ac_cv_reuse_config}" = xno ]]
    then
      [[ x"${ac_cv_reuse_conf_dir}" = x -o x"${ac_cv_reuse_conf_dir}" = xyes -o x"${ac_cv_reuse_conf_dir}" = xno ]] && ac_cv_reuse_conf_dir="${ac_cv_reuse_root}/etc"
      if [[ ! -x "${ac_cv_reuse_conf_dir}/config.guess" ]]
      then
        AC_MSG_ERROR([The reuse configuration script config.guess is missing or non-executable at ${ac_cv_reuse_conf_dir}])
      fi
      ac_cv_reuse_config=`"${ac_cv_reuse_conf_dir}/config.guess" 2>/dev/null`
      if [[ $? != 0 -o x"${ac_cv_reuse_config}" = x ]]
      then
        AC_MSG_ERROR([The reuse configuration script returned no result])
      fi
    fi
    AC_MSG_NOTICE([using the reuse configuration ${ac_cv_reuse_config}])
  
    ac_cv_reuse_include_opt="-I${ac_cv_reuse_include_dir} -I${ac_cv_reuse_include_dir}/${ac_cv_reuse_config}"
    ac_cv_reuse_lib_opt="-L${ac_cv_reuse_lib_dir}/${ac_cv_reuse_config}"
  fi
fi

saved_CFLAGS="${CFLAGS}"
saved_CPPFLAGS="${CPPFLAGS}"
saved_LDFLAGS="${LDFLAGS}"
saved_LIBS="${LIBS}"
CFLAGS="${CFLAGS} ${ac_cv_reuse_include_opt}"
CPPFLAGS="${CPPFLAGS} ${ac_cv_reuse_include_opt}"
LDFLAGS="${LDFLAGS} ${ac_cv_reuse_lib_opt}"
LIBS="-lreuse ${LIBS} -lm"

if [[ x"${ac_cv_has_reuse}" = x1 ]]
then
  AC_CHECK_HEADER([reuse/exec.h],[],[ac_cv_has_reuse=""])
fi
if [[ x"${ac_cv_has_reuse}" = x1 ]]
then
  AC_CHECK_HEADER([reuse/format_io.h],[],[ac_cv_has_reuse=""])
fi
if [[ x"${ac_cv_has_reuse}" = x1 ]]
then
  AC_CHECK_HEADER([reuse/logger.h],[],[ac_cv_has_reuse=""])
fi
if [[ x"${ac_cv_has_reuse}" = x1 ]]
then
  AC_CHECK_HEADER([reuse/MemPage.h],[],[ac_cv_has_reuse=""])
fi
if [[ x"${ac_cv_has_reuse}" = x1 ]]
then
  AC_CHECK_HEADER([reuse/number_io.h],[],[ac_cv_has_reuse=""])
fi
if [[ x"${ac_cv_has_reuse}" = x1 ]]
then
  AC_CHECK_HEADER([reuse/osdeps.h],[],[ac_cv_has_reuse=""])
fi
if [[ x"${ac_cv_has_reuse}" = x1 ]]
then
  AC_CHECK_HEADER([reuse/xalloc.h],[],[ac_cv_has_reuse=""])
fi
if [[ x"${ac_cv_has_reuse}" = x1 ]]
then
  AC_CHECK_LIB([reuse], [os_GetWorkingDir], [], [ac_cv_has_reuse=""])
fi

dnl Check new reuse features
if [[ x"${ac_cv_has_reuse}" = x1 ]]
then
  AC_CHECK_FUNCS([task_SetMaxTimeMillis task_GetRealTime task_IsMemoryLimit task_EnableMemoryLimitError task_EnableSecureExec task_SetQuietFlag task_GetErrorMessage task_EnableAllSignals task_fPrintArgs task_IsSecurityViolation task_EnableSecurityViolationError])
fi

ac_cv_version_detected=
if [[ x"${ac_cv_has_reuse}" = x1 ]]
then
  AC_MSG_CHECKING([for reuse version >= 4])
  AC_RUN_IFELSE([[
#include <reuse/version.h>
#include <stdio.h>
#include <string.h>
int main()
{
  const char *p = reuse_compile_version;
  int major, minor, patch, build = 0, n;
  if (sscanf(p, "%d.%dpre%d #%d%n", &major, &minor, &patch, &build, &n) == 4
      && !p[n]) {
    patch = 0;
  } else if (sscanf(p, "%d.%dpre%d%n", &major, &minor, &patch, &n) == 3
             && !p[n]) {
    patch = 0;
  } else if (sscanf(p, "%d.%d.%d #%d%n", &major, &minor, &patch, &build, &n)==4
             && !p[n]) {
  } else if (sscanf(p, "%d.%d.%d%n", &major, &minor, &patch, &n) == 3
             && !p[n]) {
  } else {
    return 1;
  }
  if (major < 3 || major >= 1000) return 1;
  if (minor < 0 || minor >= 1000) return 1;
  if (patch < 0 || patch >= 1000) return 1;
  if (major >= 4) return 0;
  return 1;
}
]],[
AC_MSG_RESULT([yes])
ac_cv_version_detected=1
],[
AC_MSG_RESULT([no])
])
fi

if [[ x"${ac_cv_has_reuse}" = x1 -a x"${ac_cv_version_detected}" = x ]]
then
  AC_MSG_CHECKING([for reuse version >= 3.0.17])
  AC_RUN_IFELSE(
[[
#include <stdio.h>
#include <string.h>
extern char const reuse_release_str[];
int main()
{
  const char *p = reuse_release_str;
  int major, minor, patch, build, n;
  if (*p != '$') return 1;
  if (strncmp(p + 1, "Revision: REUSE-", 16) != 0) return 1;
  if (sscanf(p + 17, "%d.%d.%d (%d) $%n", &major, &minor, &patch, &build, &n) != 4) return 1;
  if (p[17 + n]) return 1;
  if (major < 3 || major >= 1000) return 1;
  if (minor < 0 || minor >= 1000) return 1;
  if (patch < 0 || patch >= 1000) return 1;
  if (build <= 0) return 1;
  if (major > 3) return 0;
  if (minor > 0) return 0;
  if (patch < 17) return 1;
  return 0;
}
]],[AC_MSG_RESULT([yes])],
[
AC_MSG_RESULT([no])
ac_cv_has_reuse=""
])
fi

CFLAGS="${saved_CFLAGS}"
CPPFLAGS="${saved_CPPFLAGS}"
LDFLAGS="${saved_LDFLAGS}"
LIBS="${saved_LIBS}"

if [[ x"${ac_cv_has_reuse}" != x1 ]]
then
  AC_MSG_FAILURE([The reuse library is unusable])
fi

dnl localization stuff

if [[ x"${ac_cv_nls}" = xno ]]
then
  ac_cv_nls=""
else
  ac_cv_nls=1
fi 

if [[ x"${ac_cv_nls}" = x1 ]]
then
  AC_CHECK_PROG([XGETTEXT],[xgettext],[xgettext],[false])
  [[ x"${XGETTEXT}" = xfalse ]] && ac_cv_nls=""
fi
if [[ x"${ac_cv_nls}" = x1 ]]
then
  AC_CHECK_PROG([MSGMERGE],[msgmerge],[msgmerge],[false])
  [[ x"${MSGMERGE}" = xfalse ]] && ac_cv_nls=""
fi
if [[ x"${ac_cv_nls}" = x1 ]]
then
  AC_CHECK_PROG([MSGFMT],[msgfmt],[msgfmt],[false])
  [[ x"${MSGFMT}" = xfalse ]] && ac_cv_nls=""
fi
if [[ x"${ac_cv_nls}" = x1 -a x"${ac_cv_ejudge_arch}" != xwin32 ]]
then
  AC_CHECK_HEADER([locale.h],[],[ac_cv_nls=""])
fi
if [[ x"${ac_cv_nls}" = x1 -a x"${ac_cv_ejudge_arch}" != xwin32 ]]
then
  AC_CHECK_HEADER([libintl.h],[],[ac_cv_nls=""])
fi

dnl Checking for available languages
AC_MSG_NOTICE([checking available languages])

dnl It looks like we cannot use the autoconf's macros :(

AC_MSG_CHECKING([whether GNU C is available])
if [[ x"${ac_cv_contest_gcc}" != xno -a x"${ac_cv_ejudge_arch}" != xwin32 ]]
then
  [[ x"${ac_cv_contest_gcc}" = xyes ]] && ac_cv_contest_gcc=""
  [[ x"${ac_cv_contest_gcc}" = x ]] && ac_cv_contest_gcc="gcc"
  ${ac_cv_contest_gcc} -v >/dev/null 2>/dev/null
  [[ $? != 0 ]] && ac_cv_contest_gcc=no
  if [[ x"${ac_cv_contest_gcc}" != xno ]]
  then
    ac_cv_gcc_version=`${ac_cv_contest_gcc} -v 2>&1 | grep "gcc version" | sed 's/gcc version //g'`
    [[ $? != 0 ]] && ac_cv_contest_gcc=no
  fi
  if [[ x"${ac_cv_contest_gcc}" != xno ]]
  then
    echo "int main(void) { return 0; }" > conftest.c
    ${ac_cv_contest_gcc} conftest.c -o conftest 2>/dev/null >/dev/null
    [[ $? != 0 ]] && ac_cv_contest_gcc=no
  fi
  if [[ x"${ac_cv_contest_gcc}" != xno ]]
  then
    ./conftest
    [[ $? != 0 ]] && ac_cv_contest_gcc=no
  fi  
  rm -f ./conftest*
  ac_cv_contest_gcc_dir=`dirname "${ac_cv_contest_gcc}"`
  [[ x"${ac_cv_contest_gcc_dir}" = x. ]] && ac_cv_contest_gcc_dir=""
  if [[ x"${ac_cv_contest_gcc}" != xno ]]
  then
    AC_MSG_RESULT([yes, ${ac_cv_contest_gcc}, ${ac_cv_gcc_version}])
  else
    AC_MSG_RESULT([no])
  fi
else
  AC_MSG_RESULT([disabled by user])
fi

AC_MSG_CHECKING([whether GNU C++ is available])
if [[ x"${ac_cv_contest_gpp}" != xno -a x"${ac_cv_ejudge_arch}" != xwin32 ]]
then
  [[ x"${ac_cv_contest_gpp}" = xyes ]] && ac_cv_contest_gpp=""
  [[ x"${ac_cv_contest_gpp}" = x ]] && ac_cv_contest_gpp="g++"
  ${ac_cv_contest_gpp} -v >/dev/null 2>/dev/null
  [[ $? != 0 ]] && ac_cv_contest_gpp=no
  if [[ x"${ac_cv_contest_gpp}" != xno ]]
  then
    ac_cv_gpp_version=`${ac_cv_contest_gpp} -v 2>&1 | grep "gcc version" | sed 's/gcc version //g'`
    [[ $? != 0 ]] && ac_cv_contest_gpp=no
  fi
  if [[ x"${ac_cv_contest_gpp}" != xno ]]
  then
    echo "int main(void) { return 0; }" > conftest.c
    ${ac_cv_contest_gpp} conftest.c -o conftest 2>/dev/null >/dev/null
    [[ $? != 0 ]] && ac_cv_contest_gpp=no
  fi
  if [[ x"${ac_cv_contest_gpp}" != xno ]]
  then
    ./conftest
    [[ $? != 0 ]] && ac_cv_contest_gpp=no
  fi  
  rm -f ./conftest*
  ac_cv_contest_gpp_dir=`dirname "${ac_cv_contest_gpp}"`
  [[ x"${ac_cv_contest_gpp_dir}" = x. ]] && ac_cv_contest_gpp_dir=""
  if [[ x"${ac_cv_contest_gpp}" != xno ]]
  then
    AC_MSG_RESULT([yes, ${ac_cv_contest_gpp}, ${ac_cv_gpp_version}])
  else
    AC_MSG_RESULT([no])
  fi
else
  AC_MSG_RESULT([disabled by user])
fi

AC_MSG_CHECKING([whether Free Pascal is available])
if [[ x"${ac_cv_contest_fpc}" != xno -a x"${ac_cv_ejudge_arch}" != xwin32 ]]
then
  [[ x"${ac_cv_contest_fpc}" = xyes ]] && ac_cv_contest_fpc=""
  [[ x"${ac_cv_contest_fpc}" = x ]] && ac_cv_contest_fpc="fpc"
  ${ac_cv_contest_fpc} -v >/dev/null 2>/dev/null
  [[ $? != 0 -a $? != 1 ]] && ac_cv_contest_fpc=no
  if [[ x"${ac_cv_contest_fpc}" != xno ]]
  then
    ac_cv_fpc_version=`${ac_cv_contest_fpc} -h 2>/dev/null | grep "Free Pascal Compiler" | gawk '{ print $5; }'`
    [[ $? != 0 -a $? != 1 ]] && ac_cv_contest_fpc=no
  fi
  if [[ x"${ac_cv_contest_fpc}" != xno ]]
  then
    echo "begin end." > conftest.pas
    ${ac_cv_contest_fpc} conftest.pas -oconftest 2>/dev/null >/dev/null
    [[ $? != 0 ]] && ac_cv_contest_fpc=no
  fi
  if [[ x"${ac_cv_contest_fpc}" != xno ]]
  then
    ./conftest
    [[ $? != 0 ]] && ac_cv_contest_fpc=no
  fi  
  rm -f ./conftest*
  ac_cv_contest_fpc_dir=`dirname "${ac_cv_contest_fpc}"`
  [[ x"${ac_cv_contest_fpc_dir}" = x. ]] && ac_cv_contest_fpc_dir=""
  if [[ x"${ac_cv_contest_fpc}" != xno ]]
  then
    AC_MSG_RESULT([yes, ${ac_cv_contest_fpc}, ${ac_cv_fpc_version}])
  else
    AC_MSG_RESULT([no])
  fi
else
  AC_MSG_RESULT([disabled by user])
fi

AC_MSG_CHECKING([whether GNU Pascal is available])
if [[ x"${ac_cv_contest_gpc}" != xno -a x"${ac_cv_ejudge_arch}" != xwin32 ]]
then
  [[ x"${ac_cv_contest_gpc}" = xyes ]] && ac_cv_contest_gpc=""
  [[ x"${ac_cv_contest_gpc}" = x ]] && ac_cv_contest_gpc="gpc"
  ${ac_cv_contest_gpc} -v >/dev/null 2>/dev/null
  [[ $? != 0 ]] && ac_cv_contest_gpc=no
  if [[ x"${ac_cv_contest_gpc}" != xno ]]
  then
    ac_cv_gpc_version=`${ac_cv_contest_gpc} --version | gawk '{ print $1; exit 0; }'`
    [[ $? != 0 -a $? != 1 ]] && ac_cv_contest_gpc=no
  fi
  if [[ x"${ac_cv_contest_gpc}" != xno ]]
  then
    echo "begin end." > conftest.pas
    ${ac_cv_contest_gpc} conftest.pas -o conftest 2>/dev/null >/dev/null
    [[ $? != 0 ]] && ac_cv_contest_gpc=no
  fi
  if [[ x"${ac_cv_contest_gpc}" != xno ]]
  then
    ./conftest
    [[ $? != 0 ]] && ac_cv_contest_gpc=no
  fi  
  rm -f ./conftest*
  ac_cv_contest_gpc_dir=`dirname "${ac_cv_contest_gpc}"`
  [[ x"${ac_cv_contest_gpc_dir}" = x. ]] && ac_cv_contest_gpc_dir=""
  if [[ x"${ac_cv_contest_gpc}" != xno ]]
  then
    AC_MSG_RESULT([yes, ${ac_cv_contest_gpc}, ${ac_cv_gpc_version}])
  else
    AC_MSG_RESULT([no])
  fi
else
  AC_MSG_RESULT([disabled by user])
fi

AC_MSG_CHECKING([whether Borland Delphi is available])
if [[ x"${ac_cv_contest_dcc}" != xno -a x"${ac_cv_ejudge_arch}" != xwin32 ]]
then
  [[ x"${ac_cv_contest_dcc}" = xyes ]] && ac_cv_contest_dcc=""
  [[ x"${ac_cv_contest_dcc}" = x ]] && ac_cv_contest_dcc="dcc"
  ${ac_cv_contest_dcc} -v >/dev/null 2>/dev/null
  [[ $? != 0 ]] && ac_cv_contest_dcc=no
  if [[ x"${ac_cv_contest_dcc}" != xno ]]
  then
    ac_cv_dcc_version=`${ac_cv_contest_dcc} -h 2>/dev/null | grep "Borland Delphi" | gawk '{ print $6; }'`
    [[ $? != 0 ]] && ac_cv_contest_dcc=no
  fi
  if [[ x"${ac_cv_contest_dcc}" != xno ]]
  then
    echo "begin end." > conftest.pas
    ${ac_cv_contest_dcc} conftest.pas 2>/dev/null >/dev/null
    [[ $? != 0 ]] && ac_cv_contest_dcc=no
  fi
  if [[ x"${ac_cv_contest_dcc}" != xno ]]
  then
    ./conftest 2>/dev/null
    [[ $? != 0 ]] && ac_cv_contest_dcc=no
  fi  
  rm -f ./conftest*
  ac_cv_contest_dcc_dir=`dirname "${ac_cv_contest_dcc}"`
  [[ x"${ac_cv_contest_dcc_dir}" = x. ]] && ac_cv_contest_dcc_dir=""
  if [[ x"${ac_cv_contest_dcc}" != xno ]]
  then
    AC_MSG_RESULT([yes, ${ac_cv_contest_dcc}, ${ac_cv_dcc_version}])
  else
    AC_MSG_RESULT([no])
  fi
else
  AC_MSG_RESULT([disabled by user])
fi

AC_MSG_CHECKING([whether GNU Java (GCJ) is available])
if [[ x"${ac_cv_contest_gcj}" != xno -a x"${ac_cv_ejudge_arch}" != xwin32 ]]
then
  [[ x"${ac_cv_contest_gcj}" = xyes ]] && ac_cv_contest_gcj=""
  [[ x"${ac_cv_contest_gcj}" = x ]] && ac_cv_contest_gcj="gcj"
  ${ac_cv_contest_gcj} -v >/dev/null 2>/dev/null
  [[ $? != 0 ]] && ac_cv_contest_gcj=no
  if [[ x"${ac_cv_contest_gcj}" != xno ]]
  then
    ac_cv_gcj_version=`${ac_cv_contest_gcj} --version | grep gcj | gawk '{ print $3; }'`
    [[ $? != 0 -a $? != 1 ]] && ac_cv_contest_gcj=no
  fi
  if [[ x"${ac_cv_contest_gcj}" != xno ]]
  then
    echo "class Main { public static void main(String args[[]]) { System.exit(0); } }" > conftest.java
    ${ac_cv_contest_gcj} --main=Main conftest.java -o conftest 2>/dev/null >/dev/null
    [[ $? != 0 ]] && ac_cv_contest_gcj=no
  fi
  if [[ x"${ac_cv_contest_gcj}" != xno ]]
  then
    ./conftest 2>/dev/null
    [[ $? != 0 ]] && ac_cv_contest_gcj=no
  fi  
  rm -f ./conftest*
  ac_cv_contest_gcj_dir=`dirname "${ac_cv_contest_gcj}"`
  [[ x"${ac_cv_contest_gcj_dir}" = x. ]] && ac_cv_contest_gcj_dir=""
  if [[ x"${ac_cv_contest_gcj}" != xno ]]
  then
    AC_MSG_RESULT([yes, ${ac_cv_contest_gcj}, ${ac_cv_gcj_version}])
  else
    AC_MSG_RESULT([no])
  fi
else
  AC_MSG_RESULT([disabled by user])
fi

AC_MSG_CHECKING([whether GNU Fortran 77 is available])
if [[ x"${ac_cv_contest_g77}" != xno -a x"${ac_cv_ejudge_arch}" != xwin32 ]]
then
  [[ x"${ac_cv_contest_g77}" = xyes ]] && ac_cv_contest_g77=""
  [[ x"${ac_cv_contest_g77}" = x ]] && ac_cv_contest_g77="g77"
  ${ac_cv_contest_g77} -v >/dev/null 2>/dev/null
  [[ $? != 0 ]] && ac_cv_contest_g77=no
  if [[ x"${ac_cv_contest_g77}" != xno ]]
  then
    ac_cv_g77_version=`${ac_cv_contest_g77} --version | grep "GNU Fortran (GCC)" | gawk '{ print $4; }'`
    [[ $? != 0 -a $? != 1 ]] && ac_cv_contest_g77=no
  fi
  if [[ x"${ac_cv_contest_g77}" != xno ]]
  then
    echo "        END" > conftest.for
    ${ac_cv_contest_g77} conftest.for -o conftest 2>/dev/null >/dev/null
    [[ $? != 0 ]] && ac_cv_contest_g77=no
  fi
  if [[ x"${ac_cv_contest_g77}" != xno ]]
  then
    ./conftest 2>/dev/null
    [[ $? != 0 ]] && ac_cv_contest_g77=no
  fi  
  rm -f ./conftest*
  ac_cv_contest_g77_dir=`dirname "${ac_cv_contest_g77}"`
  [[ x"${ac_cv_contest_g77_dir}" = x. ]] && ac_cv_contest_g77_dir=""
  if [[ x"${ac_cv_contest_g77}" != xno ]]
  then
    AC_MSG_RESULT([yes, ${ac_cv_contest_g77}, ${ac_cv_g77_version}])
  else
    AC_MSG_RESULT([no])
  fi
else
  AC_MSG_RESULT([disabled by user])
fi

AC_MSG_CHECKING([whether GNU Fortran 90 is available])
if [[ x"${ac_cv_contest_gfortran}" != xno -a x"${ac_cv_ejudge_arch}" != xwin32 ]]
then
  [[ x"${ac_cv_contest_gfortran}" = xyes ]] && ac_cv_contest_gfortran=""
  [[ x"${ac_cv_contest_gfortran}" = x ]] && ac_cv_contest_gfortran="gfortran"
  ${ac_cv_contest_gfortran} -v >/dev/null 2>/dev/null
  [[ $? != 0 ]] && ac_cv_contest_gfortran=no
  if [[ x"${ac_cv_contest_gfortran}" != xno ]]
  then
    ac_cv_gfortran_version=`${ac_cv_contest_gfortran} --version | grep "GNU Fortran" | grep "GCC" | gawk '{ print $(NF); }'`
    [[ $? != 0 -a $? != 1 ]] && ac_cv_contest_gfortran=no
  fi
  if [[ x"${ac_cv_contest_gfortran}" != xno ]]
  then
    echo "        END" > conftest.for
    ${ac_cv_contest_gfortran} conftest.for -o conftest 2>/dev/null >/dev/null
    [[ $? != 0 ]] && ac_cv_contest_gfortran=no
  fi
  if [[ x"${ac_cv_contest_gfortran}" != xno ]]
  then
    ./conftest 2>/dev/null
    [[ $? != 0 ]] && ac_cv_contest_gfortran=no
  fi  
  rm -f ./conftest*
  ac_cv_contest_gfortran_dir=`dirname "${ac_cv_contest_gfortran}"`
  [[ x"${ac_cv_contest_gfortran_dir}" = x. ]] && ac_cv_contest_gfortran_dir=""
  if [[ x"${ac_cv_contest_gfortran}" != xno ]]
  then
    AC_MSG_RESULT([yes, ${ac_cv_contest_gfortran}, ${ac_cv_gfortran_version}])
  else
    AC_MSG_RESULT([no])
  fi
else
  AC_MSG_RESULT([disabled by user])
fi

AC_MSG_CHECKING([whether Yabasic interpreter is available])
if [[ x"${ac_cv_contest_yabasic}" != xno -a x"${ac_cv_ejudge_arch}" != xwin32 ]]
then
  [[ x"${ac_cv_contest_yabasic}" = xyes ]] && ac_cv_contest_yabasic=""
  [[ x"${ac_cv_contest_yabasic}" = x ]] && ac_cv_contest_yabasic="yabasic"
  ${ac_cv_contest_yabasic} -help 2>/dev/null 1>/dev/null
  [[ $? != 0 ]] && ac_cv_contest_yabasic=no
  if [[ x"${ac_cv_contest_yabasic}" != xno ]]
  then
    ac_cv_yabasic_version=`${ac_cv_contest_yabasic} -help 2>&1 | grep "yabasic version" | gawk '{ print $5; }'`
    [[ $? != 0 ]] && ac_cv_contest_yabasic=no
  fi
  if [[ x"${ac_cv_contest_yabasic}" != xno ]]
  then
    ac_cv_contest_yabasic_path=`which "${ac_cv_contest_yabasic}"`
    [[ $? != 0 ]] && ac_cv_contest_yabasic=no
  fi
  if [[ x"${ac_cv_contest_yabasic}" != xno ]]
  then
    echo "#!${ac_cv_contest_yabasic_path}" > conftest.bas
    echo 'PRINT "OK"' >> conftest.bas 
    echo "END" >> conftest.bas
    chmod +x ./conftest.bas
    ./conftest.bas 2>/dev/null 1>/dev/null
    [[ $? != 0 ]] && ac_cv_contest_yabasic=no
  fi
  if [[ x"${ac_cv_contest_yabasic}" != xno ]]
  then
    AC_MSG_RESULT([yes, ${ac_cv_contest_yabasic}, ${ac_cv_yabasic_version}])
  else
    AC_MSG_RESULT([no])
  fi
else
  AC_MSG_RESULT([disabled by user])
fi

AC_MSG_CHECKING([whether MzScheme interpreter is available])
if [[ x"${ac_cv_contest_mzscheme}" != xno -a x"${ac_cv_ejudge_arch}" != xwin32 ]]
then
  [[ x"${ac_cv_contest_mzscheme}" = xyes ]] && ac_cv_contest_mzscheme=""
  [[ x"${ac_cv_contest_mzscheme}" = x ]] && ac_cv_contest_mzscheme="mzscheme"
  ${ac_cv_contest_mzscheme} --version 2>/dev/null 1>/dev/null
  [[ $? != 0 ]] && ac_cv_contest_mzscheme=no
  if [[ x"${ac_cv_contest_mzscheme}" != xno ]]
  then
    ac_cv_mzscheme_version=`${ac_cv_contest_mzscheme} --version 2>&1 | grep "MzScheme version" | gawk -v FS="[[ ,]]" '{ if ($4 == "version") print $5; else print $4; }'`
    [[ $? != 0 ]] && ac_cv_contest_mzscheme=no
  fi
  if [[ x"${ac_cv_contest_mzscheme}" != xno ]]
  then
    ac_cv_contest_mzscheme_path=`which "${ac_cv_contest_mzscheme}"`
    [[ $? != 0 ]] && ac_cv_contest_mzscheme=no
  fi
  if [[ x"${ac_cv_contest_mzscheme}" != xno ]]
  then
    echo "#!${ac_cv_contest_mzscheme_path} -qr" > conftest.scm
    echo '(display "OK")' >> conftest.scm
    chmod +x ./conftest.scm
    ./conftest.scm 2>/dev/null 1>/dev/null
    [[ $? != 0 ]] && ac_cv_contest_mzscheme=no
  fi
  if [[ x"${ac_cv_contest_mzscheme}" != xno ]]
  then
    AC_MSG_RESULT([yes, ${ac_cv_contest_mzscheme}, ${ac_cv_mzscheme_version}])
  else
    AC_MSG_RESULT([no])
  fi
else
  AC_MSG_RESULT([disabled by user])
fi

AC_MSG_CHECKING([whether Perl interpreter is available])
if [[ x"${ac_cv_contest_perl}" != xno -a x"${ac_cv_ejudge_arch}" != xwin32 ]]
then
  [[ x"${ac_cv_contest_perl}" = xyes ]] && ac_cv_contest_perl=""
  [[ x"${ac_cv_contest_perl}" = x ]] && ac_cv_contest_perl="perl"
  ${ac_cv_contest_perl} --version 2>/dev/null 1>/dev/null
  [[ $? != 0 ]] && ac_cv_contest_perl=no
  if [[ x"${ac_cv_contest_perl}" != xno ]]
  then
    ac_cv_perl_version=`${ac_cv_contest_perl} --version 2>&1 | grep "This is perl" | gawk -v FS="[[ v]]" '{ print $5; }'`
    [[ $? != 0 ]] && ac_cv_contest_perl=no
  fi
  if [[ x"${ac_cv_contest_perl}" != xno ]]
  then
    ac_cv_contest_perl_path=`which "${ac_cv_contest_perl}"`
    [[ $? != 0 ]] && ac_cv_contest_perl=no
  fi
  if [[ x"${ac_cv_contest_perl}" != xno ]]
  then
    echo "#!${ac_cv_contest_perl_path} -W" > conftest.pl
    echo 'print "OK"' >> conftest.pl
    chmod +x ./conftest.pl
    ./conftest.pl 2>/dev/null 1>/dev/null
    [[ $? != 0 ]] && ac_cv_contest_perl=no
  fi
  if [[ x"${ac_cv_contest_perl}" != xno ]]
  then
    AC_MSG_RESULT([yes, ${ac_cv_contest_perl}, ${ac_cv_perl_version}])
  else
    AC_MSG_RESULT([no])
  fi
else
  AC_MSG_RESULT([disabled by user])
fi

AC_MSG_CHECKING([whether Python interpreter is available])
if [[ x"${ac_cv_contest_python}" != xno -a x"${ac_cv_ejudge_arch}" != xwin32 ]]
then
  [[ x"${ac_cv_contest_python}" = xyes ]] && ac_cv_contest_python=""
  [[ x"${ac_cv_contest_python}" = x ]] && ac_cv_contest_python="python"
  ${ac_cv_contest_python} -V 2>/dev/null 1>/dev/null
  [[ $? != 0 ]] && ac_cv_contest_python=no
  if [[ x"${ac_cv_contest_python}" != xno ]]
  then
    ac_cv_python_version=`${ac_cv_contest_python} -V 2>&1 | gawk '{ print $2; }'`
    [[ $? != 0 ]] && ac_cv_contest_python=no
  fi
  if [[ x"${ac_cv_contest_python}" != xno ]]
  then
    ac_cv_contest_python_path=`which "${ac_cv_contest_python}"`
    [[ $? != 0 ]] && ac_cv_contest_python=no
  fi
  if [[ x"${ac_cv_contest_python}" != xno ]]
  then
    echo "#!${ac_cv_contest_python_path}" > conftest.py
    echo 'print "OK"' >> conftest.py
    chmod +x ./conftest.py
    ./conftest.py 2>/dev/null 1>/dev/null
    [[ $? != 0 ]] && ac_cv_contest_python=no
  fi
  if [[ x"${ac_cv_contest_python}" != xno ]]
  then
    AC_MSG_RESULT([yes, ${ac_cv_contest_python}, ${ac_cv_python_version}])
  else
    AC_MSG_RESULT([no])
  fi
else
  AC_MSG_RESULT([disabled by user])
fi

AC_MSG_CHECKING([whether GNU Prolog is available])
if [[ x"${ac_cv_contest_gprolog}" != xno -a x"${ac_cv_ejudge_arch}" != xwin32 ]]
then
  [[ x"${ac_cv_contest_gprolog}" = xyes ]] && ac_cv_contest_gprolog=""
  [[ x"${ac_cv_contest_gprolog}" = x ]] && ac_cv_contest_gprolog="gplc"
  ${ac_cv_contest_gprolog} --version >/dev/null 2>/dev/null
  [[ $? != 0 ]] && ac_cv_contest_gprolog=no
  if [[ x"${ac_cv_contest_gprolog}" != xno ]]
  then
    ac_cv_gprolog_version=`${ac_cv_contest_gprolog} --version 2>&1 | grep "Prolog compiler" | gawk '{ print $5; }'`
    [[ $? != 0 -a $? != 1 ]] && ac_cv_contest_gprolog=no
  fi
  if [[ x"${ac_cv_contest_gprolog}" != xno ]]
  then
    echo ":-initialization(main)." > conftest.pro
    echo "main :- write('OK'), halt." >> conftest.pro
    ${ac_cv_contest_gprolog} -L --no-top-level conftest.pro -o conftest 2>/dev/null >/dev/null
    [[ $? != 0 ]] && ac_cv_contest_gprolog=no
  fi
  if [[ x"${ac_cv_contest_gprolog}" != xno ]]
  then
    ./conftest 2>/dev/null >/dev/null
    [[ $? != 0 ]] && ac_cv_contest_gprolog=no
  fi  
  rm -f ./conftest*
  ac_cv_contest_gprolog_dir=`dirname "${ac_cv_contest_gprolog}"`
  [[ x"${ac_cv_contest_gprolog_dir}" = x. ]] && ac_cv_contest_gprolog_dir=""
  if [[ x"${ac_cv_contest_gprolog}" != xno ]]
  then
    AC_MSG_RESULT([yes, ${ac_cv_contest_gprolog}, ${ac_cv_gprolog_version}])
  else
    AC_MSG_RESULT([no])
  fi
else
  AC_MSG_RESULT([disabled by user])
fi

AC_MSG_CHECKING([whether Java SDK is available])
if [[ x"${ac_cv_contest_javac}" != xno -a x"${ac_cv_ejudge_arch}" != xwin32 ]]
then
  [[ x"${ac_cv_contest_javac}" = xyes ]] && ac_cv_contest_javac=""
  [[ x"${ac_cv_contest_javac}" = x ]] && ac_cv_contest_javac="javac"

  dnl javac -version is not supported until java 1.5 :-(
  ac_cv_contest_java=`dirname "${ac_cv_contest_javac}"`
  if [[ x"${ac_cv_contest_java}" = x. ]]
  then
    dnl probably javac is specified without full path
    ac_cv_contest_java=java
  else
    ac_cv_contest_java="${ac_cv_contest_java}/java"
  fi

  "${ac_cv_contest_java}" -version >/dev/null 2>/dev/null
  [[ $? != 0 ]] && ac_cv_contest_java=no

  if [[ x"${ac_cv_contest_java}" != xno ]]
  then
    tmp_java_dir=`which "${ac_cv_contest_java}"`
    [[ x"${tmp_java_dir}" = x ]] && ac_cv_contest_java=no
  fi
  if [[ x"${ac_cv_contest_java}" != xno ]]
  then
    tmp_java_dir=`dirname "${tmp_java_dir}"`
    [[ x"${tmp_java_dir}" = x -o x"${tmp_java_dir}" = x. ]] && ac_cv_contest_java=no
  fi  
  if [[ x"${ac_cv_contest_java}" != xno ]]
  then
    tmp_b=`basename "${tmp_java_dir}"`
    [[ x"${tmp_b}" != xbin ]] && ac_cv_contest_java=no
  fi
  if [[ x"${ac_cv_contest_java}" != xno ]]
  then
    ac_cv_contest_java_dir=`dirname "${tmp_java_dir}"`
    [[ x"${ac_cv_contest_java_dir}" = x. ]] && ac_cv_contest_java=no
  fi

  if [[ x"${ac_cv_contest_java}" != xno ]]
  then
    ac_cv_contest_java_version_string=`${ac_cv_contest_java} -version 2>&1 | grep "java version" | sed 's/^.*"\(.*\)"$/\1/g'`
    [[ x"${ac_cv_contest_java_version_string}" = x ]] && ac_cv_contest_java=no
  fi

  if [[ x"${ac_cv_contest_java}" != xno ]]
  then
    case x"${ac_cv_contest_java_version_string}" in
      x1.6.*) ac_cv_contest_java_version=1.6;;
      x1.5.*) ac_cv_contest_java_version=1.5;;
      x1.4.*) ac_cv_contest_java_version=1.4;;
      x1.3.*) ac_cv_contest_java_version=1.3;;
      x1.2.*) ac_cv_contest_java_version=1.2;;
      x1.*) ac_cv_contest_java=no;; dnl FIXME: report error
      *) ac_cv_contest_java=no;; dnl FIXME: report error
    esac
  fi

  if [[ x"${ac_cv_contest_java}" != xno ]]
  then
    echo 'public class conftest { public static void main(String args[[]]) { System.out.println("OK"); } }' > conftest.java
    ${ac_cv_contest_javac} -source ${ac_cv_contest_java_version} conftest.java >/dev/null 2>/dev/null
    [[ $? != 0 ]] && ac_cv_contest_java=no
  fi

  if [[ x"${ac_cv_contest_java}" != xno ]]
  then
    touch conftest.policy
    ${ac_cv_contest_java} -Djava.security.manager -Djava.security.policy=olimp.policy conftest >/dev/null 2>/dev/null
    [[ $? != 0 ]] && ac_cv_contest_java=no
  fi
  rm -f ./conftest*

  if [[ x"${ac_cv_contest_java}" != xno ]]
  then
    AC_MSG_RESULT([yes, ${ac_cv_contest_java}, ${ac_cv_contest_java_version_string}])
  else
    AC_MSG_RESULT([no])
    ac_cv_contest_javac=no
  fi
else
  AC_MSG_RESULT([disabled by user])
  ac_cv_contest_java=no
fi

AC_MSG_CHECKING([whether C-sharp (Mono) is available])
if [[ x"${ac_cv_contest_mcs}" != xno -a x"${ac_cv_ejudge_arch}" != xwin32 ]]
then
  [[ x"${ac_cv_contest_mcs}" = xyes ]] && ac_cv_contest_mcs=""
  [[ x"${ac_cv_contest_mcs}" = x ]] && ac_cv_contest_mcs="mcs"

  ac_cv_contest_mono=`dirname "${ac_cv_contest_mcs}"`
  if [[ x"${ac_cv_contest_mono}" = x. ]]
  then
    dnl probably mcs is specified without full path
    ac_cv_contest_mono=mono
  else
    ac_cv_contest_mono="${ac_cv_contest_mono}/mono"
  fi

  "${ac_cv_contest_mono}" --version >/dev/null 2>/dev/null
  [[ $? != 0 ]] && ac_cv_contest_mono=no

  if [[ x"${ac_cv_contest_mono}" != xno ]]
  then
    ac_cv_contest_mono_version_string=`${ac_cv_contest_mono} --version 2>&1 | grep "version" | awk '{gsub(",","",$5); print $5;}'`
    [[ x"${ac_cv_contest_mono_version_string}" = x ]] && ac_cv_contest_mono=no
  fi

  if [[ x"${ac_cv_contest_mono}" != xno ]]
  then
    echo 'public class conftest { public static void Main() { System.Console.WriteLine("OK"); } }' > conftest.cs
    ${ac_cv_contest_mcs} conftest.cs -out:conftest.exe >/dev/null 2>/dev/null
    [[ $? != 0 ]] && ac_cv_contest_mono=no
  fi

  if [[ x"${ac_cv_contest_mono}" != xno ]]
  then
    ${ac_cv_contest_mono} conftest.exe >/dev/null 2>/dev/null
    [[ $? != 0 ]] && ac_cv_contest_mono=no
  fi
  rm -f ./conftest*

  if [[ x"${ac_cv_contest_mono}" != xno ]]
  then
    AC_MSG_RESULT([yes, ${ac_cv_contest_mono}, ${ac_cv_contest_mono_version_string}])
  else
    AC_MSG_RESULT([no])
    ac_cv_contest_mcs=no
  fi
else
  AC_MSG_RESULT([disabled by user])
  ac_cv_contest_mono=no
fi

if [[ x"${ac_cv_contest_mono}" != xno -a x"${ac_cv_ejudge_arch}" != xwin32 ]]
then
  AC_MSG_CHECKING([whether Visual Basic (Mono) is available])
  if [[ x"${ac_cv_contest_mbas}" != xno ]]
  then
    [[ x"${ac_cv_contest_mbas}" = xyes ]] && ac_cv_contest_mbas=""
    [[ x"${ac_cv_contest_mbas}" = x ]] && ac_cv_contest_mbas="mbas"

    "${ac_cv_contest_mbas}" -about >/dev/null 2>/dev/null
    [[ $? != 0 -a $? != 1 ]] && ac_cv_contest_mbas=no

    if [[ x"${ac_cv_contest_mbas}" != xno ]]
    then
      ac_cv_contest_mbas_version_string=`${ac_cv_contest_mbas} -about 2>&1 | head -1 | awk '{print $3;}'`
      [[ x"${ac_cv_contest_mbas_version_string}" = x ]] && ac_cv_contest_mbas=no
    fi

    if [[ x"${ac_cv_contest_mbas}" != xno ]]
    then
      echo 'Imports System\nModule Test\nSub Main()\nConsole.WriteLine("OK")\nEnd Sub\nEnd Module' > conftest.vb
      ${ac_cv_contest_mbas} conftest.vb -out:conftest.exe >/dev/null 2>/dev/null
      [[ $? != 0 ]] && ac_cv_contest_mbas=no
    fi

    if [[ x"${ac_cv_contest_mbas}" != xno ]]
    then
      ${ac_cv_contest_mono} conftest.exe >/dev/null 2>/dev/null
      [[ $? != 0 ]] && ac_cv_contest_mbas=no
    fi
    rm -f ./conftest*

    if [[ x"${ac_cv_contest_mbas}" != xno ]]
    then
      AC_MSG_RESULT([yes, ${ac_cv_contest_mbas}, ${ac_cv_contest_mbas_version_string}])
    else
      AC_MSG_RESULT([no])
      ac_cv_contest_mbas=no
    fi
  else
    AC_MSG_RESULT([disabled by user])
    ac_cv_contest_mbas=no
  fi
else
  ac_cv_contest_mbas=no
fi

dnl Create the expanded locale_dir path
if [[ x"${prefix}" = xNONE ]]
then
  actual_prefix="${ac_default_prefix}"
else
  actual_prefix="${prefix}"
fi

if [[ x"${exec_prefix}" = xNONE ]]
then
  actual_exec_prefix="${actual_prefix}"
else
  actual_exec_prefix="${exec_prefix}"
fi

if [[ x"${libexecdir}" = x'${exec_prefix}/libexec' ]]
then
  actual_libexecdir="${actual_exec_prefix}/libexec"
else
  actual_libexecdir="${libexecdir}"
fi

ac_cv_expanded_prefix="${actual_prefix}"
ac_cv_expanded_locale_dir="${actual_prefix}/share/locale"
if [[ x"${ac_cv_hidden_bins}" != x ]]
then
  ac_cv_ejudge_server_bin_path="${actual_libexecdir}/ejudge/bin"
  ac_cv_ejudge_server_bin_path_m="${libexecdir}/ejudge/bin"
else
  ac_cv_ejudge_server_bin_path="${actual_prefix}/bin"
  ac_cv_ejudge_server_bin_path_m="${bindir}"
fi
ac_cv_ejudge_serve_path="${ac_cv_ejudge_server_bin_path}/serve"
ac_cv_ejudge_run_path="${ac_cv_ejudge_server_bin_path}/run"
ac_cv_ejudge_script_dir="${libexecdir}/ejudge"
ac_cv_ejudge_script_dir_expanded="${actual_libexecdir}/ejudge"
if [[ x"${cgibindir}" = x'${libexecdir}/ejudge/cgi-bin' ]]
then
  ac_cv_ejudge_cgi_bin_dir="${actual_libexecdir}/ejudge/cgi-bin"
else
  ac_cv_ejudge_cgi_bin_dir="${cgibindir}"
fi

[[ x"${ac_cv_charset}" = xyes -o x"${ac_cv_charset}" = xno ]] && ac_cv_charset=""
[[ x"${ac_cv_socket_path}" = xyes -o x"${ac_cv_socket_path}" = xno ]] && ac_cv_socket_path=""
[[ x"${ac_cv_super_serve_socket}" = xyes -o x"${ac_cv_super_serve_socket}" = xno ]] && ac_cv_super_serve_socket=""
[[ x"${ac_cv_new_server_socket}" = xno ]] && ac_cv_new_server_socket=""

[[ x"${ac_cv_charset}" = x ]] && ac_cv_charset="utf-8"

[[ x"${ac_cv_conf_dir}" = xyes -o x"${ac_cv_conf_dir}" = xno ]] && ac_cv_conf_dir=""
if [[ x"${ac_cv_conf_dir}" != x ]]
then
# ac_cv_cgi_conf_dir
[[ x"${ac_cv_cgi_conf_dir}" = x -o x"${ac_cv_cgi_conf_dir}" = xyes ]] && ac_cv_cgi_conf_dir="${ac_cv_conf_dir}"
[[ x"${ac_cv_cgi_conf_dir}" = xno ]] && ac_cv_cgi_conf_dir=""
# ac_cv_ejudge_xml
[[ x"${ac_cv_ejudge_xml}" = x -o x"${ac_cv_ejudge_xml}" = xyes ]] && ac_cv_ejudge_xml="${ac_cv_conf_dir}/ejudge.xml"
[[ x"${ac_cv_ejudge_xml}" = xno ]] && ac_cv_ejudge_xml=""
# ac_cv_contests_dir
[[ x"${ac_cv_contests_dir}" = x -o x"${ac_cv_contests_dir}" = xyes ]] && ac_cv_contests_dir="${ac_cv_conf_dir}/contests"
[[ x"${ac_cv_contests_dir}" = xno ]] && ac_cv_contests_dir=""
else
# ac_cv_cgi_conf_dir
[[ x"${ac_cv_cgi_conf_dir}" = x -o x"${ac_cv_cgi_conf_dir}" = xyes ]] && ac_cv_cgi_conf_dir="../cgi-data"
[[ x"${ac_cv_cgi_conf_dir}" = xno ]] && ac_cv_cgi_conf_dir=""
# ac_cv_ejudge_xml
[[ x"${ac_cv_ejudge_xml}" = xyes -o x"${ac_cv_ejudge_xml}" = xno ]] && ac_cv_ejudge_xml=""
# ac_cv_contests_dir
[[ x"${ac_cv_contests_dir}" = xyes -o x"${ac_cv_contests_dir}" = xno ]] && ac_cv_contests_dir=""
fi

# ac_cv_httpd_cgi_bin_dir
[[ x"${ac_cv_httpd_cgi_bin_dir}" = xyes -o x"${ac_cv_httpd_cgi_bin_dir}" = xno ]] && ac_cv_httpd_cgi_bin_dir=""
# ac_cv_httpd_htdocs_dir
[[ x"${ac_cv_httpd_htdocs_dir}" = xyes -o x"${ac_cv_httpd_htdocs_dir}" = xno ]] && ac_cv_httpd_htdocs_dir=""

# ac_cv_contests_home_dir
[[ x"${ac_cv_contests_home_dir}" = xyes -o x"${ac_cv_contests_home_dir}" = xno ]] && ac_cv_contests_home_dir=""

if [[ x"${ac_cv_rpath}" = xno ]]
then
  ac_cv_no_rpath=1
else
  ac_cv_no_rpath=""
fi
dnl Output generation

if [[ x"${ac_cv_ejudge_arch}" = xwin32 ]]
then
  rm -f Makefile.in
  cp -p Makefile.win32.in Makefile.in
  rm -f checkers/Makefile.in
  cp -p checkers/Makefile.win32.in checkers/Makefile.in
else
  rm -f Makefile.in
  cp -p Makefile.unix.in Makefile.in
  rm -f checkers/Makefile.in
  cp -p checkers/Makefile.unix.in checkers/Makefile.in
fi

CHARSET_UPPERCASE=`echo ${ac_cv_charset} | tr '[[:lower:]]' '[[:upper:]]'`
ac_cv_ncurses_suffix=
if [[ "${CHARSET_UPPERCASE}" = UTF-8 ]]
then
  ac_cv_ncurses_suffix=w
fi

if [[ x"${ac_cv_has_libcap}" != x ]]
then
  ac_cv_libcap_link=-lcap
fi

AC_SUBST(ac_cv_ejudge_arch)
AC_SUBST(ac_cv_exe_suffix)
AC_SUBST(ac_cv_expat_root)
AC_SUBST(ac_cv_expat_include_opt)
AC_SUBST(ac_cv_expat_lib_opt)
AC_SUBST(ac_cv_reuse_root)
AC_SUBST(ac_cv_reuse_config)
AC_SUBST(ac_cv_reuse_include_opt)
AC_SUBST(ac_cv_reuse_lib_opt)
AC_SUBST(ac_cv_libcap_root)
AC_SUBST(ac_cv_libcap_include_opt)
AC_SUBST(ac_cv_libcap_lib_opt)
AC_SUBST(ac_cv_mysql_root)
AC_SUBST(ac_cv_mysql_include_opt)
AC_SUBST(ac_cv_mysql_lib_opt)
AC_SUBST(ac_cv_mysql_libs)
AC_SUBST(ac_cv_cgi_suffix)
AC_SUBST(ac_cv_static)
AC_SUBST(ac_cv_cgi_conf_dir)
AC_SUBST(ac_cv_no_kernel)
AC_SUBST(ac_cv_no_rpath)
AC_SUBST(ac_cv_nls)
AC_SUBST(ac_cv_gcc_wno_pointer_sign)
AC_SUBST(cgibindir)
AC_SUBST(XGETTEXT)
AC_SUBST(MSGMERGE)
AC_SUBST(MSGFMT)
AC_SUBST(ac_cv_style_prefix)
AC_SUBST(CHARSET_UPPERCASE)
AC_SUBST(ac_cv_ncurses_suffix)
AC_SUBST(ac_cv_local_dir)
AC_SUBST(ac_cv_werror_flag)

AC_SUBST(ac_cv_contest_gcc)
AC_SUBST(ac_cv_contest_gcc_dir)
AC_SUBST(ac_cv_contest_gpp)
AC_SUBST(ac_cv_contest_gpp_dir)
AC_SUBST(ac_cv_contest_fpc)
AC_SUBST(ac_cv_contest_fpc_dir)
AC_SUBST(ac_cv_contest_gpc)
AC_SUBST(ac_cv_contest_gpc_dir)
AC_SUBST(ac_cv_contest_dcc)
AC_SUBST(ac_cv_contest_dcc_dir)
AC_SUBST(ac_cv_contest_g77)
AC_SUBST(ac_cv_contest_g77_dir)
AC_SUBST(ac_cv_contest_gfortran)
AC_SUBST(ac_cv_contest_gfortran_dir)
AC_SUBST(ac_cv_contest_gcj)
AC_SUBST(ac_cv_contest_gcj_dir)
AC_SUBST(ac_cv_contest_gprolog)
AC_SUBST(ac_cv_contest_gprolog_dir)
AC_SUBST(ac_cv_contest_yabasic_path)
AC_SUBST(ac_cv_contest_mzscheme_path)
AC_SUBST(ac_cv_contest_perl_path)
AC_SUBST(ac_cv_contest_python_path)
AC_SUBST(ac_cv_festival_home)
AC_SUBST(ac_cv_contest_javac)
AC_SUBST(ac_cv_contest_java)
AC_SUBST(ac_cv_contest_java_dir)
AC_SUBST(ac_cv_contest_java_version)
AC_SUBST(ac_cv_contest_mcs)
AC_SUBST(ac_cv_contest_mono)
AC_SUBST(ac_cv_contest_mono_dir)
AC_SUBST(ac_cv_contest_mbas)
AC_SUBST(ac_cv_libcap_link)
AC_SUBST(ac_cv_ejudge_server_bin_path_m)

if [[ x"${ac_cv_nls}" = x1 -a x"${ac_cv_ejudge_arch}" != xwin32 ]]
then
  AC_DEFINE(CONF_HAS_LIBINTL,1)
fi

if [[ x"${ac_cv_has_libcap}" != x -a x"${ac_cv_ejudge_arch}" != xwin32 ]]
then
  AC_DEFINE(CONF_HAS_LIBCAP,1)
fi

if [[ x"${ac_cv_has_libcap}" != x -o x"${ac_cv_has_new_secure_exec}" != x ]]
then
  AC_DEFINE(CONF_HAS_SECURE_EXEC, 1)
fi

if [[ x"${ac_cv_has_mysql}" = x1 ]]
then
  AC_DEFINE(CONF_HAS_MYSQL,1)
fi

if [[ x"${ac_cv_ajax}" != xno -a x"${ac_cv_ajax}" != x ]]
then
  AC_DEFINE(CONF_ENABLE_AJAX,1)
fi

if [[ x"${ac_cv_has_libcap}" != x ]]
then
  AC_DEFINE(HAVE_CAP_SYS_OPERATIONS, 1)
fi

AC_DEFINE_UNQUOTED(CONF_STYLE_PREFIX, "${ac_cv_style_prefix}")

AC_DEFINE_UNQUOTED(CGI_PROG_SUFFIX,"$ac_cv_cgi_suffix")
if [[ x"${ac_cv_conf_dir}" != x ]]
then
  AC_DEFINE_UNQUOTED(EJUDGE_CONF_DIR,"${ac_cv_conf_dir}")
fi
if [[ x"${ac_cv_cgi_conf_dir}" != x ]]
then
  AC_DEFINE_UNQUOTED(CGI_DATA_PATH,"$ac_cv_cgi_conf_dir")
fi
if [[ x"${ac_cv_ejudge_xml}" != x ]]
then
  AC_DEFINE_UNQUOTED(EJUDGE_XML_PATH,"${ac_cv_ejudge_xml}")
fi
if [[ x"${ac_cv_contests_dir}" != x ]]
then
  AC_DEFINE_UNQUOTED(EJUDGE_CONTESTS_DIR,"${ac_cv_contests_dir}")
fi
if [[ x"${ac_cv_contests_home_dir}" != x ]]
then
  AC_DEFINE_UNQUOTED(EJUDGE_CONTESTS_HOME_DIR,"${ac_cv_contests_home_dir}")
fi
if [[ x"${ac_cv_local_dir}" != x ]]
then
  AC_DEFINE_UNQUOTED(EJUDGE_LOCAL_DIR,"${ac_cv_local_dir}")
fi
AC_DEFINE_UNQUOTED(EJUDGE_PREFIX_DIR,"${ac_cv_expanded_prefix}")
AC_DEFINE_UNQUOTED(EJUDGE_LOCALE_DIR,"$ac_cv_expanded_locale_dir")
AC_DEFINE_UNQUOTED(EJUDGE_SERVER_BIN_PATH,"${ac_cv_ejudge_server_bin_path}")
AC_DEFINE_UNQUOTED(EJUDGE_SERVE_PATH,"${ac_cv_ejudge_serve_path}")
AC_DEFINE_UNQUOTED(EJUDGE_RUN_PATH,"${ac_cv_ejudge_run_path}")
AC_DEFINE_UNQUOTED(EJUDGE_SCRIPT_DIR,"${ac_cv_ejudge_script_dir_expanded}")
AC_DEFINE_UNQUOTED(EJUDGE_CGI_BIN_DIR,"${ac_cv_ejudge_cgi_bin_dir}")
if [[ x"${ac_cv_charset}" != x ]]
then
  AC_DEFINE_UNQUOTED(EJUDGE_CHARSET,"${ac_cv_charset}")
fi
if [[ x"${ac_cv_socket_path}" != x ]]
then
  AC_DEFINE_UNQUOTED(EJUDGE_SOCKET_PATH,"${ac_cv_socket_path}")
fi
if [[ x"${ac_cv_super_serve_socket}" != x ]]
then
  AC_DEFINE_UNQUOTED(EJUDGE_SUPER_SERVE_SOCKET,"${ac_cv_super_serve_socket}")
fi
if [[ x"${ac_cv_new_server_socket}" != x ]]
then
  AC_DEFINE_UNQUOTED(EJUDGE_NEW_SERVER_SOCKET,"${ac_cv_new_server_socket}")
fi
if [[ x"${ac_cv_httpd_cgi_bin_dir}" != x ]]
then
  AC_DEFINE_UNQUOTED(EJUDGE_HTTPD_CGI_BIN_DIR,"${ac_cv_httpd_cgi_bin_dir}")
fi
if [[ x"${ac_cv_httpd_htdocs_dir}" != x ]]
then
  AC_DEFINE_UNQUOTED(EJUDGE_HTTPD_HTDOCS_DIR,"${ac_cv_httpd_htdocs_dir}")
fi

if [[ x"${ac_cv_gcc_version}" != x ]]
then
  AC_DEFINE_UNQUOTED(COMPILE_GCC_VERSION,"${ac_cv_gcc_version}")
fi
if [[ x"${ac_cv_gpp_version}" != x ]]
then
  AC_DEFINE_UNQUOTED(COMPILE_GPP_VERSION,"${ac_cv_gpp_version}")
fi
if [[ x"${ac_cv_fpc_version}" != x ]]
then
  AC_DEFINE_UNQUOTED(COMPILE_FPC_VERSION,"${ac_cv_fpc_version}")
fi
if [[ x"${ac_cv_gpc_version}" != x ]]
then
  AC_DEFINE_UNQUOTED(COMPILE_GPC_VERSION,"${ac_cv_gpc_version}")
fi
if [[ x"${ac_cv_dcc_version}" != x ]]
then
  AC_DEFINE_UNQUOTED(COMPILE_DCC_VERSION,"${ac_cv_dcc_version}")
fi
if [[ x"${ac_cv_g77_version}" != x ]]
then
  AC_DEFINE_UNQUOTED(COMPILE_G77_VERSION,"${ac_cv_g77_version}")
fi
if [[ x"${ac_cv_gfortran_version}" != x ]]
then
  AC_DEFINE_UNQUOTED(COMPILE_GFORTRAN_VERSION,"${ac_cv_gfortran_version}")
fi
if [[ x"${ac_cv_gcj_version}" != x ]]
then
  AC_DEFINE_UNQUOTED(COMPILE_GCJ_VERSION,"${ac_cv_gcj_version}")
fi
if [[ x"${ac_cv_gprolog_version}" != x ]]
then
  AC_DEFINE_UNQUOTED(COMPILE_GPROLOG_VERSION,"${ac_cv_gprolog_version}")
fi
if [[ x"${ac_cv_yabasic_version}" != x ]]
then
  AC_DEFINE_UNQUOTED(COMPILE_YABASIC_VERSION,"${ac_cv_yabasic_version}")
fi
if [[ x"${ac_cv_mzscheme_version}" != x ]]
then
  AC_DEFINE_UNQUOTED(COMPILE_MZSCHEME_VERSION,"${ac_cv_mzscheme_version}")
fi
if [[ x"${ac_cv_perl_version}" != x ]]
then
  AC_DEFINE_UNQUOTED(COMPILE_PERL_VERSION,"${ac_cv_perl_version}")
fi
if [[ x"${ac_cv_python_version}" != x ]]
then
  AC_DEFINE_UNQUOTED(COMPILE_PYTHON_VERSION,"${ac_cv_python_version}")
fi
if [[ x"${ac_cv_contest_java_version_string}" != x ]]
then
  AC_DEFINE_UNQUOTED(COMPILE_JAVA_VERSION,"${ac_cv_contest_java_version_string}")
fi
if [[ x"${ac_cv_contest_mono_version_string}" != x ]]
then
  AC_DEFINE_UNQUOTED(COMPILE_MONO_VERSION,"${ac_cv_contest_mono_version_string}")
fi
if [[ x"${ac_cv_contest_mbas_version_string}" != x ]]
then
  AC_DEFINE_UNQUOTED(COMPILE_MBAS_VERSION,"${ac_cv_contest_mbas_version_string}")
fi

AC_CONFIG_HEADERS([config.h])
AC_OUTPUT(Makefile extra/Makefile extra/captest/Makefile checkers/Makefile scripts/Makefile scripts/gcc scripts/gcc-version scripts/g++ scripts/g++-version scripts/fpc scripts/fpc-version scripts/gpc scripts/gpc-version scripts/dcc scripts/dcc-version scripts/g77 scripts/g77-version scripts/gfortran scripts/gfortran-version scripts/gcj scripts/gcj-version scripts/gprolog scripts/gprolog-version scripts/yabasic scripts/yabasic-version scripts/mzscheme scripts/mzscheme-version scripts/perl scripts/perl-version scripts/python scripts/python-version scripts/txt scripts/txt-version ejudge-config.v scripts/festival scripts/javac scripts/javac-version scripts/runjava scripts/mcs scripts/mcs-version scripts/runmono scripts/mbas scripts/mbas-version scripts/runperl plugins/mysql-userlist/Makefile python/Makefile)

chmod +x scripts/gcc scripts/gcc-version scripts/g++ scripts/g++-version scripts/fpc scripts/fpc-version scripts/gpc scripts/gpc-version scripts/dcc scripts/dcc-version scripts/g77 scripts/g77-version scripts/gfortran scripts/gfortran-version scripts/gcj scripts/gcj-version scripts/gprolog scripts/gprolog-version scripts/yabasic scripts/yabasic-version scripts/mzscheme scripts/mzscheme-version scripts/perl scripts/perl-version scripts/python scripts/python-version scripts/txt scripts/txt-version ejudge-config.v scripts/festival scripts/javac scripts/javac-version scripts/runjava scripts/mcs scripts/mcs-version scripts/runmono scripts/mbas scripts/mbas-version scripts/runperl

if [[ "x${ac_cv_has_libcap}" = x -a "${ac_cv_has_new_secure_exec}" = x ]]
then
  echo
  echo "WARNING:"
  echo "The configure script did not detect neither libcap library"
  echo "supporting the kernel CAP_SYS_OPERATIONS capability bit,"
  echo "nor the new style secure execution support in the running kernel"
  echo "provided by the patch -cher1 for kernel starting from"
  echo "version 2.6.18 onward."
  echo "However, all the tools necessary for secure executions are"
  echo "configured and will be compiled, and if you install the kernel"
  echo "patch secure execution and the related features (memory limit"
  echo "error detection and millisecond time-limit precision will be supported."
fi

if [[ "x${ac_cv_has_libcap}" = x1 -a "x${ac_cv_has_runtime_libcap}" != x1 -a x"${ac_cv_has_new_secure_exec}" = x ]]
then
  echo
  echo "WARNING:"
  echo "The configure script detected, that the libcap library"
  echo "supports the kernel CAP_SYS_OPERATIONS capability bit,"
  echo "but the current running Linux kernel does not. However, the"
  echo "configuration files, which will be generated by ejudge-setup"
  echo "utility will include support for the patched kernel, and"
  echo "may result in inability of proper testing of programs by"
  echo "the run program."
fi
