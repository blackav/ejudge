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
AC_ARG_ENABLE([preserve-scripts],AC_HELP_STRING([--enable-preserve-scripts],[do not overwrite the existing language scripts]), [ac_cv_preserve_scripts=1],[ac_cv_preserve_scripts=])
AC_ARG_ENABLE([lang-config-dir],AC_HELP_STRING([--enable-lang-config-dir],[install language config scripts into specified directory]),[ac_cv_lang_config_dir="${enableval}"],[ac_cv_lang_config_dir=])

AC_ARG_WITH([httpd-cgi-bin-dir],AC_HELP_STRING([--with-httpd-cgi-bin-dir],[specify the path to the web serve CGI directory]),[ac_cv_httpd_cgi_bin_dir="${withval}"])
AC_ARG_WITH([httpd-htdocs-dir],AC_HELP_STRING([--with-httpd-htdocs-dir],[specify the path to the web server HTML directory]),[ac_cv_httpd_htdocs_dir="${withval}"])

AC_ARG_WITH([gcc],AC_HELP_STRING([--with-gcc],[specify the GNU C compiler to use in contests]),[ac_cv_contest_gcc="$withval"])
AC_ARG_WITH([gpp],AC_HELP_STRING([--with-gpp],[specify the GNU C++ compiler to use in contests]),[ac_cv_contest_gpp="$withval"])
AC_ARG_WITH([fpc],AC_HELP_STRING([--with-fpc],[specify the Free Pascal compiler to use in contests]),[ac_cv_contest_fpc="$withval"])
AC_ARG_WITH([gpc],AC_HELP_STRING([--with-gpc],[specify the GNU Pascal compiler to use in contests]),[ac_cv_contest_gpc="$withval"])
AC_ARG_WITH([gcj],AC_HELP_STRING([--with-gcj],[specify the GNU Java (GCJ) compiler to use in contests]),[ac_cv_contest_gcj="$withval"])
AC_ARG_WITH([g77],AC_HELP_STRING([--with-g77],[specify the GNU Fortran 77 compiler to use in contests]),[ac_cv_contest_g77="$withval"])
AC_ARG_WITH([gfortran],AC_HELP_STRING([--with-gfortran],[specify the GNU Fortran 90 compiler to use in contests]),[ac_cv_contest_gfortran="$withval"])
AC_ARG_WITH([dcc],AC_HELP_STRING([--with-dcc],[specify the Borland Delphi compiler to use in contests]),[ac_cv_contest_dcc="$withval"])
AC_ARG_WITH([yabasic],AC_HELP_STRING([--with-yabasic],[specify the Yabasic interpreter to use in contests]),[ac_cv_contest_yabasic="$withval"])
AC_ARG_WITH([scheme],AC_HELP_STRING([--with-scheme],[specify the MzScheme interpreter to use in contests]),[ac_cv_contest_mzscheme="$withval"])
AC_ARG_WITH([python],AC_HELP_STRING([--with-python],[specify the Python interpreter to use in contests]),[ac_cv_contest_python="$withval"])
AC_ARG_WITH([perl],AC_HELP_STRING([--with-perl],[specify the Perl interpreter to use in contests]),[ac_cv_contest_perl="$withval"])
AC_ARG_WITH([prolog],AC_HELP_STRING([--with-prolog],[specify the GNU Prolog compiler to use in contests]),[ac_cv_contest_gprolog="$withval"])
AC_ARG_WITH([festival],AC_HELP_STRING([--with-festival],[specify the home directory of the festival speech generator]),[ac_cv_festival_home="$withval"])
AC_ARG_WITH([javac],AC_HELP_STRING([--with-javac],[specify the Java2 SDK javac path to use in contests]),[ac_cv_contest_javac="$withval"])
AC_ARG_WITH([mcs],AC_HELP_STRING([--with-mcs],[specify the C-sharp Mono mcs/gmcs path to use in contests]),[ac_cv_contest_mcs="$withval"])
AC_ARG_WITH([vbnc],AC_HELP_STRING([--with-vbnc],[specify the Visual Basic Mono vbnc path to use in contests]),[ac_cv_contest_vbnc="$withval"])

if [[ x"${ac_cv_contest_gcc}${ac_cv_contest_gpp}${ac_cv_contest_fpc}${ac_cv_contest_gpc}${ac_cv_contest_gcj}${ac_cv_contest_g77}${ac_cv_contest_gfortran}${ac_cv_contest_dcc}${ac_cv_contest_yabasic}${ac_cv_contest_mzscheme}${ac_cv_contest_python}${ac_cv_contest_perl}${ac_cv_contest_gprolog}${ac_cv_contest_javac}${ac_cv_contest_mcs}${ac_cv_contest_vbnc}" != x ]]
then
  cat <<EOF

ERROR:
The configure script now does not configure programming language
compilers. Options like --with-gcc are no longer supported.
To configure programming language compilers please use ejudge-setup
or ejudge-configure-compilers programs.
EOF
  exit 1
fi

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
[[ x"${ac_cv_lang_config_dir}" = x -o x"${ac_cv_lang_config_dir}" = xyes ]] && ac_cv_lang_config_dir="${ac_cv_contests_home_dir}/compile/conf/lang.d"

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
dnl AC_MSG_NOTICE([checking available languages])

dnl Iterate over version scripts in scripts directory
dnl ac_cv_contest_LANG is passed as arg
dnl [[ -d scripts/config.d ]] || mkdir scripts/config.d
dnl for i in scripts/*-version.in
dnl do
dnl   j=`basename ${i/-version.in/}`
dnl   langname="$j"
dnl   [[ "${langname}" = "g++" ]] && langname=gpp
dnl   varname="ac_cv_contest_${langname}"
dnl   eval optval='$'${varname}
dnl   [[ "${optval}" = "yes" ]] && optval=""
dnl   [[ "${optval}" = "no" ]] && optval="/bin/false"
dnl   if [[ "${optval}" != "" ]]
dnl   then
dnl     "./$i" -v -r "${optval}" 2>&1 >scripts/config.d/$j.cfg
dnl   else
dnl     "./$i" -v -r 2>&1 >scripts/config.d/$j.cfg
dnl   fi
dnl done

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
if [[ x"${ac_cv_lang_config_dir}" = x'${libexecdir}/ejudge/lang/config.d' ]]
then
  ac_cv_lang_config_dir_expanded="${actual_libexecdir}/ejudge/lang/config.d"
else
  ac_cv_lang_config_dir_expanded="${ac_cv_lang_config_dir}"
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
AC_SUBST(ac_cv_preserve_scripts)

AC_SUBST(ac_cv_festival_home)
AC_SUBST(ac_cv_libcap_link)
AC_SUBST(ac_cv_ejudge_server_bin_path_m)
AC_SUBST(ac_cv_lang_config_dir)
AC_SUBST(ac_cv_lang_config_dir_expanded)

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
AC_DEFINE_UNQUOTED(EJUDGE_LIBEXEC_DIR,"${actual_libexecdir}")
AC_DEFINE_UNQUOTED(EJUDGE_LOCALE_DIR,"$ac_cv_expanded_locale_dir")
AC_DEFINE_UNQUOTED(EJUDGE_SERVER_BIN_PATH,"${ac_cv_ejudge_server_bin_path}")
AC_DEFINE_UNQUOTED(EJUDGE_SERVE_PATH,"${ac_cv_ejudge_serve_path}")
AC_DEFINE_UNQUOTED(EJUDGE_RUN_PATH,"${ac_cv_ejudge_run_path}")
AC_DEFINE_UNQUOTED(EJUDGE_SCRIPT_DIR,"${ac_cv_ejudge_script_dir_expanded}")
AC_DEFINE_UNQUOTED(EJUDGE_CGI_BIN_DIR,"${ac_cv_ejudge_cgi_bin_dir}")
AC_DEFINE_UNQUOTED(EJUDGE_LANG_CONFIG_DIR,"${ac_cv_lang_config_dir_expanded}")
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

AC_CONFIG_HEADERS([config.h])
AC_OUTPUT(Makefile extra/Makefile extra/captest/Makefile checkers/Makefile scripts/Makefile ejudge-config.v scripts/festival plugins/mysql-userlist/Makefile python/Makefile)

chmod +x ejudge-config.v scripts/festival

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
