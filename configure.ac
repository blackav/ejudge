dnl Copyright (C) 2004-2024 Alexander Chernov <cher@ejudge.ru>

AC_INIT([ejudge],[3])
AC_PREREQ([2.71])
AC_REVISION($Revision$)

AC_PREFIX_DEFAULT([/opt/ejudge])
AC_USE_SYSTEM_EXTENSIONS
AC_PROG_INSTALL
AC_PROG_AWK
AC_PROG_GREP
AC_PROG_SED
AC_PROG_LN_S
AC_PROG_MKDIR_P
AC_PROG_YACC
AC_PROG_LEX(noyywrap)

if ! which which > /dev/null 2>/dev/null
then
  echo "'which' program is not found, please install it." >&2
  echo "The package is probably called 'which'." >&2
  exit 1
fi

for tool in gawk grep sed make rm cp ln ar cat chmod mkdir tar gzip bzip2
do
  if ! which "$tool" >/dev/null 2>/dev/null
  then
    echo "'$tool' program is not found. Please, install it." >&2
    exit 1
  fi
done

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
AC_TYPE_LONG_DOUBLE
AC_C_STRINGIZE
AC_C_PROTOTYPES

AC_ARG_WITH([lib32dir], AS_HELP_STRING([--with-lib32dir=DIR],[specify directory for 32-bit libraries]),[lib32dir=$withval])

AC_ARG_WITH([libcap], AS_HELP_STRING([--with-libcap=LIBCAP-DIR],[use the linux capability library]),[ac_cv_libcap_root=$withval])
AC_ARG_WITH([libcap-include-dir], AS_HELP_STRING([--with-libcap-include-dir],[specify non-standard location of <sys/capability.h> [[LIBCAP-DIR/include]]]),[ac_cv_libcap_include_dir=$withval])
AC_ARG_WITH([libcap-lib-dir], AS_HELP_STRING([--with-libcap-lib-dir],[specify non-standard location for -lcap [[LIBCAP-DIR/lib]]]), [ac_cv_libcap_lib_dir=$withval])

AC_ARG_WITH([expat], AS_HELP_STRING([--with-expat=EXPAT-DIR],[specify non-standard path to expat library]),[ac_cv_expat_root=$withval])
AC_ARG_WITH([expat-include-dir],AS_HELP_STRING([--with-expat-include-dir],[specify non-standard location of <expat.h> [[EXPAT-DIR/include]]]),[ac_cv_expat_include_dir=$withval])
AC_ARG_WITH([expat-lib-dir],AS_HELP_STRING([--with-expat-lib-dir],[specify non-standard location of -lexpat [[EXPAT-DIR/lib]]]),[ac_cv_expat_lib_dir=$withval])

AC_ARG_WITH([mysql], AS_HELP_STRING([--with-mysql=MYSQL-DIR],[specify the path to the mysql installation directory]),[ac_cv_mysql_root="$withval"])

AC_ARG_ENABLE([cgi-suffix], AS_HELP_STRING([--enable-cgi-suffix],[append the given suffix to the CGI programs]),[ac_cv_cgi_suffix=$enableval],[ac_cv_cgi_suffix=""])
AC_ARG_ENABLE([cgi-bin-dir], AS_HELP_STRING([--enable-cgi-bin-dir],[specify the destination CGI script directory [[\${prefix}/libexec/ejudge/cgi-bin]]]),[cgibindir=$enableval], [cgibindir='${libexecdir}/ejudge/cgi-bin'])
AC_ARG_ENABLE([static], AS_HELP_STRING([--enable-static],[link programs statically]),[ac_cv_static=1],[ac_cv_static=""])
AC_ARG_ENABLE([rpath], AS_HELP_STRING([--disable-rpath],[do not use -rpath feature]),[ac_cv_rpath="$enableval"])
AC_ARG_ENABLE([nls], AS_HELP_STRING([--disable-nls],[disable localization]),[ac_cv_nls=$enableval],[ac_cv_nls=""])
AC_ARG_ENABLE([charset],AS_HELP_STRING([--enable-charset],[specify the default charset]),[ac_cv_charset="$enableval"],[ac_cv_charset=""])
AC_ARG_ENABLE([socket-path],AS_HELP_STRING([--enable-socket-path],[specify the default userlist-server socket path]),[ac_cv_socket_path="$enableval"],[ac_cv_socket_path=""])
AC_ARG_ENABLE([super-serve-socket],AS_HELP_STRING([--enable-super-serve-socket],[specify the default super-serve socket path]),[ac_cv_super_serve_socket="$enableval"],[ac_cv_super_serve_socket=""])
AC_ARG_ENABLE([new-server-socket],AS_HELP_STRING([--enable-new-server-socket],[specify the default new-server socket path]),[ac_cv_new_server_socket="$enableval"],[ac_cv_new_server_socket=""])
AC_ARG_ENABLE([conf-dir], AS_HELP_STRING([--enable-conf-dir=CONF-DIR],[specify the ejudge configuration directory]),[ac_cv_conf_dir="$enableval"],[ac_cv_conf_dir=""])
AC_ARG_ENABLE([cgi-conf-dir], AS_HELP_STRING([--enable-cgi-conf-dir],[specify path to CGI configuration files]),[ac_cv_cgi_conf_dir="$enableval"],[ac_cv_cgi_conf_dir=""])
AC_ARG_ENABLE([ejudge-xml],AS_HELP_STRING([--enable-ejudge-xml],[specify the default location of ejudge.xml]),[ac_cv_ejudge_xml="$enableval"],[ac_cv_ejudge_xml=""])
AC_ARG_ENABLE([contests-dir],AS_HELP_STRING([--enable-contests-dir],[specify the default path to the contest configuration directory]),[ac_cv_contests_dir="$enableval"],[ac_cv_contests_dir=""])
AC_ARG_ENABLE([contests-home-dir],AS_HELP_STRING([--enable-contests-home-dir],[specify the default path to the contests home directory]),[ac_cv_contests_home_dir="$enableval"],[ac_cv_contests_home_dir=""])
AC_ARG_ENABLE([compile-spool-dir],AS_HELP_STRING([--enable-compile-spool-dir],[specify the path to the compile spool directory]),[ac_cv_compile_spool_dir="$enableval"],[ac_cv_compile_spool_dir=""])
AC_ARG_ENABLE([run-spool-dir],AS_HELP_STRING([--enable-run-spool-dir],[specify the path to the run spool directory]),[ac_cv_run_spool_dir="$enableval"],[ac_cv_run_spool_dir=""])
AC_ARG_ENABLE([contests-status-dir],AS_HELP_STRING([--enable-contests-status-dir],[specify the path to the contest status directory]),[ac_cv_contests_status_dir="$enableval"],[ac_cv_contests_status_dir=""])
AC_ARG_ENABLE([local-dir],AS_HELP_STRING([--enable-local-dir],[specify the default path to the local state directory]),[ac_cv_local_dir="$enableval"],[ac_cv_local_dir=""])
AC_ARG_ENABLE([ajax],AS_HELP_STRING([--enable-ajax],[enable use of the ajax technology for the client web interface]),[ac_cv_ajax="$enableval"],[ac_cv_ajax=""])
AC_ARG_ENABLE([style-prefix],AS_HELP_STRING([--enable-style-prefix],[specify the prefix for HTML style files]),[ac_cv_style_prefix="$enableval"],[ac_cv_style_prefix=""])
AC_ARG_ENABLE([hidden-server-bins],AS_HELP_STRING([--enable-hidden-server-bins],[do not install the server binaries into bin directory]),[ac_cv_hidden_bins=1],[ac_cv_hidden_bins=])
AC_ARG_ENABLE([werror],AS_HELP_STRING([--enable-werror],[enable -Werror compilation flag]),[ac_cv_werror_flag=-Werror],[ac_cv_werror_flag=])
AC_ARG_ENABLE([preserve-scripts],AS_HELP_STRING([--enable-preserve-scripts],[do not overwrite the existing language scripts]), [ac_cv_preserve_scripts=1],[ac_cv_preserve_scripts=])
AC_ARG_ENABLE([lang-config-dir],AS_HELP_STRING([--enable-lang-config-dir],[install language config scripts into specified directory]),[ac_cv_lang_config_dir="${enableval}"],[ac_cv_lang_config_dir=])

AC_ARG_ENABLE([libmongoc],AS_HELP_STRING([--enable-libmongoc],[enable libmongoc mongo client library]),[ac_cv_enable_libmongoc="${enableval}"],[ac_cv_enable_libmongoc=])

AC_ARG_WITH([rest],AS_HELP_STRING([--with-rest],[enable RESTful API]),[ac_cv_rest="$withval"])

AC_ARG_WITH([primary-user],AS_HELP_STRING([--with-primary-user],[primary ejudge user]),[ac_cv_primary_user="$withval"])
AC_ARG_WITH([exec-user],AS_HELP_STRING([--with-exec-user],[ejudge executer user]),[ac_cv_exec_user="$withval"])
AC_ARG_WITH([compile-user],AS_HELP_STRING([--with-compile-user],[ejudge compiler user]),[ac_cv_compile_user="$withval"])

AC_ARG_WITH([httpd-cgi-bin-dir],AS_HELP_STRING([--with-httpd-cgi-bin-dir],[specify the path to the web serve CGI directory]),[ac_cv_httpd_cgi_bin_dir="${withval}"])
AC_ARG_WITH([httpd-htdocs-dir],AS_HELP_STRING([--with-httpd-htdocs-dir],[specify the path to the web server HTML directory]),[ac_cv_httpd_htdocs_dir="${withval}"])

AC_ARG_WITH([festival],AS_HELP_STRING([--with-festival],[specify the home directory of the festival speech generator]),[ac_cv_festival_home="$withval"])

dnl setup default values
[[ x"${ac_cv_contests_home_dir}" = x -o x"${ac_cv_contests_home_dir}" = xyes ]] && ac_cv_contests_home_dir="/home/judges"

[[ x"${ac_cv_local_dir}" = xyes ]] && ac_cv_local_dir="/var/lib/ejudge"
if [[ x"${ac_cv_local_dir}" != x ]]
then
  [[ x"${ac_cv_socket_path}" = x -o x"${ac_cv_socket_path}" = xyes ]] && ac_cv_socket_path="${ac_cv_local_dir}/sockets/userlist"
  [[ x"${ac_cv_super_serve_socket}" = x -o x"${ac_cv_super_serve_socket}" = xyes ]] && ac_cv_super_serve_socket="${ac_cv_local_dir}/sockets/super-serve"
  [[ x"${ac_cv_new_server_socket}" = x -o x"${ac_cv_new_server_socket}" = xyes ]] && ac_cv_new_server_socket="${ac_cv_local_dir}/sockets/new-server"
else
  [[ x"${ac_cv_socket_path}" = x -o x"${ac_cv_socket_path}" = xyes ]] && ac_cv_socket_path="${ac_cv_contests_home_dir}/var/socket/userlist-socket"
  [[ x"${ac_cv_super_serve_socket}" = x -o x"${ac_cv_super_serve_socket}" = xyes ]] && ac_cv_super_serve_socket="${ac_cv_contests_home_dir}/var/socket/super-serve-socket"
  [[ x"${ac_cv_new_server_socket}" = x -o x"${ac_cv_new_server_socket}" = xyes ]] && ac_cv_new_server_socket="${ac_cv_contests_home_dir}/var/socket/new-server-socket"
fi

[[ x"${ac_cv_conf_dir}" = x -o x"${ac_cv_conf_dir}" = xyes ]] && ac_cv_conf_dir="${ac_cv_contests_home_dir}/data"
[[ x"${ac_cv_cgi_conf_dir}" = x -o x"${ac_cv_cgi_conf_dir}" = xyes ]] && ac_cv_cgi_conf_dir="../cgi-data"
[[ x"${ac_cv_style_prefix}" = x -o x"${ac_cv_style_prefix}" = xyes ]] && ac_cv_style_prefix="/ejudge/"
[[ x"${ac_cv_lang_config_dir}" = x -o x"${ac_cv_lang_config_dir}" = xyes ]] && ac_cv_lang_config_dir="${ac_cv_contests_home_dir}/compile/conf/lang.d"
[[ x"${ac_cv_compile_spool_dir}" = xyes ]] && ac_cv_compile_spool_dir=`dirname "${ac_cv_contests_home_dir}"`/ej-compile-spool
[[ x"${ac_cv_run_spool_dir}" = xyes ]] && ac_cv_run_spool_dir=`dirname "${ac_cv_contests_home_dir}"`/ej-run-spool
if [[ x"${ac_cv_contests_status_dir}" = xyes ]]
then
  if [[ x"${ac_cv_local_dir}" != x ]]
  then
    ac_cv_contests_status_dir="${ac_cv_local_dir}"/status
  else
    ac_cv_contests_status_dir=`dirname "${ac_cv_contests_home_dir}"`/ej-status
  fi
fi

machine=`uname -m`

case "${machine}" in
  x86_64)
    if [[ x"${libdir}" = x'${exec_prefix}/lib' ]]
    then
      libdir='${exec_prefix}/lib64'
    fi
    if [[ x"${lib32dir}" = x ]]
    then
      lib32dir='${exec_prefix}/lib'
    fi
    ac_cv_conf_64_bit=1
    ;;
esac

dnl choose an arch type
AC_MSG_CHECKING([for arch type])
case "${target}" in
  *-*-mingw*)
    ac_cv_ejudge_arch=win32
    ac_cv_exe_suffix=.exe
    ac_cv_conf_dos_filenaming=1
    ac_cv_dir_separator='\\'
    ac_cv_path_separator=';'
    #CFLAGS="${CFLAGS} -mno-cygwin"
    #LDFLAGS="${LDFLAGS} -mno-cygwin"
    AC_MSG_RESULT([win32])
    ;;
  *)
    ac_cv_ejudge_arch=unix
    ac_cv_exe_suffix=
    ac_cv_conf_unix_filenaming=1
    ac_cv_dir_separator='/'
    ac_cv_path_separator=':'
    AC_MSG_RESULT([unix])
    ;;
esac

if [[ x"${ac_cv_ejudge_arch}" != xwin32 ]]
then
AC_CHECK_HEADERS([termios.h])
fi

AC_CHECK_HEADERS([iconv.h pwd.h])

AC_CHECK_FUNCS([strnlen open_memstream fmemopen truncate setsid pselect ferror_unlocked fgets_unlocked])

AC_CHECK_LIB([iconv],[iconv],[ac_cv_has_lib_iconv=-liconv],[ac_cv_has_lib_iconv=])

AC_CHECK_LIB([iconv],[libiconv],[ac_cv_has_lib_libiconv=-liconv],[ac_cv_has_lib_libiconv=])

saved_CFLAGS="${CFLAGS}"
saved_LIBS="${LIBS}"
CFLAGS="${CFLAGS} -Werror -Wall"
LIBS=" ${ac_cv_has_lib_libiconv} ${ac_cv_has_lib_iconv}"
AC_MSG_CHECKING([that iconv requires const qualifier])
AC_RUN_IFELSE(
[AC_LANG_SOURCE([[
#include <iconv.h>
#include <stdio.h>
int main(void)
{
  iconv_t cvt = iconv_open("iso8859-1", "utf-8");
  const char str1[] = "123";
  char str2[16];
  size_t sz1 = 3, sz2 = 16, sz3;
  const char *p1 = str1;
  char *p2 = str2;
  sz3 = iconv(cvt, &p1, &sz1, &p2, &sz2);
  return 0;
}
]])],[
AC_MSG_RESULT([yes])
ac_cv_iconv_needs_const=1
],[
AC_MSG_RESULT([no])
ac_cv_iconv_needs_const=""
])
LIBS="${saved_LIBS}"
CFLAGS="${saved_CFLAGS}"

ac_cv_have_so_passcred=
AC_MSG_CHECKING([SO_PASSCRED flag])
AC_RUN_IFELSE([AC_LANG_SOURCE([[
#include <sys/types.h>
#include <sys/socket.h>
int main()
{
  int val = 1;
  setsockopt(0, SOL_SOCKET, SO_PASSCRED, &val, sizeof(val));
  return 0;
}
]])],[
AC_MSG_RESULT([yes])
ac_cv_have_so_passcred=1
],[
AC_MSG_RESULT([no])
])

ac_cv_have_siocing=
AC_MSG_CHECKING([SIOCINQ flag])
AC_RUN_IFELSE([AC_LANG_SOURCE([[
#include <sys/ioctl.h>
#include <linux/sockios.h>
int main()
{
  int sz = 0;

  ioctl(0, SIOCINQ, &sz);
  return 0;
}
]])],[
AC_MSG_RESULT([yes])
ac_cv_have_siocing=1
],[
AC_MSG_RESULT([no])
])

ac_cv_have_f_notify=
AC_MSG_CHECKING([F_NOTIFY flag])
AC_RUN_IFELSE([AC_LANG_SOURCE([[
#define _GNU_SOURCE
#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/wait.h>
#include <time.h>
int main()
{
  fcntl(0, F_SETSIG, SIGRTMIN);
  fcntl(0, F_NOTIFY, DN_CREATE | DN_DELETE | DN_RENAME | DN_MULTISHOT);
  return 0;
}
]])],[
AC_MSG_RESULT([yes])
ac_cv_have_f_notify=1
],[
AC_MSG_RESULT([no])
])

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
[AC_LANG_SOURCE([[
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
]])],[
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
[AC_LANG_SOURCE([[
#include <zlib.h>
#include <stdio.h>
int main(void)
{
  if (ZLIB_VERNUM >= 0x1200) return 0;
  return 1;
}
]])],[
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

AC_CHECK_LIB([intl],[gettext],[ac_cv_has_lib_intl=-lintl],[ac_cv_has_lib_intl=])

dnl check ncurses library
AC_CHECK_HEADER([ncurses.h],[ac_cv_has_ncurses=1],[ac_cv_has_ncurses=0])
#if [[ x"${ac_cv_has_ncurses}" != x1 ]]
#then
#  AC_MSG_FAILURE([ncurses.h is missing, please install ncurses development package])
#fi

dnl check for menu.h
AC_CHECK_HEADER([menu.h],[ac_cv_ncurses_menu=1],[ac_cv_ncurses_menu=0])

dnl check for ncurses/menu.h
AC_CHECK_HEADER([ncurses/menu.h],[ac_cv_ncurses_ncurses_menu=1],[ac_cv_ncurses_ncurses_menu=0])

if [[ "$ac_cv_ncurses_menu" = "0" -a "$ac_cv_ncurses_ncurses_menu" = "1" ]]
then
  ac_cv_ncurses_include=" -I/usr/include/ncurses"
fi

dnl check zlib library
AC_CHECK_HEADER([zip.h],[ac_cv_has_libzip=1],[ac_cv_has_libzip=0])
AC_CHECK_LIB([zip],[zip_open],[ac_cv_has_lib_libzip=-lzip],[ac_cv_has_lib_libzip=])

AC_CHECK_HEADER([lzma.h],[ac_cv_has_liblzma=1],[ac_cv_has_liblzma=0])
AC_CHECK_LIB([lzma],[lzma_version_string],[ac_cv_has_lib_liblzma=-llzma],[ac_cv_has_lib_liblzma=])

dnl check hiredis redis client library
AC_CHECK_HEADER([hiredis/hiredis.h],[ac_cv_has_hiredis=1],[ac_cv_has_hiredis=0])
AC_CHECK_LIB([hiredis],[redisConnectWithTimeout],[ac_cv_has_lib_hiredis=-lhiredis],[ac_cv_has_lib_hiredis=])

dnl check libcurl library
AC_CHECK_HEADER([curl/curl.h],[ac_cv_has_libcurl=1],[ac_cv_has_libcurl=0])
AC_CHECK_LIB([curl],[curl_easy_init],[ac_cv_has_lib_libcurl=-lcurl],[ac_cv_has_lib_libcurl=])

dnl check libuuid library
AC_CHECK_HEADER([uuid/uuid.h],[ac_cv_has_libuuid=1],[ac_cv_has_libuuid=0])
if [[ x"${ac_cv_has_libuuid}" != x1 -a x"${ac_cv_ejudge_arch}" != xwin32 ]]
then
  AC_MSG_FAILURE([please install libuuid development package])
fi
AC_CHECK_LIB([uuid],[uuid_parse],[ac_cv_has_lib_libuuid=-luuid],[ac_cv_has_lib_libuuid=])
if [[ x"${ac_cv_has_libuuid}" != x1 -a x"${ac_cv_ejudge_arch}" != xwin32 ]]
then
  AC_MSG_FAILURE([please install libuuid development package])
fi

dnl check regex library
AC_CHECK_HEADER([regex.h],[ac_cv_has_regex=1],[ac_cv_has_regex=0])

dnl check libelf library
AC_CHECK_HEADER([libelf.h],[ac_cv_has_libelf=1],[ac_cv_has_libelf=0])
if [[ x"${ac_cv_has_libelf}" != x1 -a x"${ac_cv_ejudge_arch}" != xwin32 ]]
then
  AC_MSG_FAILURE([please install libelf development package])
fi
AC_CHECK_LIB([elf],[elf_begin],[ac_cv_has_libelf=1],[ac_cv_has_libelf=0])
if [[ x"${ac_cv_has_libelf}" != x1 -a x"${ac_cv_ejudge_arch}" != xwin32 ]]
then
  AC_MSG_FAILURE([please install libelf development package])
fi

dnl checl libdwarf library
dnl saved_LIBS="${LIBS}"
dnl LIBS="-lelf"
dnl AC_CHECK_HEADER([libdwarf/libdwarf.h],[ac_cv_has_libdwarf=1],[ac_cv_has_libdwarf=0])
dnl if [[ x"${ac_cv_has_libdwarf}" != x1 -a x"${ac_cv_ejudge_arch}" != xwin32 ]]
dnl then
dnl   AC_MSG_FAILURE([please install libdwarf development package])
dnl fi
dnl AC_CHECK_LIB([dwarf],[dwarf_init],[ac_cv_has_libdwarf=1],[ac_cv_has_libdwarf=0])
dnl if [[ x"${ac_cv_has_libdwarf}" != x1 -a x"${ac_cv_ejudge_arch}" != xwin32 ]]
dnl then
dnl   AC_MSG_FAILURE([please install libdwarf development package])
dnl fi
dnl LIBS="${saved_LIBS}"

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
[AC_LANG_SOURCE([[
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
]])],
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
[AC_LANG_SOURCE([[
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
]])],
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
[AC_LANG_SOURCE([[
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
]])],
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
          ac_cv_mysql_lib_opt="${ac_cv_mysql_lib_opt}${xx}"
          if [[ x"${ac_cv_rpath}" != xno ]]
          then
            tmp_rpath=`echo "$xx" | sed s+-L+-Wl,-rpath,+`
            ac_cv_mysql_lib_opt="${ac_cv_mysql_lib_opt} ${tmp_rpath}"
          fi
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
saved_CFLAGS="${CFLAGS}"
AC_MSG_CHECKING([for -Wno-pointer-sign necessity])
CC="${CC} -Wall -Werror"
AC_COMPILE_IFELSE([AC_LANG_SOURCE([[
#include <string.h>
#include <stdio.h>
int main(void)
{
  unsigned char *str = "zzz";
  int v = strlen(str);
  printf("%d\n", v);
  return 0;
}
]])],[
AC_MSG_RESULT([no])
],[
AC_MSG_RESULT([yes])
ac_cv_annoying_warning=1
])
if [[ x"${ac_cv_annoying_warning}" = x1 ]]
then
  AC_MSG_CHECKING([for -Wno-pointer-sign])
  CC="${saved_CC} -Wno-pointer-sign -Werror"
  CFLAGS=
  AC_COMPILE_IFELSE([AC_LANG_SOURCE([[
int main(void)
{
  unsigned char *str = "zzz";
  (void) str;
  return 0;
}
]])],[
AC_MSG_RESULT([yes])
ac_cv_gcc_wno_pointer_sign=-Wno-pointer-sign
],[
AC_MSG_RESULT([no])
])
fi
CC="${saved_CC}"
CFLAGS="${saved_CFLAGS}"

saved_CC="${CC}"
saved_CFLAGS="${CFLAGS}"
AC_MSG_CHECKING([for -Wno-format-truncation necessity])
CC="${CC} -Wall -Werror"
AC_COMPILE_IFELSE([AC_LANG_SOURCE([[
#include <string.h>
#include <stdio.h>
int main(void)
{
  char buf1[32];
  char buf2[32];
  if (fgets(buf1, sizeof(buf1), stdin))
    snprintf(buf2, sizeof(buf2), "prefix%s", buf1);
}
]])],[
AC_MSG_RESULT([no])
],[
AC_MSG_RESULT([yes])
ac_cv_annoying_warning2=1
])
if [[ x"${ac_cv_annoying_warning2}" = x1 ]]
then
  AC_MSG_CHECKING([for -Wno-format-truncation])
  CC="${saved_CC} -Wall -Wno-format-truncation -Werror"
  CFLAGS=
  AC_COMPILE_IFELSE([AC_LANG_SOURCE([[
#include <string.h>
#include <stdio.h>
int main(void)
{
  char buf1[32];
  char buf2[32];
  if (fgets(buf1, sizeof(buf1), stdin))
    snprintf(buf2, sizeof(buf2), "prefix%s", buf1);
}
]])],[
AC_MSG_RESULT([yes])
ac_cv_gcc_wno_format_truncation=-Wno-format-truncation
],[
AC_MSG_RESULT([no])
])
fi
CC="${saved_CC}"
CFLAGS="${saved_CFLAGS}"

dnl check whether long long is supported
AC_MSG_CHECKING([for long long type])
AC_RUN_IFELSE(
[AC_LANG_SOURCE([[
int main(void)
{
  long long a = 0;
  unsigned long long b = 0;
  signed long long c = 0;
  return 0;
}
]])],[
AC_MSG_RESULT([yes])
ac_cv_has_long_long=1
],[
AC_MSG_RESULT([no])
ac_cv_has_long_long=""
])

dnl check whether __int64 is supported
AC_MSG_CHECKING([for __int64 type])
AC_RUN_IFELSE(
[AC_LANG_SOURCE([[
int main(void)
{
  __int64 a = 0;
  unsigned __int64 b = 0;
  signed __int64 c = 0;
  return 0;
}
]])],[
AC_MSG_RESULT([yes])
ac_cv_has___int64=1
],[
AC_MSG_RESULT([no])
ac_cv_has___int64=""
])

AC_MSG_CHECKING([for -m32 support])
saved_CC="${CC}"
saved_CFLAGS="${CFLAGS}"
CC="${CC} -m32 -fPIC -DPIC"
CFLAGS=`echo "${CFLAGS}" | sed s/-m32//g | sed s/-m64//g`
AC_RUN_IFELSE([AC_LANG_SOURCE([[
#include <string.h>
#include <stdio.h>
int main(void)
{
  printf("");
  return 0;
}
]])],[
AC_MSG_RESULT([yes])
ac_cv_need_32=1
],[
AC_MSG_RESULT([no])
])
CC="${saved_CC}"
CFLAGS="${saved_CFLAGS}"

AC_MSG_CHECKING([for -m64 support])
saved_CC="${CC}"
saved_CFLAGS="${CFLAGS}"
CC="${CC} -m64 -fPIC -DPIC"
CFLAGS=`echo "${CFLAGS}" | sed s/-m32//g | sed s/-m64//g`
AC_RUN_IFELSE([AC_LANG_SOURCE([[
#include <string.h>
#include <stdio.h>
int main(void)
{
  printf("");
  return 0;
}
]])],[
AC_MSG_RESULT([yes])
ac_cv_need_64=1
],[
AC_MSG_RESULT([no])
])
CC="${saved_CC}"
CFLAGS="${saved_CFLAGS}"

dnl localization stuff

if [[ x"${ac_cv_nls}" = xno ]]
then
  ac_cv_nls=""
else
  ac_cv_nls=1
fi 

if [[ x"${ac_cv_nls}" = x1 ]]
then
  AC_CHECK_PROG([ICONV],[iconv],[iconv],[false])
  [[ x"${ICONV}" = xfalse ]] && ac_cv_nls=""
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

if [[ x"${ac_cv_enable_libmongoc}" != xdisable ]]
then
  AC_MSG_CHECKING([for libmongoc])
  if pkg-config --atleast-version 1.13.0 libmongoc-1.0
  then
    AC_MSG_RESULT([yes])
    ac_cv_has_libmongoc=2
  elif pkg-config --exists libmongoc-1.0
  then
    AC_MSG_RESULT([yes])
    ac_cv_has_libmongoc=1
  else
    AC_MSG_RESULT([no])
    ac_cv_has_libmongoc=
  fi
fi

if [[ x"${ac_cv_has_libmongoc}" != x ]]
then
  ac_cv_libmongoc_cflags=`pkg-config --cflags libmongoc-1.0`
  ac_cv_libmongoc_libs=`pkg-config --libs libmongoc-1.0`
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
elif [[ x"${libexecdir}" = x'${exec_prefix}/lib' ]]
then
  actual_libexecdir="${actual_exec_prefix}/lib"
else
  actual_libexecdir="${libexecdir}"
fi

actual_libdir=`echo ${libdir} | sed 's|${exec_prefix}|'${actual_exec_prefix}'|'`
if [[ x"${lib32dir}" != x ]]
then
  actual_lib32dir=`echo ${lib32dir} | sed 's|${exec_prefix}|'${actual_exec_prefix}'|'`
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
ac_cv_ejudge_serve_path="${ac_cv_ejudge_server_bin_path}/ej-serve"
ac_cv_ejudge_run_path="${ac_cv_ejudge_server_bin_path}/ej-run"
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

if [[ -x ../new-c/bin/rcc ]]
then
  ac_cv_meta_cc=../new-c/bin/rcc
else
  ac_cv_meta_cc=./scripts/rcc
fi

if [[ x"${ac_cv_rest}" = x ]]
then
  ac_cv_rest="/ej/"
fi

AC_SUBST(ac_cv_ejudge_arch)
AC_SUBST(ac_cv_exe_suffix)
AC_SUBST(ac_cv_expat_root)
AC_SUBST(ac_cv_expat_include_opt)
AC_SUBST(ac_cv_expat_lib_opt)
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
AC_SUBST(ac_cv_gcc_wno_format_truncation)
AC_SUBST(cgibindir)
AC_SUBST(XGETTEXT)
AC_SUBST(MSGMERGE)
AC_SUBST(MSGFMT)
AC_SUBST(ac_cv_style_prefix)
AC_SUBST(CHARSET_UPPERCASE)
AC_SUBST(ac_cv_ncurses_suffix)
AC_SUBST(ac_cv_ncurses_include)
AC_SUBST(ac_cv_local_dir)
AC_SUBST(ac_cv_werror_flag)
AC_SUBST(ac_cv_preserve_scripts)
AC_SUBST(ac_cv_httpd_cgi_bin_dir)
AC_SUBST(ac_cv_httpd_htdocs_dir)
AC_SUBST(ac_cv_has_lib_iconv)
AC_SUBST(ac_cv_has_lib_libiconv)
AC_SUBST(ac_cv_has_lib_intl)
AC_SUBST(ac_cv_has_lib_libzip)
AC_SUBST(ac_cv_has_lib_liblzma)
AC_SUBST(ac_cv_has_lib_libcurl)
AC_SUBST(ac_cv_has_lib_libuuid)
AC_SUBST(ac_cv_has_lib_hiredis)
AC_SUBST(ac_cv_meta_cc)
AC_SUBST(ac_cv_need_32)
AC_SUBST(ac_cv_need_64)
AC_SUBST(lib32dir)

AC_SUBST(ac_cv_festival_home)
AC_SUBST(ac_cv_libcap_link)
AC_SUBST(ac_cv_ejudge_server_bin_path_m)
AC_SUBST(ac_cv_lang_config_dir)
AC_SUBST(ac_cv_lang_config_dir_expanded)
AC_SUBST(ac_cv_has_libmongoc)
AC_SUBST(ac_cv_libmongoc_cflags)
AC_SUBST(ac_cv_libmongoc_libs)

AC_SUBST(ac_cv_primary_user)
AC_SUBST(ac_cv_compile_user)
AC_SUBST(ac_cv_exec_user)

if [[ x"${ac_cv_has_regex}" = x1 ]]
then
  AC_DEFINE(CONF_HAS_REGEX,1)
fi

if [[ x"${ac_cv_has_libuuid}" = x1 -a x"${ac_cv_has_lib_libuuid}" != x ]]
then
  AC_DEFINE(CONF_HAS_LIBUUID,1)
fi

if [[ x"${ac_cv_has_libcurl}" = x1 -a x"${ac_cv_has_lib_libcurl}" != x ]]
then
  AC_DEFINE(CONF_HAS_LIBCURL,1)
fi

if [[ x"${ac_cv_has_libzip}" = x1 -a x"${ac_cv_has_lib_libzip}" != x ]]
then
  AC_DEFINE(CONF_HAS_LIBZIP,1)
fi

if [[ x"${ac_cv_has_liblzma}" = x1 -a x"${ac_cv_has_lib_liblzma}" != x ]]
then
  AC_DEFINE(CONF_HAS_LIBLZMA,1)
fi

if [[ x"${ac_cv_has_hiredis}" = x1 -a x"${ac_cv_has_lib_hiredis}" != x ]]
then
  AC_DEFINE(CONF_HAS_HIREDIS,1)
fi

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

if [[ x"${ac_cv_iconv_needs_const}" = x1 ]]
then
  AC_DEFINE(CONF_ICONV_NEEDS_CONST,1)
fi

if [[ x"${ac_cv_ajax}" != xno -a x"${ac_cv_ajax}" != x ]]
then
  AC_DEFINE(CONF_ENABLE_AJAX,1)
fi

if [[ x"${ac_cv_have_task_append}" != xno -a x"${ac_cv_have_task_append}" != x ]]
then
  AC_DEFINE(HAVE_TASK_APPEND,1)
fi

if [[ x"${ac_cv_have_so_passcred}" != xno -a x"${ac_cv_have_so_passcred}" != x ]]
then
  AC_DEFINE(HAVE_SO_PASSCRED,1)
fi

if [[ x"${ac_cv_have_siocing}" != xno -a x"${ac_cv_have_siocing}" != x ]]
then
  AC_DEFINE(HAVE_SIOCINQ,1)
fi

if [[ x"${ac_cv_have_f_notify}" != xno -a x"${ac_cv_have_f_notify}" != x ]]
then
  AC_DEFINE(HAVE_F_NOTIFY,1)
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
AC_DEFINE_UNQUOTED(EJUDGE_LIB_DIR,"${actual_libdir}")
if [[ x"${lib32dir}" != x ]]
then
  AC_DEFINE_UNQUOTED(EJUDGE_LIB32_DIR,"${actual_lib32dir}")
fi
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
if [[ x"${ac_cv_compile_spool_dir}" != x ]]
then
  AC_DEFINE_UNQUOTED(EJUDGE_COMPILE_SPOOL_DIR,"${ac_cv_compile_spool_dir}")
fi
if [[ x"${ac_cv_run_spool_dir}" != x ]]
then
  AC_DEFINE_UNQUOTED(EJUDGE_RUN_SPOOL_DIR,"${ac_cv_run_spool_dir}")
fi
if [[ x"${ac_cv_contests_status_dir}" != x ]]
then
  AC_DEFINE_UNQUOTED(EJUDGE_CONTESTS_STATUS_DIR,"${ac_cv_contests_status_dir}")
fi

if [[ x"${ac_cv_conf_dos_filenaming}" != x ]]
then
  AC_DEFINE(CONF_DOS_FILENAMING, 1)
fi

if [[ x"${ac_cv_conf_unix_filenaming}" != x ]]
then
  AC_DEFINE(CONF_UNIX_FILENAMING, 1)
fi

AC_DEFINE_UNQUOTED(CONF_EXE_SUFFIX,"${ac_cv_exe_suffix}")
AC_DEFINE_UNQUOTED(CONF_DIRSEP,"${ac_cv_dir_separator}")
AC_DEFINE_UNQUOTED(CONF_PATHSEP,"${ac_cv_path_separator}")

if [[ x"${ac_cv_rest}" != xno ]]
then
  ac_cv_rest_len=${#ac_cv_rest}
  AC_DEFINE_UNQUOTED(EJUDGE_REST_PREFIX,"${ac_cv_rest}")
  AC_DEFINE_UNQUOTED(EJUDGE_REST_PREFIX_LEN,${ac_cv_rest_len})
fi

if [[ x"${ac_cv_primary_user}" != x -a x"${ac_cv_primary_user}" != xno ]]
then
  AC_DEFINE_UNQUOTED(EJUDGE_PRIMARY_USER,"${ac_cv_primary_user}")
fi
if [[ x"${ac_cv_exec_user}" != x -a x"${ac_cv_exec_user}" != xno ]]
then
  AC_DEFINE_UNQUOTED(EJUDGE_EXEC_USER,"${ac_cv_exec_user}")
fi
if [[ x"${ac_cv_compile_user}" != x -a x"${ac_cv_compile_user}" != xno ]]
then
  AC_DEFINE_UNQUOTED(EJUDGE_COMPILE_USER,"${ac_cv_compile_user}")
fi

if [[ x"${ac_cv_conf_64_bit}" != xyes ]]
then
  AC_DEFINE(CONF_64_BIT, 1)
fi

if [[ x"${ac_cv_c_long_double}" != xyes ]]
then
  AC_DEFINE(R_LONG_DOUBLE_IS_DOUBLE, 1)
fi

if [[ x"${ac_cv_has_long_long}" = x1 ]]
then
  AC_DEFINE(R_HAS_LONGLONG, 1)
fi

if [[ x"${ac_cv_has___int64}" = x1 ]]
then
  AC_DEFINE(R_HAS___INT64, 1)
fi

if [[ x"${ac_cv_has_libmongoc}" = x2 ]]
then
  AC_DEFINE(HAVE_LIBMONGOC, 2)
elif [[ x"${ac_cv_has_libmongoc}" = x1 ]]
then
  AC_DEFINE(HAVE_LIBMONGOC, 1)
fi

AC_CONFIG_HEADERS([config.h])

AC_CONFIG_SUBDIRS([libdwarf])

AC_CONFIG_SUBDIRS([libbacktrace])

AC_CONFIG_FILES([Makefile extra/Makefile extra/captest/Makefile checkers/Makefile scripts/Makefile ejudge-config.v scripts/festival plugins/common-mysql/Makefile plugins/userlist-mysql/Makefile plugins/clardb-mysql/Makefile plugins/rundb-mysql/Makefile plugins/common-mongo/Makefile plugins/xuser-mongo/Makefile style/ejudge-upgrade-web cfront/Makefile reuse/Makefile csp/contests/Makefile csp/super-server/Makefile csp_header.make plugins/telegram/Makefile plugins/avatar-mongo/Makefile plugins/status-mongo/Makefile plugins/status-mysql/Makefile plugins/auth-google/Makefile plugins/auth-base/Makefile plugins/auth-vk/Makefile plugins/auth-fb/Makefile plugins/xuser-mysql/Makefile plugins/avatar-mysql/Makefile plugins/variant-mysql/Makefile plugins/storage-mysql/Makefile plugins/cache-mysql/Makefile plugins/submit-mysql/Makefile plugins/userprob-mysql/Makefile plugins/vcs-gitlab/Makefile plugins/auth-yandex/Makefile plugins/notify-redis/Makefile plugins/auth-oidc/Makefile plugins/notify-redis-streams/Makefile])
AC_OUTPUT

#cp -p config.h include/reuse
cp -p config.h include/ejudge
cp -p libdwarf/libdwarf/dwarf.h include/libdwarf-internal
cp -p libdwarf/libdwarf/libdwarf.h include/libdwarf-internal

chmod +x ejudge-config.v scripts/festival style/ejudge-upgrade-web

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
