dnl $Id$
dnl Copyright (C) 2004 Alexander Chernov

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

AC_ARG_WITH([reuse], AC_HELP_STRING([--with-reuse=REUSE-DIR],[specify the path to reuse library]),[ac_cv_reuse_root=$withval])
AC_ARG_WITH([reuse-include-dir],AC_HELP_STRING([--with-reuse-include-dir],[specify the location of reuse include directories [[REUSE-DIR/include]]]),[ac_cv_reuse_include_dir=$withval])
AC_ARG_WITH([reuse-lib-dir],AC_HELP_STRING([--with-reuse-lib-dir],[specify the location of reuse library directories [[REUSE-DIR/lib]]]),[ac_cv_reuse_lib_dir=$withval])
AC_ARG_WITH([reuse-conf-dir],AC_HELP_STRING([--with-reuse-conf-dir],[specify the location of reuse configuration directories [[REUSE-DIR/etc]]]),[ac_cv_reuse_conf_dir=$withval])
AC_ARG_WITH([reuse-config],AC_HELP_STRING([--with-reuse-config],[specify the configuration name]),[ac_cv_reuse_config=$withval])

AC_ARG_ENABLE([cgi-suffix], AC_HELP_STRING([--enable-cgi-suffix],[append the given suffix to the CGI programs]),[ac_cv_cgi_suffix=$enableval],[ac_cv_cgi_suffix=""])
AC_ARG_ENABLE([cgi-bin-dir], AC_HELP_STRING([--enable-cgi-bin-dir],[specify the destination CGI script directory [[\${prefix}/cgi-bin]]]),[cgibindir=$enableval], [cgibindir='${prefix}/cgi-bin'])
AC_ARG_ENABLE([static], AC_HELP_STRING([--enable-static],[link programs statically]),[ac_cv_static=1],[ac_cv_static=""])
AC_ARG_ENABLE([cgi-conf-path], AC_HELP_STRING([--enable-cgi-conf-path],[specify path to CGI configuration files]),[ac_cv_cgi_conf_path=$enableval],[ac_cv_cgi_conf_path=../cgi-data])
AC_ARG_ENABLE([nls], AC_HELP_STRING([--disable-nls],[disable localization]),[ac_cv_nls=$enableval],[ac_cv_nls=""])
AC_ARG_ENABLE([ejudge-xml],AC_HELP_STRING([--enable-ejudge-xml],[specify the default location of ejudge.xml]),[ac_cv_default_ejudge_xml="$enableval"],[ac_cv_default_ejudge_xml=""])
AC_ARG_ENABLE([charset],AC_HELP_STRING([--enable-charset],[specify the default charset]),[ac_cv_default_charset="$enableval"],[ac_cv_default_charset=""])
AC_ARG_ENABLE([socket-path],AC_HELP_STRING([--enable-socket-path],[specify the default userlist-server socket path]),[ac_cv_socket_path="$enableval"],[ac_cv_socket_path=""])
AC_ARG_ENABLE([contests-dir],AC_HELP_STRING([--enable-contests-dir],[specify the default path to the contest configuration directory]),[ac_cv_contests_dir="$enableval"],[ac_cv_contests_dir=""])

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

if [[ x"${ac_cv_has_expat}" = x ]]
then
AC_MSG_FAILURE([expat XML parsing library missing])
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

CFLAGS="${saved_CFLAGS}"
CPPFLAGS="${saved_CPPFLAGS}"
LDFLAGS="${saved_LDFLAGS}"
LIBS="${saved_LIBS}"

if [[ x"${ac_cv_has_libcap}" = x ]]
then
ac_cv_no_kernel=1
else
ac_cv_no_kernel=
fi

dnl reuse checking stuff

ac_cv_has_reuse=1
if [[ x"${ac_cv_reuse_root}" = x -o x"${ac_cv_reuse_root}" = xyes -o x"${ac_cv_reuse_root}" = xno ]]
then
  AC_MSG_ERROR([You must specify the reuse directory using --with-reuse])
fi

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

if [[ x"${ac_cv_has_reuse}" = x1 ]]
then
  AC_MSG_CHECKING([that reuse version >= 3.0.17])
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
if [[ x"${ac_cv_nls}" = x1 ]]
then
  AC_CHECK_HEADER([locale.h],[],[ac_cv_nls=""])
fi
if [[ x"${ac_cv_nls}" = x1 ]]
then
  AC_CHECK_HEADER([libintl.h],[],[ac_cv_nls=""])
fi

dnl Create the expanded locale_dir path
if [[ x"${prefix}" = xNONE ]]
then
  actual_prefix="${ac_default_prefix}"
else
  actual_prefix="${prefix}"
fi

ac_cv_expanded_locale_dir="${actual_prefix}/share/locale"
ac_cv_ejudge_serve_path="${actual_prefix}/bin/serve"
ac_cv_ejudge_run_path="${actual_prefix}/bin/run"
ac_cv_ejudge_script_dir="${actual_prefix}/libexec/ejudge"

[[ x"${ac_cv_default_ejudge_xml}" = xyes -o x"${ac_cv_default_ejudge_xml}" = xno ]] && ac_cv_default_ejudge_xml=""
[[ x"${ac_cv_default_charset}" = xyes -o x"${ac_cv_default_charset}" = xno ]] && ac_cv_default_charset=""
[[ x"${ac_cv_socket_path}" = xyes -o x"${ac_cv_socket_path}" = xno ]] && ac_cv_socket_path=""
[[ x"${ac_cv_contests_dir}" = xyes -o x"${ac_cv_contests_dir}" = xno ]] && ac_cv_contests_dir=""

dnl Output generation

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
AC_SUBST(ac_cv_cgi_suffix)
AC_SUBST(ac_cv_static)
AC_SUBST(ac_cv_cgi_conf_path)
AC_SUBST(ac_cv_no_kernel)
AC_SUBST(ac_cv_nls)
AC_SUBST(cgibindir)
AC_SUBST(XGETTEXT)
AC_SUBST(MSGMERGE)
AC_SUBST(MSGFMT)
if [[ x"${ac_cv_nls}" = x1 ]]
then
  AC_DEFINE(CONF_HAS_LIBINTL,1)
fi
AC_DEFINE_UNQUOTED(CGI_PROG_SUFFIX,"$ac_cv_cgi_suffix")
AC_DEFINE_UNQUOTED(CGI_DATA_PATH,"$ac_cv_cgi_conf_path")
AC_DEFINE_UNQUOTED(EJUDGE_LOCALE_DIR,"$ac_cv_expanded_locale_dir")
if [[ x"${ac_cv_default_ejudge_xml}" != x ]]
then
  AC_DEFINE_UNQUOTED(EJUDGE_XML_PATH,"${ac_cv_default_ejudge_xml}")
fi
AC_DEFINE_UNQUOTED(EJUDGE_SERVE_PATH,"${ac_cv_ejudge_serve_path}")
AC_DEFINE_UNQUOTED(EJUDGE_RUN_PATH,"${ac_cv_ejudge_run_path}")
AC_DEFINE_UNQUOTED(EJUDGE_SCRIPT_DIR,"${ac_cv_ejudge_script_dir}")
if [[ x"${ac_cv_default_charset}" != x ]]
then
  AC_DEFINE_UNQUOTED(EJUDGE_CHARSET,"${ac_cv_default_charset}")
fi
if [[ x"${ac_cv_socket_path}" != x ]]
then
  AC_DEFINE_UNQUOTED(EJUDGE_SOCKET_PATH,"${ac_cv_socket_path}")
fi
if [[ x"${ac_cv_contests_dir}" != x ]]
then
  AC_DEFINE_UNQUOTED(EJUDGE_CONTESTS_DIR,"${ac_cv_contests_dir}")
fi
AC_CONFIG_HEADERS([config.h])
AC_OUTPUT(Makefile extra/Makefile checkers/Makefile scripts/Makefile)
