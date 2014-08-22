/* -*- mode:c -*- */
/* $Id$ */

/* Copyright (C) 2002-2014 Alexander Chernov <cher@ejudge.ru> */

/*
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 */

#include "ejudge/xalloc.h"
#include "ejudge/osdeps.h"

#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <limits.h>
#include <ctype.h>
#include <grp.h>

/**
 * NAME:    strip_trailing_slashes
 * PURPOSE: Remove trailing slashes from PATH.
 * ARGS:    path -- directory path 
 *         
 * RETURN:  void
 * NOTE: 
   This is useful when using filename completion from a shell that
   adds a "/" after directory names (such as tcsh and bash), because
   the Unix rename and rmdir system calls return an "Invalid argument" error
   when given a path that ends in "/" (except for the root directory).  
 */

static void
strip_trailing_slashes (char *path)
{
  int last;

  last = strlen (path) - 1;
  while (last > 0 && path[last] == '/')
    path[last--] = '\0';
}

struct ptr_list
{
  char *dirname_end;
  struct ptr_list *next;
};

/**
 * NAME:    make_path
 * PURPOSE: make directory hierarchy
 * ARGS:     
 *         
 * RETURN:  1 -- error, 0 -- ok 
 * NOTE: 
 * Ensure that the directory ARGPATH exists.

   Create any leading directories that don't already exist, with
   permissions PARENT_MODE.
   If the last element of ARGPATH does not exist, create it as
   a new directory with permissions MODE.
   If OWNER and GROUP are non-negative, use them to set the UID and GID of
   any created directories.
   If PRESERVE_EXISTING is non-zero and ARGPATH is an existing directory,
   then do not attempt to set its permissions and ownership.

   Return 0 if ARGPATH exists as a directory with the proper
   ownership and permissions when done, otherwise 1.  */

static int
make_path (const char *argpath,
           int mode,
           int parent_mode,
           uid_t owner,
           gid_t group,
           int preserve_existing)
{
  char *dirpath;                /* A copy we can scribble NULs on.  */
  struct stat stats;
  int retval = 0;
  int oldmask = umask (0);
  dirpath = (char *) xmalloc (strlen (argpath) + 1);
  strcpy (dirpath, argpath);
  strip_trailing_slashes(dirpath); /* del last '/' */
  if (stat (dirpath, &stats)) {
    char *slash;
    int tmp_mode;             /* Initial perms for leading dirs.  */
    int re_protect;           /* Should leading dirs be unwritable? */
    struct ptr_list *p, *leading_dirs = NULL;

    /* If leading directories shouldn't be writable or executable,
       or should have set[ug]id or sticky bits set and we are setting
       their owners, we need to fix their permissions after making them.  */

    if (((parent_mode & 0300) != 0300)
        || (owner != (uid_t) -1 && group != (gid_t) -1
            && (parent_mode & 07000) != 0)) {
      tmp_mode = 0700;
      re_protect = 1;
    } else {
      tmp_mode = parent_mode;
      re_protect = 0;
    }

    slash = dirpath;
    while (*slash == '/')
      slash++;
    while ((slash = strchr (slash, '/'))) {
      *slash = '\0';
      if (stat (dirpath, &stats)) {
        if (mkdir (dirpath, tmp_mode)) {
          //error (0, errno, "cannot create directory `%s'", dirpath);
          retval=1;
          goto ret;
        } else {
          if (owner != (uid_t) -1 && group != (gid_t) -1
              && chown (dirpath, owner, group)) {
            //error (0, errno, "%s", dirpath);
            retval = 1;
          }
          if (re_protect) {
            struct ptr_list *new = (struct ptr_list *)
              alloca (sizeof (struct ptr_list));
            new->dirname_end = slash;
            new->next = leading_dirs;
            leading_dirs = new;
          }
        }
      } else if (!S_ISDIR (stats.st_mode)) {
        //error (0, 0, "`%s' exists but is not a directory", dirpath);
        errno=20;
        retval=1;
        goto ret;
      }

      *slash++ = '/';

      /* Avoid unnecessary calls to `stat' when given
         pathnames containing multiple adjacent slashes.  */
      while (*slash == '/')
            slash++;
    }

    /* We're done making leading directories.
       Create the final component of the path.  */

    /* The path could end in "/." or contain "/..", so test
       if we really have to create the directory.  */

    if (stat (dirpath, &stats) && mkdir (dirpath, mode)) {
      //error (0, errno, "cannot create directory `%s'", dirpath);
      retval=1;
      goto ret;
    }

    if (owner != (uid_t) -1 && group != (gid_t) -1) {
      if (chown (dirpath, owner, group)) {
        //error (0, errno, "%s", dirpath);
        retval = 1;
      }
      /* chown may have turned off some permission bits we wanted.  */
      if ((mode & 07000) != 0 && chmod (dirpath, mode)) {
        //error (0, errno, "%s", dirpath);
        retval = 1;
      }
    }

    /* If the mode for leading directories didn't include owner "wx"
       privileges, we have to reset their protections to the correct
       value.  */
    for (p = leading_dirs; p != NULL; p = p->next) {
      *(p->dirname_end) = '\0';
      if (chmod (dirpath, parent_mode)) {
        //error (0, errno, "%s", dirpath);
        retval = 1;
      }
    }
  } else {
    /* We get here if the entire path already exists.  */
    if (!S_ISDIR (stats.st_mode)) {
      //error (0, 0, "`%s' exists but is not a directory", dirpath);
      errno=20;
      retval=1;
      goto ret;
    }

    if (!preserve_existing) {
      /* chown must precede chmod because on some systems,
         chown clears the set[ug]id bits for non-superusers,
         resulting in incorrect permissions.
         On System V, users can give away files with chown and then not
         be able to chmod them.  So don't give files away.  */
      
      if (owner != (uid_t) -1 && group != (gid_t) -1
          && chown (dirpath, owner, group)) {
        //error (0, errno, "%s", dirpath);
        retval = 1;
      }
      if (chmod (dirpath, mode)) {
        //error (0, errno, "%s", dirpath);
        retval = 1;
      }
    }
  }

ret:
//  fprintf(stderr, "exiting with errno=%d\n", errno);
  xfree(dirpath);
  umask (oldmask);
  return retval;
}

/**
 * NAME:    os_MakeDirPath
 * PURPOSE: make directory hierarchy
 * ARGS:    path - path to the directory to be created
 *          mode - directory mode
 * RETURN:  <0 - error, >= 0 - ok
 * NOTE:    not implemented
 */
  int
os_MakeDirPath(char const *path, int mode)
{
  int newmode, parent_mode, err;
  int old_mask = umask(0);
  newmode = 0777 & ~old_mask;
  parent_mode = newmode | 0300; /* u+wx */
   
  errno=0;
  err = make_path (path, newmode, parent_mode,
                     -1, -1, 1);
  umask(old_mask);
  return -err;
      
}

int
os_MakeDirPath2(const unsigned char *path, const unsigned char *mode_str, const unsigned char *group_str)
{
  char *eptr = NULL;
  int mode = -1, len, user_id = -1, group_id = -1, old_mask, err;
  unsigned char *tstr = NULL;
  struct group *grp = NULL;

  if (mode_str != NULL) {
    len = strlen(mode_str);
    if (len >= PATH_MAX) {
      errno = -EINVAL;
      return -1;
    }
    tstr = (unsigned char *) alloca(len + 1);
    strcpy(tstr, mode_str);
    while (len > 0 && isspace(tstr[len - 1])) --len;
    tstr[len] = 0;
    mode_str = tstr;
    if (len == 0) mode_str = NULL;
  }

  if (mode_str != NULL) {
    errno = 0;
    mode = strtol(mode_str, &eptr, 8);
    if (errno || *eptr || mode <= 0 || mode > 07777) {
      errno = -EINVAL;
      return -1;
    }
    mode |= 0700;
  }

  if (group_str != NULL) {
    len = strlen(group_str);
    if (len >= PATH_MAX) {
      errno = -EINVAL;
      return -1;
    }
    tstr = (unsigned char *) alloca(len + 1);
    strcpy(tstr, group_str);
    while (len > 0 && isspace(tstr[len - 1])) --len;
    tstr[len] = 0;
    group_str = tstr;
    if (len == 0) group_str = NULL;
  }

  if (group_str != NULL) {
    errno = 0;
    grp = getgrnam(group_str);
    if (grp == NULL || errno != 0) {
      errno = EINVAL;
      return -1;
    }
    group_id = grp->gr_gid;
    user_id = getuid();
  }

  old_mask = umask(0);
  if (mode <= 0) {
    mode = 0777 & ~old_mask;
  }
  errno = 0;
  err = make_path(path, mode, mode, user_id, group_id, 1);
  umask(old_mask);

  return err;
}

/*
 * Local variables:
 *  compile-command: "make -C .."
 * End:
 */
