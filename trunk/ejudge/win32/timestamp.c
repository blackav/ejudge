/* -*- c -*- */
/* $Id$ */

/* Copyright (C) 2005-2006 Alexander Chernov <cher@ispras.ru> */

/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include "timestamp.h"

#include <reuse/logger.h>
#include <reuse/xalloc.h>

#include <windows.h>

struct file_stamp
{
  FILETIME      mtime; // last modification time
  LARGE_INTEGER size;  // the file size
  FILETIME      check_time;
};

WINBASEAPI BOOL WINAPI GetFileSizeEx(HANDLE,PLARGE_INTEGER);

file_stamp_t
file_stamp_get(const unsigned char *path)
{
  file_stamp_t ts = 0;
  HANDLE h = INVALID_HANDLE_VALUE;
  SYSTEMTIME st;

  ASSERT(path);
  h = CreateFile(path, 0, 0, NULL, 0, 0, NULL);
  if (h == INVALID_HANDLE_VALUE) return 0;
  XCALLOC(ts, 1);
  GetFileTime(h, NULL, NULL, &ts->mtime);
  GetFileSizeEx(h, &ts->size);
  GetSystemTime(&st);
  SystemTimeToFileTime(&st, &ts->check_time);
  CloseHandle(h);
  return ts;
}

int
file_stamp_is_updated(const unsigned char *path, const file_stamp_t ts)
{
  HANDLE h;
  LARGE_INTEGER new_size;
  FILETIME new_mtime;
  SYSTEMTIME st;

  ASSERT(path);
  ASSERT(ts);

  h = CreateFile(path, 0, 0, NULL, 0, 0, NULL);
  if (h == INVALID_HANDLE_VALUE) return 1;
  GetFileTime(h, NULL, NULL, &new_mtime);
  GetFileSizeEx(h, &new_size);
  CloseHandle(h);

  /* FIXME: check for time interval */
  if (new_size.QuadPart != ts->size.QuadPart
	  || new_mtime.dwLowDateTime != ts->mtime.dwLowDateTime
	  || new_mtime.dwHighDateTime != ts->mtime.dwHighDateTime)
    return 1;
  GetSystemTime(&st);
  SystemTimeToFileTime(&st, &ts->check_time);
  return 0;
}

file_stamp_t
file_stamp_update(const unsigned char *path, file_stamp_t ts)
{
  HANDLE h;
  SYSTEMTIME st;

  ASSERT(path);

  if (!ts) return file_stamp_get(path);
  h = CreateFile(path, 0, 0, NULL, 0, 0, NULL);
  if (h == INVALID_HANDLE_VALUE) return file_stamp_free(ts);

  GetFileTime(h, NULL, NULL, &ts->mtime);
  GetFileSizeEx(h, &ts->size);
  GetSystemTime(&st);
  SystemTimeToFileTime(&st, &ts->check_time);
  CloseHandle(h);
  return ts;
}

file_stamp_t
file_stamp_free(file_stamp_t ts)
{
  if (!ts) return 0;
  xfree(ts);
  return 0;
}


/**
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */
