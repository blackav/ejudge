#! /bin/sh
# $Id$

filename="$1"
infile="$2"
outfile="$3"

if [ x"${filename}" = x"" ]
then
    echo "filename parameter is not specified" >&2
    exit 1
fi
if [ x"${infile}" = x"" ]
then
    echo "infile parameter is not specified" >&2
    exit 1
fi
if [ x"${outfile}" = x"" ]
then
    echo "outfile parameter is not specified" >&2
    exit 1
fi

if [ ! -f "${infile}" ]
then
    echo "${infile} does not exist" >&2
    exit 1
fi

if uuencode --help > /dev/null
then
    uuencode -m contest-1.tar.gz < contest-1/contest-1.tar.gz | sed 's/$/\\n"/g' | sed 's/^/"/g' > contest-1/contest-1.c
else
    touch contest-1/contest-1.c
fi
