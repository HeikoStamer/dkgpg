# Copyright (C) 2017, 2018, 2019  Heiko Stamer <HeikoStamer@gmx.net>
#
# This file is part of Distributed Privacy Guard (DKGPG).
#
#   DKGPG is free software; you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation; either version 2 of the License, or
#   (at your option) any later version.
#
#   DKGPG is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with DKGPG; if not, write to the Free Software
#   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#
# (Process this file with autoconf to produce a configure script.)

AC_REVISION([20190604])
AC_PREREQ(2.61)

AC_INIT([Distributed Privacy Guard], [1.1.3], [HeikoStamer@gmx.net], [dkgpg],
	[https://www.nongnu.org/dkgpg/])

AC_LANG(C++)
AC_CONFIG_SRCDIR([src/dkg-common.hh])
AC_CONFIG_HEADERS([src/dkgpg_config.h])
AM_INIT_AUTOMAKE([subdir-objects])
AM_MAINTAINER_MODE

AC_SUBST(PACKAGE)
AC_SUBST(VERSION)
AC_DEFINE_UNQUOTED(PACKAGE, "$PACKAGE_NAME", [Name of this package])
AC_DEFINE_UNQUOTED(VERSION, "$PACKAGE_VERSION", [Version of this package])

# Define some parameters and helping macros
AC_DEFINE(DKGPG_MAX_N, 32, [Define the maximum number of parties/peers])

# Checks for Libtool
LT_PREREQ([2.4.2])
LT_INIT
LT_LANG([C++])

# Checks for required programs
AC_PROG_CC
AC_PROG_CXX
AC_PROG_MAKE_SET
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MKDIR_P

# Checks for required libraries
backup_LDFLAGS="$LDFLAGS"
backup_CPPFLAGS="$CPPFLAGS"
AC_ARG_WITH(gmp, [AS_HELP_STRING([--with-gmp=<path>],
 [prefix of libgmp installation e.g. /usr/local])],
 [GMP_PREFIX="$with_gmp" LDFLAGS="-L${with_gmp}/lib $backup_LDFLAGS"\
  CPPFLAGS="-I${with_gmp}/include $backup_CPPFLAGS"],
 [AC_CHECK_LIB(gmp, __gmpz_init, [LIBS=""],
  AC_MSG_ERROR([libgmp is required; use the --with-gmp=<path> option]))])
AC_CHECK_LIB(gmp, __gmpz_import, [LIBS=""],
 AC_MSG_ERROR([libgmp >= 4.2 is required]))
AC_CHECK_LIB(gmp, __gmpz_export, [LIBS=""],
 AC_MSG_ERROR([libgmp >= 4.2 is requird]))
AC_CHECK_LIB(gmp, __gmpz_powm_sec, [LIBS=""],
 AC_MSG_ERROR([libgmp >= 5.0.3 is required]))
AC_CHECK_HEADERS([gmp.h], , AC_MSG_ERROR([libgmp headers are missing]))
if test "x$GMP_PREFIX" != x ; then
	LIBGMP_LIBS=" -L${GMP_PREFIX}/lib"
	LIBGMP_CFLAGS=" -I${GMP_PREFIX}/include"
else
	LIBGMP_LIBS=""
	LIBGMP_CFLAGS=""
fi
LIBGMP_LIBS="${LIBGMP_LIBS} -lgmp"
AC_SUBST(LIBGMP_LIBS)
AC_SUBST(LIBGMP_CFLAGS)
LDFLAGS="$backup_LDFLAGS"
CPPFLAGS="$backup_CPPFLAGS"

echo "(1) $LDFLAGS"
echo "(2) $CPPFLAGS"
echo "(3) $CFLAGS"
echo "(4) $LIBS"

AM_PATH_LIBGCRYPT("1.6.0")
if test "x$LIBGCRYPT_LIBS" = "x"; then
	AC_MSG_ERROR([libgcrypt >= 1.6.0 is needed])
fi
backup_CPPFLAGS="$CPPFLAGS"
CPPFLAGS="$LIBGCRYPT_CFLAGS $backup_CPPFLAGS"
AC_CHECK_HEADERS([gcrypt.h], , AC_MSG_ERROR([libgcrypt headers are missing]))
CPPFLAGS="$backup_CPPFLAGS"

echo "(1) $LDFLAGS"
echo "(2) $CPPFLAGS"
echo "(3) $CFLAGS"
echo "(4) $LIBS"

AM_PATH_GPG_ERROR("1.12")
if test "x$GPG_ERROR_LIBS" = "x"; then
	AC_MSG_ERROR([libgpg-error >= 1.12 is needed])
fi

echo "(1) $LDFLAGS"
echo "(2) $CPPFLAGS"
echo "(3) $CFLAGS"
echo "(4) $LIBS"

AM_PATH_LIBTMCG("1.3.18")
if test "x$LIBTMCG_LIBS" = "x"; then
        AC_MSG_ERROR([libTMCG >= 1.3.18 is needed])
fi
AC_SUBST(LIBTMCG_LIBS)
AC_SUBST(LIBTMCG_CFLAGS)

echo "(1) $LDFLAGS"
echo "(2) $CPPFLAGS"
echo "(3) $CFLAGS"
echo "(4) $LIBS"

# "It is the user's responsibilty to tell the configure script where the
#  libraries are. [...] There is absolutely no reason for the maintainer to
#  modify the build scripts at all to accomodate a user on this point, and
#  many good reasons for not trying to do anything."
# cf. https://stackoverflow.com/questions/10199754/adding-a-path-to-ac-check-lib
AC_CHECK_LIB(z, inflateInit2_, , AC_MSG_ERROR([zlib is required]))
COMP_LIBS="-lz"
AC_CHECK_LIB(bz2, BZ2_bzDecompressInit, [libbz=1 COMP_LIBS="$COMP_LIBS -lbz2"
 AC_DEFINE(LIBBZ, 1, [Defined if libbzip2 is available])],
 AC_MSG_WARN([libbzip2 is recommended; adjust LDFLAGS to be detected]))
AC_SUBST(COMP_LIBS)

echo "(1) $LDFLAGS"
echo "(2) $CPPFLAGS"
echo "(3) $CFLAGS"
echo "(4) $LIBS"

# Checks for required header files
AC_HEADER_STDC
AC_HEADER_TIME
AC_CHECK_HEADERS([algorithm assert.h cassert cstdarg cstdio cstdlib cstring\
 ctime climits errno.h fcntl.h fstream functional inttypes.h iostream\
 limits.h list map sstream stdint.h stdio.h string string.h sys/stat.h\
 sys/select.h sys/types.h time.h unistd.h vector], , 
	AC_MSG_ERROR([some headers are missing]))

echo "(1) $LDFLAGS"
echo "(2) $CPPFLAGS"
echo "(3) $CFLAGS"
echo "(4) $LIBS"

AC_CHECK_HEADERS([zlib.h], , AC_MSG_ERROR([zlib header is missing]))
if test "x$libbz" = "x1"; then
AC_CHECK_HEADERS([bzlib.h], , AC_MSG_ERROR([bzlib header is missing]))
fi

# Checks for required typedefs, structures, and compiler characteristics
AC_C_CONST
AC_C_INLINE
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T

# Checks for required basic library functions
AC_FUNC_MALLOC
AC_FUNC_MEMCMP
AC_CHECK_FUNCS([abs chmod clock close ctime fcntl fileno fprintf memcmp\
 memcpy memmove memset mktime open perror read sscanf select sleep snprintf\
 stat strptime strrchr strtoul time write], ,
	AC_MSG_ERROR([some basic functions are missing]))

# Checks for required process and network library functions
AC_HEADER_SYS_WAIT
AC_TYPE_PID_T
AC_TYPE_SIGNAL
AC_FUNC_FORK
AC_CHECK_HEADERS([unistd.h sys/types.h sys/wait.h signal.h netdb.h\
 netinet/in.h sys/socket.h termios.h], ,
	AC_MSG_ERROR([some further headers are missing]))
AC_CHECK_FUNCS([fork kill pipe pipe2 waitpid getaddrinfo getnameinfo\
 htons htonl socket setsockopt connect bind listen accept signal sigaction\
 gai_strerror freeaddrinfo tcgetattr tcsetattr], , 
	AC_MSG_ERROR([some further functions are missing]))

# Checks for locking memory
AC_CHECK_HEADERS([sys/mman.h], , 
	AC_MSG_ERROR([some headers for locking memory are missing]))
AC_CHECK_FUNCS([mlockall munlockall], ,
	AC_MSG_ERROR([some functions for locking memory are missing]))

# Checks for optional GNUnet support
gnunet=0
lookin=${prefix}
backup_LDFLAGS="$LDFLAGS"       
backup_CPPLAGS="$CPPFLAGS"
GNUNET_LIBS=""
GNUNET_CFLAGS=""
AC_MSG_CHECKING([for GNUnet])
AC_ARG_WITH(gnunet, [AS_HELP_STRING([--with-gnunet=<path>],
	[prefix of GNUnet installation])], [AC_MSG_RESULT([$with_gnunet])
	case $with_gnunet in
		no)
			lookin=""
			;;
		yes)
			lookin="${prefix}"
			;;
		*)
			lookin="$with_gnunet"
			;;
	esac
	], [AC_MSG_RESULT([--with-gnunet not specified])])

if test "x$gnunet" = "x0" -a ! "x$lookin" = "x"; then
	GNUNET_LIBS="-L${lookin}/lib"
	GNUNET_CFLAGS="-I${lookin}/include"
	LDFLAGS="$GNUNET_LIBS $backup_LDFLAGS"
	CPPFLAGS="$GNUNET_CFLAGS $backup_CPPFLAGS"
	AC_CHECK_HEADERS([gnunet/gnunet_util_lib.h], [gnunet=1], [gnunet=0],
	 [#include <gnunet/platform.h>])
	AC_CHECK_LIB([gnunetutil], [GNUNET_xfree_], [LIBS=""], [gnunet=0])
	AC_CHECK_HEADERS([gnunet/gnunet_hello_lib.h], , [gnunet=0],
	 [#include <gnunet/platform.h>])
	AC_CHECK_LIB([gnunethello], [GNUNET_HELLO_get_id], [LIBS=""], [gnunet=0])
	AC_CHECK_HEADERS([gnunet/gnunet_transport_hello_service.h], , [gnunet=0],
	 [#include <gnunet/platform.h>])
	AC_CHECK_LIB([gnunettransport], [GNUNET_TRANSPORT_hello_get], [LIBS=""],
	 [gnunet=0])
	AC_CHECK_HEADERS([gnunet/gnunet_cadet_service.h], , [gnunet=0],
	 [#include <gnunet/platform.h>])
	AC_CHECK_LIB([gnunetcadet], [GNUNET_CADET_connect], [LIBS=""], [gnunet=0])
fi
if test "x$gnunet" = "x1"; then
	AC_DEFINE(GNUNET, , [Define to enable GNUnet support])
	GNUNET_LIBS="${GNUNET_LIBS} -lgnunetutil"
	GNUNET_LIBS="${GNUNET_LIBS} -lgnunethello"
	GNUNET_LIBS="${GNUNET_LIBS} -lgnunettransport"
	GNUNET_LIBS="${GNUNET_LIBS} -lgnunetcadet"
fi
if test "x$gnunet" = "x0"; then
	GNUNET_LIBS=""
	GNUNET_CFLAGS=""
fi
AC_SUBST(GNUNET_LIBS)
AC_SUBST(GNUNET_CFLAGS)
LDFLAGS="$backup_LDFLAGS"
CPPFLAGS="$backup_CPPFLAGS"

# Enable all compiler warnings by default and some more
CFLAGS="$CFLAGS -Wall -Wextra"
CXXFLAGS="$CXXFLAGS -Wall -Wextra"

# Linking some sources for subdirectories tests and tools
AC_CONFIG_LINKS([tests/t-dkg-gencrs.cc:src/dkg-gencrs.cc])
AC_CONFIG_LINKS([tests/t-dkg-tcpip-common.hh:src/dkg-tcpip-common.hh])
AC_CONFIG_LINKS([tests/t-dkg-tcpip-common.cc:src/dkg-tcpip-common.cc])
AC_CONFIG_LINKS([tests/t-dkg-gnunet-common.hh:src/dkg-gnunet-common.hh])
AC_CONFIG_LINKS([tests/t-dkg-gnunet-common.cc:src/dkg-gnunet-common.cc])
AC_CONFIG_LINKS([tests/t-dkg-io.hh:src/dkg-io.hh])
AC_CONFIG_LINKS([tests/t-dkg-io.cc:src/dkg-io.cc])
AC_CONFIG_LINKS([tests/t-dkg-common.hh:src/dkg-common.hh])
AC_CONFIG_LINKS([tests/t-dkg-common.cc:src/dkg-common.cc])
AC_CONFIG_LINKS([tests/t-dkg-generate.cc:src/dkg-generate.cc])
AC_CONFIG_LINKS([tests/t-dkg-keyinfo.cc:src/dkg-keyinfo.cc])
AC_CONFIG_LINKS([tests/t-dkg-keycheck.cc:src/dkg-keycheck.cc])
AC_CONFIG_LINKS([tests/t-dkg-keysign.cc:src/dkg-keysign.cc])
AC_CONFIG_LINKS([tests/t-dkg-encrypt.cc:src/dkg-encrypt.cc])
AC_CONFIG_LINKS([tests/t-dkg-decrypt.cc:src/dkg-decrypt.cc])
AC_CONFIG_LINKS([tests/t-dkg-sign.cc:src/dkg-sign.cc])
AC_CONFIG_LINKS([tests/t-dkg-verify.cc:src/dkg-verify.cc])
AC_CONFIG_LINKS([tests/t-dkg-timestamp.cc:src/dkg-timestamp.cc])
AC_CONFIG_LINKS([tests/t-dkg-timestamp-verify.cc:src/dkg-timestamp-verify.cc])
AC_CONFIG_LINKS([tests/t-dkg-refresh.cc:src/dkg-refresh.cc])
AC_CONFIG_LINKS([tests/t-dkg-revoke.cc:src/dkg-revoke.cc])
AC_CONFIG_LINKS([tests/t-dkg-adduid.cc:src/dkg-adduid.cc])
AC_CONFIG_LINKS([tests/t-dkg-revuid.cc:src/dkg-revuid.cc])
AC_CONFIG_LINKS([tests/t-dkg-addrevoker.cc:src/dkg-addrevoker.cc])
AC_CONFIG_LINKS([tools/dkg-io.hh:src/dkg-io.hh])
AC_CONFIG_LINKS([tools/dkg-io.cc:src/dkg-io.cc])

# Define output
AC_CONFIG_FILES([Makefile src/Makefile tests/Makefile tools/Makefile\
 src/dkg-generate.1 src/dkg-encrypt.1 src/dkg-decrypt.1 src/dkg-sign.1\
 src/dkg-revoke.1 src/dkg-verify.1 src/dkg-keysign.1])
AC_OUTPUT

echo "Now type 'make && make install' to build and install $PACKAGE_NAME."

