# Copyright (C) 2017, 2018  Heiko Stamer <HeikoStamer@gmx.net>
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


TESTS = t-dkg-gencrs t-dkg-generate t-dkg-keyinfo t-dkg-keysign t-dkg-encrypt\
 t-dkg-decrypt t-dkg-sign t-dkg-verify t-dkg-timestamp t-dkg-timestamp-verify\
 t-dkg-refresh t-dkg-revoke\
 y-dkg-generate y-dkg-keycheck y-dkg-keysign y-dkg-encrypt y-dkg-decrypt\
 y-dkg-sign y-dkg-verify y-dkg-timestamp y-dkg-timestamp-verify

AM_CPPFLAGS = -DDKGPG_TESTSUITE -I$(top_srcdir)/src @LIBTMCG_CFLAGS@\
 @LIBGCRYPT_CFLAGS@ @GPG_ERROR_CFLAGS@ @LIBGMP_CFLAGS@
LDADD = @LIBTMCG_LIBS@ @LIBGCRYPT_LIBS@ @GPG_ERROR_LIBS@ @LIBGMP_LIBS@

noinst_PROGRAMS = $(TESTS)

t_dkg_gencrs_SOURCES = t-dkg-gencrs.cc
t_dkg_generate_SOURCES = t-dkg-tcpip-common.hh t-dkg-tcpip-common.cc\
 t-dkg-gnunet-common.hh t-dkg-gnunet-common.cc t-dkg-io.hh t-dkg-io.cc\
 t-dkg-generate.cc
t_dkg_keyinfo_SOURCES = t-dkg-io.hh t-dkg-io.cc t-dkg-common.hh t-dkg-common.cc\
 t-dkg-keyinfo.cc
t_dkg_keysign_SOURCES = t-dkg-tcpip-common.hh t-dkg-tcpip-common.cc\
 t-dkg-gnunet-common.hh t-dkg-gnunet-common.cc t-dkg-common.hh t-dkg-common.cc\
 t-dkg-io.hh t-dkg-io.cc t-dkg-keysign.cc
t_dkg_encrypt_SOURCES = t-dkg-io.hh t-dkg-io.cc t-dkg-encrypt.cc
t_dkg_decrypt_SOURCES = t-dkg-tcpip-common.hh t-dkg-tcpip-common.cc\
 t-dkg-gnunet-common.hh t-dkg-gnunet-common.cc t-dkg-common.hh t-dkg-common.cc\
 t-dkg-io.hh t-dkg-io.cc t-dkg-decrypt.cc
t_dkg_decrypt_LDADD = @LIBTMCG_LIBS@ @LIBGCRYPT_LIBS@ @GPG_ERROR_LIBS@ @LIBGMP_LIBS@\
 @COMP_LIBS@
t_dkg_sign_SOURCES = t-dkg-tcpip-common.hh t-dkg-tcpip-common.cc\
 t-dkg-gnunet-common.hh t-dkg-gnunet-common.cc t-dkg-common.hh t-dkg-common.cc\
 t-dkg-io.hh t-dkg-io.cc t-dkg-sign.cc
t_dkg_verify_SOURCES = t-dkg-io.hh t-dkg-io.cc t-dkg-verify.cc
t_dkg_timestamp_SOURCES = t-dkg-tcpip-common.hh t-dkg-tcpip-common.cc\
 t-dkg-gnunet-common.hh t-dkg-gnunet-common.cc t-dkg-common.hh t-dkg-common.cc\
 t-dkg-io.hh t-dkg-io.cc t-dkg-timestamp.cc
t_dkg_timestamp_verify_SOURCES = t-dkg-io.hh t-dkg-io.cc t-dkg-timestamp-verify.cc
t_dkg_refresh_SOURCES = t-dkg-tcpip-common.hh t-dkg-tcpip-common.cc\
 t-dkg-gnunet-common.hh t-dkg-gnunet-common.cc t-dkg-common.hh t-dkg-common.cc\
 t-dkg-io.hh t-dkg-io.cc t-dkg-refresh.cc
t_dkg_revoke_SOURCES = t-dkg-tcpip-common.hh t-dkg-tcpip-common.cc\
 t-dkg-gnunet-common.hh t-dkg-gnunet-common.cc t-dkg-common.hh t-dkg-common.cc\
 t-dkg-io.hh t-dkg-io.cc t-dkg-revoke.cc

y_dkg_generate_CPPFLAGS = -DDKGPG_TESTSUITE_Y -I$(top_srcdir)/src\
 @LIBTMCG_CFLAGS@ @LIBGCRYPT_CFLAGS@ @GPG_ERROR_CFLAGS@ @LIBGMP_CFLAGS@
y_dkg_generate_SOURCES = t-dkg-tcpip-common.hh t-dkg-tcpip-common.cc\
 t-dkg-gnunet-common.hh t-dkg-gnunet-common.cc t-dkg-io.hh t-dkg-io.cc\
 t-dkg-generate.cc
y_dkg_keycheck_CPPFLAGS = -DDKGPG_TESTSUITE_Y -I$(top_srcdir)/src\
 @LIBTMCG_CFLAGS@ @LIBGCRYPT_CFLAGS@ @GPG_ERROR_CFLAGS@ @LIBGMP_CFLAGS@
y_dkg_keycheck_SOURCES = t-dkg-io.hh t-dkg-io.cc t-dkg-keycheck.cc
y_dkg_keysign_CPPFLAGS = -DDKGPG_TESTSUITE_Y -I$(top_srcdir)/src\
 @LIBTMCG_CFLAGS@ @LIBGCRYPT_CFLAGS@ @GPG_ERROR_CFLAGS@ @LIBGMP_CFLAGS@
y_dkg_keysign_SOURCES = t-dkg-tcpip-common.hh t-dkg-tcpip-common.cc\
 t-dkg-gnunet-common.hh t-dkg-gnunet-common.cc t-dkg-common.hh t-dkg-common.cc\
 t-dkg-io.hh t-dkg-io.cc t-dkg-keysign.cc
y_dkg_encrypt_CPPFLAGS = -DDKGPG_TESTSUITE_Y -I$(top_srcdir)/src\
 @LIBTMCG_CFLAGS@ @LIBGCRYPT_CFLAGS@ @GPG_ERROR_CFLAGS@ @LIBGMP_CFLAGS@
y_dkg_encrypt_SOURCES = t-dkg-io.hh t-dkg-io.cc t-dkg-encrypt.cc
y_dkg_decrypt_CPPFLAGS = -DDKGPG_TESTSUITE_Y -I$(top_srcdir)/src\
 @LIBTMCG_CFLAGS@ @LIBGCRYPT_CFLAGS@ @GPG_ERROR_CFLAGS@ @LIBGMP_CFLAGS@
y_dkg_decrypt_SOURCES = t-dkg-tcpip-common.hh t-dkg-tcpip-common.cc\
 t-dkg-gnunet-common.hh t-dkg-gnunet-common.cc t-dkg-common.hh t-dkg-common.cc\
 t-dkg-io.hh t-dkg-io.cc t-dkg-decrypt.cc
y_dkg_decrypt_LDADD = @LIBTMCG_LIBS@ @LIBGCRYPT_LIBS@ @GPG_ERROR_LIBS@\
 @LIBGMP_LIBS@ @COMP_LIBS@
y_dkg_sign_CPPFLAGS = -DDKGPG_TESTSUITE_Y -I$(top_srcdir)/src\
 @LIBTMCG_CFLAGS@ @LIBGCRYPT_CFLAGS@ @GPG_ERROR_CFLAGS@ @LIBGMP_CFLAGS@
y_dkg_sign_SOURCES = t-dkg-tcpip-common.hh t-dkg-tcpip-common.cc\
 t-dkg-gnunet-common.hh t-dkg-gnunet-common.cc t-dkg-common.hh t-dkg-common.cc\
 t-dkg-io.hh t-dkg-io.cc t-dkg-sign.cc
y_dkg_verify_CPPFLAGS = -DDKGPG_TESTSUITE_Y -I$(top_srcdir)/src\
 @LIBTMCG_CFLAGS@ @LIBGCRYPT_CFLAGS@ @GPG_ERROR_CFLAGS@ @LIBGMP_CFLAGS@
y_dkg_verify_SOURCES = t-dkg-io.hh t-dkg-io.cc t-dkg-verify.cc
y_dkg_timestamp_CPPFLAGS = -DDKGPG_TESTSUITE_Y -I$(top_srcdir)/src\
 @LIBTMCG_CFLAGS@ @LIBGCRYPT_CFLAGS@ @GPG_ERROR_CFLAGS@ @LIBGMP_CFLAGS@
y_dkg_timestamp_SOURCES = t-dkg-tcpip-common.hh t-dkg-tcpip-common.cc\
 t-dkg-gnunet-common.hh t-dkg-gnunet-common.cc t-dkg-common.hh t-dkg-common.cc\
 t-dkg-io.hh t-dkg-io.cc t-dkg-timestamp.cc
y_dkg_timestamp_verify_CPPFLAGS = -DDKGPG_TESTSUITE_Y -I$(top_srcdir)/src\
 @LIBTMCG_CFLAGS@ @LIBGCRYPT_CFLAGS@ @GPG_ERROR_CFLAGS@ @LIBGMP_CFLAGS@
y_dkg_timestamp_verify_SOURCES = t-dkg-io.hh t-dkg-io.cc t-dkg-timestamp-verify.cc


