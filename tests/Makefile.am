# Copyright (C) 2017, 2018, 2019, 2020  Heiko Stamer <HeikoStamer@gmx.net>
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

TESTS = t-dkg-gencrs.test t-dkg-generate.test t-dkg-keyinfo.test\
 y-dkg-generate.test y-dkg-keycheck.test t-dkg-keysign.test t-dkg-encrypt.test\
 t-dkg-decrypt.test t-dkg-sign.test t-dkg-verify.test t-dkg-adduid.test\
 t-dkg-refresh.test t-dkg-revuid.test t-dkg-addrevoker.test y-dkg-keysign.test\
 t-dkg-attest.test y-dkg-encrypt.test y-dkg-decrypt.test y-dkg-sign.test\
 y-dkg-verify.test y-dkg-timestamp.test y-dkg-timestamp-verify.test\
 y-dkg-adduid.test y-dkg-revuid.test y-dkg-addrevoker.test y-dkg-attest.test\
 ts-dkg-generate.test ts-dkg-timestamp.test ts-dkg-timestamp-verify.test\
 t-dkg-revoke.test
t-dkg-keyinfo.log: t-dkg-generate.log
y-dkg-keycheck.log: y-dkg-generate.log
t-dkg-keysign.log: t-dkg-generate.log y-dkg-generate.log
t-dkg-encrypt.log: t-dkg-generate.log
t-dkg-decrypt.log: t-dkg-encrypt.log
t-dkg-sign.log: t-dkg-encrypt.log
t-dkg-verify.log: t-dkg-sign.log
t-dkg-adduid.log: t-dkg-generate.log
t-dkg-refresh.log: t-dkg-generate.log
t-dkg-revuid.log: t-dkg-adduid.log
t-dkg-addrevoker.log: t-dkg-generate.log
y-dkg-keysign.log: t-dkg-generate.log y-dkg-generate.log
t-dkg-attest.log: y-dkg-keysign.log
y-dkg-encrypt.log: y-dkg-generate.log
y-dkg-decrypt.log: y-dkg-encrypt.log
y-dkg-sign.log: y-dkg-encrypt.log
y-dkg-verify.log: y-dkg-sign.log
y-dkg-timestamp.log: y-dkg-sign.log
y-dkg-timestamp-verify.log: y-dkg-timestamp.log
y-dkg-adduid.log: y-dkg-generate.log
y-dkg-revuid.log: y-dkg-adduid.log
y-dkg-addrevoker.log: y-dkg-generate.log
y-dkg-attest.log: t-dkg-keysign.log
ts-dkg-timestamp.log: ts-dkg-generate.log t-dkg-sign.log
ts-dkg-timestamp-verify.log: ts-dkg-timestamp.log
t-dkg-revoke.log: ts-dkg-timestamp-verify.log t-dkg-attest.log y-dkg-attest.log

AM_CPPFLAGS = -DDKGPG_TESTSUITE -I$(top_srcdir)/src @LIBTMCG_CFLAGS@\
 @LIBGCRYPT_CFLAGS@ @GPG_ERROR_CFLAGS@ @LIBGMP_CFLAGS@
LDADD = @LIBTMCG_LIBS@ @LIBGCRYPT_LIBS@ @GPG_ERROR_LIBS@ @LIBGMP_LIBS@

EXTRA_PROGRAMS = t-dkg-gencrs.test t-dkg-generate.test t-dkg-keyinfo.test\
 y-dkg-generate.test y-dkg-keycheck.test t-dkg-keysign.test t-dkg-encrypt.test\
 t-dkg-decrypt.test t-dkg-sign.test t-dkg-verify.test t-dkg-adduid.test\
 t-dkg-refresh.test t-dkg-revuid.test t-dkg-addrevoker.test y-dkg-keysign.test\
 t-dkg-attest.test y-dkg-encrypt.test y-dkg-decrypt.test y-dkg-sign.test\
 y-dkg-verify.test y-dkg-timestamp.test y-dkg-timestamp-verify.test\
 y-dkg-adduid.test y-dkg-revuid.test y-dkg-addrevoker.test y-dkg-attest.test\
 ts-dkg-generate.test ts-dkg-timestamp.test ts-dkg-timestamp-verify.test\
 t-dkg-revoke.test

t_dkg_gencrs_test_SOURCES = t-dkg-gencrs.cc
t_dkg_generate_test_SOURCES = t-dkg-tcpip-common.hh t-dkg-tcpip-common.cc\
 t-dkg-gnunet-common.hh t-dkg-gnunet-common.cc t-dkg-common.hh t-dkg-common.cc\
 t-dkg-io.hh t-dkg-io.cc t-dkg-generate.cc
t_dkg_keyinfo_test_SOURCES = t-dkg-io.hh t-dkg-io.cc t-dkg-common.hh t-dkg-common.cc\
 t-dkg-keyinfo.cc
t_dkg_keysign_test_SOURCES = t-dkg-tcpip-common.hh t-dkg-tcpip-common.cc\
 t-dkg-gnunet-common.hh t-dkg-gnunet-common.cc t-dkg-common.hh t-dkg-common.cc\
 t-dkg-io.hh t-dkg-io.cc t-dkg-keysign.cc
t_dkg_encrypt_test_SOURCES = t-dkg-io.hh t-dkg-io.cc t-dkg-encrypt.cc
t_dkg_decrypt_test_SOURCES = t-dkg-tcpip-common.hh t-dkg-tcpip-common.cc\
 t-dkg-gnunet-common.hh t-dkg-gnunet-common.cc t-dkg-common.hh t-dkg-common.cc\
 t-dkg-io.hh t-dkg-io.cc t-dkg-decrypt.cc
t_dkg_decrypt_test_LDADD = @LIBTMCG_LIBS@ @LIBGCRYPT_LIBS@ @GPG_ERROR_LIBS@\
 @LIBGMP_LIBS@ @COMP_LIBS@
t_dkg_sign_test_SOURCES = t-dkg-tcpip-common.hh t-dkg-tcpip-common.cc\
 t-dkg-gnunet-common.hh t-dkg-gnunet-common.cc t-dkg-common.hh t-dkg-common.cc\
 t-dkg-io.hh t-dkg-io.cc t-dkg-sign.cc
t_dkg_verify_test_SOURCES = t-dkg-io.hh t-dkg-io.cc t-dkg-verify.cc
t_dkg_refresh_test_SOURCES = t-dkg-tcpip-common.hh t-dkg-tcpip-common.cc\
 t-dkg-gnunet-common.hh t-dkg-gnunet-common.cc t-dkg-common.hh t-dkg-common.cc\
 t-dkg-io.hh t-dkg-io.cc t-dkg-refresh.cc
t_dkg_revoke_test_SOURCES = t-dkg-tcpip-common.hh t-dkg-tcpip-common.cc\
 t-dkg-gnunet-common.hh t-dkg-gnunet-common.cc t-dkg-common.hh t-dkg-common.cc\
 t-dkg-io.hh t-dkg-io.cc t-dkg-revoke.cc
t_dkg_adduid_test_SOURCES = t-dkg-tcpip-common.hh t-dkg-tcpip-common.cc\
 t-dkg-gnunet-common.hh t-dkg-gnunet-common.cc t-dkg-common.hh t-dkg-common.cc\
 t-dkg-io.hh t-dkg-io.cc t-dkg-adduid.cc
t_dkg_revuid_test_SOURCES = t-dkg-tcpip-common.hh t-dkg-tcpip-common.cc\
 t-dkg-gnunet-common.hh t-dkg-gnunet-common.cc t-dkg-common.hh t-dkg-common.cc\
 t-dkg-io.hh t-dkg-io.cc t-dkg-revuid.cc
t_dkg_addrevoker_test_SOURCES = t-dkg-tcpip-common.hh t-dkg-tcpip-common.cc\
 t-dkg-gnunet-common.hh t-dkg-gnunet-common.cc t-dkg-common.hh t-dkg-common.cc\
 t-dkg-io.hh t-dkg-io.cc t-dkg-addrevoker.cc
t_dkg_attest_test_SOURCES = t-dkg-tcpip-common.hh t-dkg-tcpip-common.cc\
 t-dkg-gnunet-common.hh t-dkg-gnunet-common.cc t-dkg-common.hh t-dkg-common.cc\
 t-dkg-io.hh t-dkg-io.cc t-dkg-attest.cc

y_dkg_generate_test_CPPFLAGS = -DDKGPG_TESTSUITE_Y -I$(top_srcdir)/src\
 @LIBTMCG_CFLAGS@ @LIBGCRYPT_CFLAGS@ @GPG_ERROR_CFLAGS@ @LIBGMP_CFLAGS@
y_dkg_generate_test_SOURCES = t-dkg-tcpip-common.hh t-dkg-tcpip-common.cc\
 t-dkg-gnunet-common.hh t-dkg-gnunet-common.cc t-dkg-common.hh t-dkg-common.cc\
 t-dkg-io.hh t-dkg-io.cc t-dkg-generate.cc
y_dkg_keycheck_test_CPPFLAGS = -DDKGPG_TESTSUITE_Y -I$(top_srcdir)/src\
 @LIBTMCG_CFLAGS@ @LIBGCRYPT_CFLAGS@ @GPG_ERROR_CFLAGS@ @LIBGMP_CFLAGS@
y_dkg_keycheck_test_SOURCES = t-dkg-io.hh t-dkg-io.cc t-dkg-keycheck.cc
y_dkg_keysign_test_CPPFLAGS = -DDKGPG_TESTSUITE_Y -I$(top_srcdir)/src\
 @LIBTMCG_CFLAGS@ @LIBGCRYPT_CFLAGS@ @GPG_ERROR_CFLAGS@ @LIBGMP_CFLAGS@
y_dkg_keysign_test_SOURCES = t-dkg-tcpip-common.hh t-dkg-tcpip-common.cc\
 t-dkg-gnunet-common.hh t-dkg-gnunet-common.cc t-dkg-common.hh t-dkg-common.cc\
 t-dkg-io.hh t-dkg-io.cc t-dkg-keysign.cc
y_dkg_encrypt_test_CPPFLAGS = -DDKGPG_TESTSUITE_Y -I$(top_srcdir)/src\
 @LIBTMCG_CFLAGS@ @LIBGCRYPT_CFLAGS@ @GPG_ERROR_CFLAGS@ @LIBGMP_CFLAGS@
y_dkg_encrypt_test_SOURCES = t-dkg-io.hh t-dkg-io.cc t-dkg-encrypt.cc
y_dkg_decrypt_test_CPPFLAGS = -DDKGPG_TESTSUITE_Y -I$(top_srcdir)/src\
 @LIBTMCG_CFLAGS@ @LIBGCRYPT_CFLAGS@ @GPG_ERROR_CFLAGS@ @LIBGMP_CFLAGS@
y_dkg_decrypt_test_SOURCES = t-dkg-tcpip-common.hh t-dkg-tcpip-common.cc\
 t-dkg-gnunet-common.hh t-dkg-gnunet-common.cc t-dkg-common.hh t-dkg-common.cc\
 t-dkg-io.hh t-dkg-io.cc t-dkg-decrypt.cc
y_dkg_decrypt_test_LDADD = @LIBTMCG_LIBS@ @LIBGCRYPT_LIBS@ @GPG_ERROR_LIBS@\
 @LIBGMP_LIBS@ @COMP_LIBS@
y_dkg_sign_test_CPPFLAGS = -DDKGPG_TESTSUITE_Y -I$(top_srcdir)/src\
 @LIBTMCG_CFLAGS@ @LIBGCRYPT_CFLAGS@ @GPG_ERROR_CFLAGS@ @LIBGMP_CFLAGS@
y_dkg_sign_test_SOURCES = t-dkg-tcpip-common.hh t-dkg-tcpip-common.cc\
 t-dkg-gnunet-common.hh t-dkg-gnunet-common.cc t-dkg-common.hh t-dkg-common.cc\
 t-dkg-io.hh t-dkg-io.cc t-dkg-sign.cc
y_dkg_verify_test_CPPFLAGS = -DDKGPG_TESTSUITE_Y -I$(top_srcdir)/src\
 @LIBTMCG_CFLAGS@ @LIBGCRYPT_CFLAGS@ @GPG_ERROR_CFLAGS@ @LIBGMP_CFLAGS@
y_dkg_verify_test_SOURCES = t-dkg-io.hh t-dkg-io.cc t-dkg-verify.cc
y_dkg_timestamp_test_CPPFLAGS = -DDKGPG_TESTSUITE_Y -I$(top_srcdir)/src\
 @LIBTMCG_CFLAGS@ @LIBGCRYPT_CFLAGS@ @GPG_ERROR_CFLAGS@ @LIBGMP_CFLAGS@
y_dkg_timestamp_test_SOURCES = t-dkg-tcpip-common.hh t-dkg-tcpip-common.cc\
 t-dkg-gnunet-common.hh t-dkg-gnunet-common.cc t-dkg-common.hh t-dkg-common.cc\
 t-dkg-io.hh t-dkg-io.cc t-dkg-timestamp.cc
y_dkg_timestamp_verify_test_CPPFLAGS = -DDKGPG_TESTSUITE_Y -I$(top_srcdir)/src\
 @LIBTMCG_CFLAGS@ @LIBGCRYPT_CFLAGS@ @GPG_ERROR_CFLAGS@ @LIBGMP_CFLAGS@
y_dkg_timestamp_verify_test_SOURCES = t-dkg-io.hh t-dkg-io.cc\
 t-dkg-timestamp-verify.cc
y_dkg_adduid_test_CPPFLAGS = -DDKGPG_TESTSUITE_Y -I$(top_srcdir)/src\
 @LIBTMCG_CFLAGS@ @LIBGCRYPT_CFLAGS@ @GPG_ERROR_CFLAGS@ @LIBGMP_CFLAGS@
y_dkg_adduid_test_SOURCES = t-dkg-tcpip-common.hh t-dkg-tcpip-common.cc\
 t-dkg-gnunet-common.hh t-dkg-gnunet-common.cc t-dkg-common.hh t-dkg-common.cc\
 t-dkg-io.hh t-dkg-io.cc t-dkg-adduid.cc
y_dkg_revuid_test_CPPFLAGS = -DDKGPG_TESTSUITE_Y -I$(top_srcdir)/src\
 @LIBTMCG_CFLAGS@ @LIBGCRYPT_CFLAGS@ @GPG_ERROR_CFLAGS@ @LIBGMP_CFLAGS@
y_dkg_revuid_test_SOURCES = t-dkg-tcpip-common.hh t-dkg-tcpip-common.cc\
 t-dkg-gnunet-common.hh t-dkg-gnunet-common.cc t-dkg-common.hh t-dkg-common.cc\
 t-dkg-io.hh t-dkg-io.cc t-dkg-revuid.cc
y_dkg_addrevoker_test_CPPFLAGS = -DDKGPG_TESTSUITE_Y -I$(top_srcdir)/src\
 @LIBTMCG_CFLAGS@ @LIBGCRYPT_CFLAGS@ @GPG_ERROR_CFLAGS@ @LIBGMP_CFLAGS@
y_dkg_addrevoker_test_SOURCES = t-dkg-tcpip-common.hh t-dkg-tcpip-common.cc\
 t-dkg-gnunet-common.hh t-dkg-gnunet-common.cc t-dkg-common.hh t-dkg-common.cc\
 t-dkg-io.hh t-dkg-io.cc t-dkg-addrevoker.cc
y_dkg_attest_test_CPPFLAGS = -DDKGPG_TESTSUITE_Y -I$(top_srcdir)/src\
 @LIBTMCG_CFLAGS@ @LIBGCRYPT_CFLAGS@ @GPG_ERROR_CFLAGS@ @LIBGMP_CFLAGS@
y_dkg_attest_test_SOURCES = t-dkg-tcpip-common.hh t-dkg-tcpip-common.cc\
 t-dkg-gnunet-common.hh t-dkg-gnunet-common.cc t-dkg-common.hh t-dkg-common.cc\
 t-dkg-io.hh t-dkg-io.cc t-dkg-attest.cc

# tests for timestamping
ts_dkg_generate_test_CPPFLAGS = -DDKGPG_TESTSUITE_TS -I$(top_srcdir)/src\
 @LIBTMCG_CFLAGS@ @LIBGCRYPT_CFLAGS@ @GPG_ERROR_CFLAGS@ @LIBGMP_CFLAGS@
ts_dkg_generate_test_SOURCES = t-dkg-tcpip-common.hh t-dkg-tcpip-common.cc\
 t-dkg-gnunet-common.hh t-dkg-gnunet-common.cc t-dkg-common.hh t-dkg-common.cc\
 t-dkg-io.hh t-dkg-io.cc t-dkg-generate.cc
ts_dkg_timestamp_test_SOURCES = t-dkg-tcpip-common.hh t-dkg-tcpip-common.cc\
 t-dkg-gnunet-common.hh t-dkg-gnunet-common.cc t-dkg-common.hh t-dkg-common.cc\
 t-dkg-io.hh t-dkg-io.cc t-dkg-timestamp.cc
ts_dkg_timestamp_verify_test_SOURCES = t-dkg-io.hh t-dkg-io.cc\
 t-dkg-timestamp-verify.cc

