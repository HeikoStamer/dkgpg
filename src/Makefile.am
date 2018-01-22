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


AM_CPPFLAGS = @LIBTMCG_CFLAGS@ @LIBGCRYPT_CFLAGS@ @GPG_ERROR_CFLAGS@ @LIBGMP_CFLAGS@ @GNUNET_CFLAGS@
LDADD = @LIBTMCG_LIBS@ @LIBGCRYPT_LIBS@ @GPG_ERROR_LIBS@ @LIBGMP_LIBS@ @GNUNET_LIBS@

bin_PROGRAMS = dkg-gencrs dkg-generate dkg-encrypt dkg-decrypt dkg-sign dkg-revoke dkg-keyinfo dkg-refresh dkg-verify dkg-keycheck dkg-keysign

dist_man_MANS = dkg-generate.1 dkg-encrypt.1 dkg-decrypt.1 dkg-sign.1 dkg-revoke.1 dkg-verify.1 dkg-keysign.1

dkg_gencrs_SOURCES = dkg-gencrs.cc
dkg_gencrs_LDADD = @LIBTMCG_LIBS@ @LIBGCRYPT_LIBS@ @GPG_ERROR_LIBS@ @LIBGMP_LIBS@
dkg_generate_SOURCES = dkg-tcpip-common.hh dkg-tcpip-common.cc dkg-gnunet-common.hh dkg-gnunet-common.cc dkg-common.hh dkg-common.cc dkg-generate.cc
dkg_encrypt_SOURCES = dkg-common.hh dkg-common.cc dkg-encrypt.cc
dkg_encrypt_LDADD = @LIBTMCG_LIBS@ @LIBGCRYPT_LIBS@ @GPG_ERROR_LIBS@ @LIBGMP_LIBS@
dkg_decrypt_SOURCES = dkg-tcpip-common.hh dkg-tcpip-common.cc dkg-gnunet-common.hh dkg-gnunet-common.cc dkg-common.hh dkg-common.cc dkg-decrypt.cc
dkg_sign_SOURCES = dkg-tcpip-common.hh dkg-tcpip-common.cc dkg-gnunet-common.hh dkg-gnunet-common.cc dkg-common.hh dkg-common.cc dkg-sign.cc
dkg_revoke_SOURCES = dkg-tcpip-common.hh dkg-tcpip-common.cc dkg-gnunet-common.hh dkg-gnunet-common.cc dkg-common.hh dkg-common.cc dkg-revoke.cc
dkg_keyinfo_SOURCES = dkg-common.hh dkg-common.cc dkg-keyinfo.cc
dkg_keyinfo_LDADD = @LIBTMCG_LIBS@ @LIBGCRYPT_LIBS@ @GPG_ERROR_LIBS@ @LIBGMP_LIBS@
dkg_refresh_SOURCES = dkg-tcpip-common.hh dkg-tcpip-common.cc dkg-gnunet-common.hh dkg-gnunet-common.cc dkg-common.hh dkg-common.cc dkg-refresh.cc
dkg_verify_SOURCES = dkg-common.hh dkg-common.cc dkg-verify.cc
dkg_verify_LDADD = @LIBTMCG_LIBS@ @LIBGCRYPT_LIBS@ @GPG_ERROR_LIBS@ @LIBGMP_LIBS@
dkg_keycheck_SOURCES = dkg-common.hh dkg-common.cc dkg-keycheck.cc
dkg_keycheck_LDADD = @LIBTMCG_LIBS@ @LIBGCRYPT_LIBS@ @GPG_ERROR_LIBS@ @LIBGMP_LIBS@
dkg_keysign_SOURCES = dkg-tcpip-common.hh dkg-tcpip-common.cc dkg-gnunet-common.hh dkg-gnunet-common.cc dkg-common.hh dkg-common.cc dkg-keysign.cc

