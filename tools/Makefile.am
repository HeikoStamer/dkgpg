# Copyright (C) 2019  Heiko Stamer <HeikoStamer@gmx.net>
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


AM_CPPFLAGS = -I$(top_srcdir)/src @LIBTMCG_CFLAGS@ @LIBGCRYPT_CFLAGS@\
 @GPG_ERROR_CFLAGS@ @LIBGMP_CFLAGS@
LDADD = @LIBTMCG_LIBS@ @LIBGCRYPT_LIBS@ @GPG_ERROR_LIBS@ @LIBGMP_LIBS@

noinst_PROGRAMS = dkg-fuzzer
bin_PROGRAMS = dkg-sop

dkg_fuzzer_SOURCES = dkg-io.hh dkg-io.cc dkg-fuzzer.cc
dkg_sop_SOURCES = dkg-io.hh dkg-io.cc dkg-sop.cc

