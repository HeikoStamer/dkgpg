/*******************************************************************************
   This file is part of Distributed Privacy Guard (DKGPG).

 Copyright (C) 2017, 2018, 2019  Heiko Stamer <HeikoStamer@gmx.net>

   DKGPG is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   DKGPG is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with DKGPG; if not, write to the Free Software
   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
*******************************************************************************/

#ifndef INCLUDED_dkg_common_HH
	#define INCLUDED_dkg_common_HH

	// include headers
	#include <string>
	#include <iostream>
	#include <sstream>
	#include <vector>
	#include <map>
	#include <algorithm>
	#include <cassert>
	#include <cstring>
	#include <ctime>
	#include <unistd.h>
	#include <errno.h>
	#include <sys/wait.h>

	#include <libTMCG.hh>
	#include <aiounicast_select.hh>

	// setup CRS (common reference string) |p| = 3072 bit, |q| = 256 bit
	static std::string crs = "fips-crs|etc0k13hu6mDWyye0MUepXvXJf1M6Uqt13"
		"mAyAEhJ292TMOxG5HilFlFaG2YUIXsPISxWKjZqBY0VO6YjF1DIGsIzQ6GK9"
		"Myk9MGSVxP44lfjVIodRRFk2anRLktvO2Kcq0Z6hP3yvQNmM0sl5JTvzrJLt"
		"WDk3B7W3D9WTEjLRqBw3ULUlQz1pVCQELXaUcz8AOZv5iGAec9Vyf2YyWA8L"
		"xvVZXcLEemvD7ompIVuQM1Baos9fXqs3AmegAKPZdEQUCU5LdTeNvLOq5J2c"
		"Yx4jWMqVJlOyDdlMtdOXzzz59m58atKxN9RG5npkNshxk7zDfd0NOM9wyFfT"
		"wfVakACyp1so0osIDPGtJgVSqCDf5f2KOMRHrScAayCkTSAaWiPn8fFAOuDT"
		"UGiZS9Sj8ftSvT3yo6MooyNVd6U90BwQE2OAuTe7GPLE8cBu7sGjOMK8bkXc"
		"TuSSnGeV77LEiRUyd2Egqrkz84arBDerBdZgONliQiTK1YjF4COMXDpLixuR"
		"iN|kNJC9FeFYk5xs7d0bwhA2xoxbrUPLMvalMXmHHD3wNn|PY8SlRuWwjTAV"
		"1e99wxssLrNXcRWTxIFoKIP5RAyZLqZGct2M3wXURqAmtagS6MDl7PPWQ3ju"
		"pFYHxkGtv2MwROsB9cQVHmH9xspZ9ERFAbE8qNtpLeHHMUqFD9S7GZi1QwuY"
		"ryqrlj8nhZCfAOaQLA08Z7Ki36wlGmTaY9iTIRy4cZkdSjOwxT5kOcp0Y0yg"
		"5sWo5M4vSOdQeVf92qzgmFYbL77OX3M0xwQkTTDy8ITrFlEJEBClAZmTMc55"
		"opm4bKb7tvrr07YtUknMX0IaRW7eBWUjmnAMx09bPjFpA9NWMorqqzvKnU02"
		"PRTGpuROhFVg64BXS2X8Oj7Y8aRsejljzjMz7fXOVpNfCXlUBNNgkkURvSOj"
		"vs55mHzqrkoup9f5Fma5zTRYpwD2YJSczEytU2wZaTLxQrMkwZhhpFDiuxC7"
		"7x7soBo1ynYtD8AJtWDYdkmU6bSxPBSYRXCOD3BJnvAApNogQQx49TG254ve"
		"asLh5kDXSllYkKqv3hJOFV6|sfrJREYoxAPXzCHLjNOyabkDzpQxlMul6wWe"
		"X4Zqu7dIjkWg5PdlTrPk8QIaMX2DWSttERDAfxUaWmtCFNxSjGUV3jb0H1fv"
		"0DjviPfHYQyVKOTHHjtkEopPAP8TvkQdVV4CWyTYZ0O2fwlEGOCMDZBbjGjn"
		"rfEOeptn08B3OwA9MYbCq958LTIdIta8b1KDnr2ckTKCbpTazJgq4LUrFOZC"
		"tKMk2ZlKXeN0X3iWb8oEG3JPE3kJGuzQQ44Wnx7ZzzLohDhGSUMgXULUezB8"
		"EUVnXpq7oIaYqjAachOTmaQpPSygbBWAhwnvRB2LhoJQpLNUzTgJ8vh4DALd"
		"u3gsuR7cthjS6vGqcq84aMJJ8ypoqA8wpEDenc9xjmZ4bc9EZCyZShSLeIyY"
		"ymv7CFgtuiCyjFUBXjfM928Tar27a4mDpAhluUoXa0O5VfV70e04LlnzgQ8w"
		"RtCqfaGcWesaHzPEk|8|DKGPGdkgpgDKGPGdkgpgDKGPGdkgpgDKGPGdkgpg"
		"DKGST|38|1k|";

	bool pqg_extract
		(std::string crs, const bool fips, const int opt_verbose,
		 mpz_ptr fips_p, mpz_ptr fips_q, mpz_ptr fips_g,
		 std::stringstream &crss);
	bool init_tDSS
		(const TMCG_OpenPGP_Prvkey *prv,
		 const int opt_verbose,
		 CanettiGennaroJareckiKrawczykRabinDSS* &dss);
	bool init_tElG
		(const TMCG_OpenPGP_PrivateSubkey *sub,
		 const int opt_verbose,
		 GennaroJareckiKrawczykRabinDKG* &dkg);
	bool verify_signature
		(const tmcg_openpgp_octets_t &data,
		 const std::string &armored_pubkey,
		 const TMCG_OpenPGP_Signature *signature,
		 const TMCG_OpenPGP_Keyring *ring,
		 const int opt_verbose,
		 const bool opt_weak = false);
	void xtest
		(const size_t num_xtests,
		 const size_t whoami,
		 const size_t peers,
		 CachinKursawePetzoldShoupRBC *rbc);
	time_t agree_time
		(const time_t mytime,
		 const size_t whoami,
		 const size_t peers,
		 const int opt_verbose,
		 CachinKursawePetzoldShoupRBC *rbc);
	bool select_hashalgo
		(CanettiGennaroJareckiKrawczykRabinDSS *dss,
		 tmcg_openpgp_hashalgo_t &hashalgo);
	bool sign_hash
		(const tmcg_openpgp_octets_t &hash,
		 const tmcg_openpgp_octets_t &trailer,
		 const tmcg_openpgp_octets_t &left,
		 const size_t whoami,
		 const size_t peers,
		 TMCG_OpenPGP_Prvkey *prv,
		 const tmcg_openpgp_hashalgo_t hashalgo,
		 tmcg_openpgp_octets_t &sig,
		 const int opt_verbose,
		 const bool opt_y = true,
		 CanettiGennaroJareckiKrawczykRabinDSS *dss = NULL,
		 aiounicast_select *aiou = NULL,
		 CachinKursawePetzoldShoupRBC *rbc = NULL);
	void canonicalize
		(std::vector<std::string> &plist);
	int wait_instance
		(const size_t whoami,
		 const int opt_verbose,
		 pid_t pid[DKGPG_MAX_N]);
	int run_localtest
		(const size_t peers,
		 const int opt_verbose,
		 pid_t pid[DKGPG_MAX_N],
		 int pipefd[DKGPG_MAX_N][DKGPG_MAX_N][2],
		 int self_pipefd[2],
		 int bpipefd[DKGPG_MAX_N][DKGPG_MAX_N][2],
		 int bself_pipefd[2],
		 void (*fork_instance)(const size_t));

#endif

