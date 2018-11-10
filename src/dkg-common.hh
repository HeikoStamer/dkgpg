/*******************************************************************************
   This file is part of Distributed Privacy Guard (DKGPG).

 Copyright (C) 2017, 2018  Heiko Stamer <HeikoStamer@gmx.net>

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

	#include <libTMCG.hh>
	#include <aiounicast_select.hh>

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
		(const time_t sigtime,
		 const size_t whoami,
		 const size_t peers,
		 const int opt_verbose,
		 CachinKursawePetzoldShoupRBC *rbc);
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
		 const char *opt_y = NULL,
		 CanettiGennaroJareckiKrawczykRabinDSS *dss = NULL,
		 aiounicast_select *aiou = NULL,
		 CachinKursawePetzoldShoupRBC *rbc = NULL);

#endif

