/*******************************************************************************
   This file is part of Distributed Privacy Guard (DKGPG).

 Copyright (C) 2020  Heiko Stamer <HeikoStamer@gmx.net>

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

#ifndef INCLUDED_dkg_openpgp_HH
	#define INCLUDED_dkg_openpgp_HH

	// include headers
	#include <string>
	#include <iostream>
	#include <vector>
	#include <ctime>
	
	#include <zlib.h>
#ifdef LIBBZ
	#include <bzlib.h>
#endif

	#include <libTMCG.hh>

	bool verify_signature
		(const tmcg_openpgp_octets_t &data,
		 const std::string &armored_pubkey,
		 const TMCG_OpenPGP_Signature *signature,
		 const TMCG_OpenPGP_Keyring *ring,
		 const int opt_verbose,
		 const bool opt_weak = false,
		 const bool opt_broken = false);
	bool encrypt_session_key
		(const TMCG_OpenPGP_Subkey* sub,
		 const tmcg_openpgp_secure_octets_t &seskey,
		 const tmcg_openpgp_octets_t &subkeyid,
		 tmcg_openpgp_octets_t &out);
	bool encrypt_session_key
		(const TMCG_OpenPGP_Pubkey* pub,
		 const tmcg_openpgp_secure_octets_t &seskey,
		 const tmcg_openpgp_octets_t &keyid,
		 tmcg_openpgp_octets_t &out);
	gcry_error_t encrypt_kek
		(const tmcg_openpgp_octets_t &kek,
		 const tmcg_openpgp_skalgo_t algo,
		 const tmcg_openpgp_secure_octets_t &key,
		 tmcg_openpgp_octets_t &out);
	bool decrypt_session_key
		(const gcry_mpi_t p,
		 const gcry_mpi_t g,
		 const gcry_mpi_t y,
		 const gcry_mpi_t gk,
		 const gcry_mpi_t myk,
		 tmcg_openpgp_secure_octets_t &out);
	bool check_esk
		(const TMCG_OpenPGP_PKESK* esk,
		 const TMCG_OpenPGP_PrivateSubkey* ssb,
		 const int opt_verbose);
	gcry_error_t decrypt_kek
		(const tmcg_openpgp_octets_t &kek,
		 const tmcg_openpgp_skalgo_t algo,
		 const tmcg_openpgp_secure_octets_t &key,
		 tmcg_openpgp_secure_octets_t &out);
	bool decrypt_session_key
		(const TMCG_OpenPGP_Message* msg,
		 tmcg_openpgp_secure_octets_t &seskey,
		 const int opt_verbose,
		 const std::vector<std::string> &opt_with_password);
	bool decrypt_session_key
		(const TMCG_OpenPGP_Message* msg,
		 tmcg_openpgp_secure_octets_t &seskey,
		 const int opt_verbose,
		 const bool opt_E);
	bool decompress_libz
		(const TMCG_OpenPGP_Message* msg,
		 tmcg_openpgp_octets_t &infmsg,
		 const int opt_verbose);
	bool decompress_libbz
		(const TMCG_OpenPGP_Message* msg,
		 tmcg_openpgp_octets_t &infmsg,
		 const int opt_verbose);
#endif

