/*******************************************************************************
   This file is part of Distributed Privacy Guard (DKGPG).

 Copyright (C) 2018, 2019  Heiko Stamer <HeikoStamer@gmx.net>

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

#ifndef INCLUDED_dkg_io_HH
	#define INCLUDED_dkg_io_HH

	// include headers
	#include <string>
	#include <iostream>
	#include <sstream>
	#include <fstream>
	#include <vector>
	#include <map>
	#include <algorithm>
	#include <cassert>
	#include <cstring>
	#include <ctime>
	#include <unistd.h>
	#include <errno.h>
	#include <fcntl.h>
	#include <termios.h>
	#include <sys/mman.h>
	#include <sys/stat.h>
	#include <sys/types.h>

	#include <libTMCG.hh>

	bool get_passphrase
		(const std::string &prompt,
		 const bool echo,
		 tmcg_openpgp_secure_string_t &passphrase);
	bool read_key_file
		(const std::string &filename,
		 std::string &result);
	bool read_binary_key_file
		(const std::string &filename,
		 const tmcg_openpgp_armor_t type,
		 std::string &result);
	bool write_key_file
		(const std::string &filename,
		 const std::string &key);
	bool write_key_file
		(const std::string &filename,
		 const tmcg_openpgp_armor_t type,
		 const tmcg_openpgp_octets_t &key);
	bool check_strict_permissions
		(const std::string &filename);
	bool set_strict_permissions
		(const std::string &filename);
	bool create_strict_permissions
		(const std::string &filename);
	bool read_binary_signature
		(const std::string &filename,
		 std::string &result);
	bool read_message
		(const std::string &filename,
		 std::string &result);
	bool read_binary_message
		(const std::string &filename,
		 std::string &result);
	bool write_message
		(const std::string &filename,
		 const tmcg_openpgp_octets_t &msg);
	bool write_message
		(const std::string &filename,
		 const std::string &msg);
	bool lock_memory
		();
	bool unlock_memory
		();
	bool get_key_by_fingerprint
		(const TMCG_OpenPGP_Keyring *ring,
		 const std::string &fingerprint,
		 const int verbose,
		 std::string &armored_key);
	bool get_key_by_keyid
		(const TMCG_OpenPGP_Keyring *ring,
		 const std::string &keyid,
		 const int verbose,
		 std::string &armored_key);
	bool get_key_by_signature
		(const TMCG_OpenPGP_Keyring *ring,
		 const TMCG_OpenPGP_Signature *signature,
		 const int verbose,
		 std::string &armored_key);
#endif

