/*******************************************************************************
   This file is part of Distributed Privacy Guard (DKGPG).

 Copyright (C) 2018  Heiko Stamer <HeikoStamer@gmx.net>

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

// include headers
#ifdef HAVE_CONFIG_H
	#include "dkgpg_config.h"
#endif

#include <vector>
#include <map>
#include <string>
#include <algorithm>
#include <ctime>

#include <libTMCG.hh>
#include "dkg-io.hh"

int main
	(int argc, char **argv)
{
	static const char *usage = "dkg-timestamp-verify [OPTIONS] KEYFILE";
	static const char *about = PACKAGE_STRING " " PACKAGE_URL;
	static const char *version = PACKAGE_VERSION " (" PACKAGE_NAME ")";

	std::string	filename, kfilename, sfilename;
	int 		opt_verbose = 0;
	bool		opt_binary = false, opt_weak = false;
	char		*opt_sigfrom = NULL, *opt_sigto = NULL;
	char		*opt_k = NULL;
	char		*opt_s = NULL;
	std::string	sigfrom_str, sigto_str;
	struct tm	sigfrom_tm = { 0 }, sigto_tm = { 0 };
	time_t		sigfrom = 1535000000, sigto = time(NULL);

	// parse command line arguments
	for (size_t i = 0; i < (size_t)(argc - 1); i++)
	{
		std::string arg = argv[i+1];
		if (arg.find("-f") == 0)
		{
			size_t idx = ++i;
			if ((idx < (size_t)(argc - 1)) && (opt_sigfrom == NULL))
			{
				sigfrom_str = argv[i+1];
				opt_sigfrom = (char*)sigfrom_str.c_str();
			}
			else
			{
				std::cerr << "ERROR: bad option \"" << arg << "\" found" <<
					std::endl;
				return -1;
			}
			continue;
		}
		else if (arg.find("-t") == 0)
		{
			size_t idx = ++i;
			if ((idx < (size_t)(argc - 1)) && (opt_sigto == NULL))
			{
				sigto_str = argv[i+1];
				opt_sigto = (char*)sigto_str.c_str();
			}
			else
			{
				std::cerr << "ERROR: bad option \"" << arg << "\" found" <<
					std::endl;
				return -1;
			}
			continue;
		}
		else if (arg.find("-k") == 0)
		{
			size_t idx = ++i;
			if ((idx < (size_t)(argc - 1)) && (opt_k == NULL))
			{
				kfilename = argv[i+1];
				opt_k = (char*)kfilename.c_str();
			}
			else
			{
				std::cerr << "ERROR: bad option \"" << arg << "\" found" <<
					std::endl;
				return -1;
			}
			continue;
		}
		else if (arg.find("-s") == 0)
		{
			size_t idx = ++i;
			if ((idx < (size_t)(argc - 1)) && (opt_s == NULL))
			{
				sfilename = argv[i+1];
				opt_s = (char*)sfilename.c_str();
			}
			else
			{
				std::cerr << "ERROR: bad option \"" << arg << "\" found" <<
					std::endl;
				return -1;
			}
			continue;
		}
		else if ((arg.find("--") == 0) || (arg.find("-b") == 0) ||
				 (arg.find("-v") == 0) || (arg.find("-h") == 0) ||
				 (arg.find("-V") == 0) || (arg.find("-w") == 0))
		{
			if ((arg.find("-h") == 0) || (arg.find("--help") == 0))
			{
				std::cout << usage << std::endl;
				std::cout << about << std::endl;
				std::cout << "Arguments mandatory for long options are also" <<
					" mandatory for short options." << std::endl;
				std::cout << "  -b, --binary   consider KEYFILE and FILENAME" <<
					" as binary input" << std::endl;
				std::cout << "  -f TIMESPEC    signature made before given" <<
					" TIMESPEC is not valid" << std::endl;
				std::cout << "  -h, --help     print this help" << std::endl;
				std::cout << "  -k FILENAME    use keyring FILENAME" <<
					" containing external revocation keys" << std::endl;
				std::cout << "  -s FILENAME    read signature from FILENAME" <<
					" instead of STDIN" << std::endl; 
				std::cout << "  -t TIMESPEC    signature made after given" <<
					" TIMESPEC is not valid" << std::endl;
				std::cout << "  -v, --version  print the version number" <<
					std::endl;
				std::cout << "  -V, --verbose  turn on verbose output" <<
					std::endl;
				std::cout << "  -w, --weak     allow weak or expired keys" <<
					std::endl;
				return 0; // not continue
			}
			if ((arg.find("-b") == 0) || (arg.find("--binary") == 0))
				opt_binary = true;
			if ((arg.find("-v") == 0) || (arg.find("--version") == 0))
			{
				std::cout << "dkg-timestamp-verify v" << version << std::endl;
				return 0; // not continue
			}
			if ((arg.find("-V") == 0) || (arg.find("--verbose") == 0))
				opt_verbose++; // increase verbosity
			if ((arg.find("-w") == 0) || (arg.find("--weak") == 0))
				opt_weak = true;
			continue;
		}
		else if (arg.find("-") == 0)
		{
			std::cerr << "ERROR: unknown option \"" << arg << "\"" << std::endl;
			return -1;
		}
		filename = arg;
	}
#ifdef DKGPG_TESTSUITE
	filename = "Test1_dkg-pub.asc";
	sfilename = "Test1_output_timestamp.sig";
	opt_s = (char*)sfilename.c_str();
	opt_verbose = 2;
#else
#ifdef DKGPG_TESTSUITE_Y
	filename = "TestY-pub.asc";
	sfilename = "TestY_output_timestamp.sig";
	opt_s = (char*)sfilename.c_str();
	opt_verbose = 2;
#endif
#endif
	// check command line arguments
	if ((opt_k == NULL) && (filename.length() == 0))
	{
		std::cerr << "ERROR: argument KEYFILE missing; usage: " << usage <<
			std::endl;
		return -1;
	}
	if (opt_sigfrom)
	{
		strptime(opt_sigfrom, "%Y-%m-%d_%H:%M:%S", &sigfrom_tm);
		sigfrom = mktime(&sigfrom_tm);
		if (sigfrom == ((time_t) -1))
		{
			perror("ERROR: dkg-timestamp-verify (mktime)");
			std::cerr << "ERROR: cannot convert TIMESPEC; required format:" <<
				" YYYY-MM-DD_HH:MM:SS" << std::endl;
			return -1;
		}
	}
	if (opt_sigto)
	{
		strptime(opt_sigto, "%Y-%m-%d_%H:%M:%S", &sigto_tm);
		sigto = mktime(&sigto_tm);
		if (sigto == ((time_t) -1))
		{
			perror("ERROR: dkg-timestamp-verify (mktime)");
			std::cerr << "ERROR: cannot convert TIMESPEC; required format:" <<
				" YYYY-MM-DD_HH:MM:SS" << std::endl;
			return -1;
		}
	}

	// initialize LibTMCG
	if (!init_libTMCG())
	{
		std::cerr << "ERROR: initialization of LibTMCG failed" << std::endl;
		return -1;
	}
	if (opt_verbose)
		std::cerr << "INFO: using LibTMCG version " << version_libTMCG() <<
			std::endl;

	// read the public key from KEYFILE
	std::string armored_pubkey;
	if (filename.length() > 0)
	{
		if (opt_binary && !read_binary_key_file(filename,
			TMCG_OPENPGP_ARMOR_PUBLIC_KEY_BLOCK, armored_pubkey))
			return -1;
		if (!opt_binary && !read_key_file(filename, armored_pubkey))
			return -1;
	}

	// read the keyring
	std::string armored_pubring;
	if ((opt_k != NULL) && opt_binary && !read_binary_key_file(kfilename,
			TMCG_OPENPGP_ARMOR_PUBLIC_KEY_BLOCK, armored_pubring))
		return -1;
	if ((opt_k != NULL) && !opt_binary && !read_key_file(kfilename,
			armored_pubring))
		return -1;

	// read the signature from stdin or from file
	std::string armored_signature;
	if (opt_s != NULL)
	{
		if (!opt_binary && !read_message(sfilename, armored_signature))
			return -1;
		if (opt_binary && !read_binary_signature(sfilename, armored_signature))
			return -1;
	}
	else
	{
		char c;
		while (std::cin.get(c))
			armored_signature += c;
		std::cin.clear();
	}

	// parse the signature
	TMCG_OpenPGP_Signature *signature = NULL;
	bool parse_ok = CallasDonnerhackeFinneyShawThayerRFC4880::
		SignatureParse(armored_signature, opt_verbose, signature);
	if (parse_ok)
	{
		if ((signature->type != TMCG_OPENPGP_SIGNATURE_TIMESTAMP) &&
			(signature->type != TMCG_OPENPGP_SIGNATURE_STANDALONE))
		{
			std::cerr << "ERROR: wrong signature type " <<
				(int)signature->type << " found" << std::endl;
			delete signature;
			return -1;
		}
		// extract embedded target signature
// TODO
	}
	else
	{
		std::cerr << "ERROR: cannot parse resp. use the provided signature" <<
			std::endl;
		return -1;
	}
	if (opt_verbose)
		signature->PrintInfo();

	// parse the keyring, the public key block and corresponding signatures
	TMCG_OpenPGP_Pubkey *primary = NULL;
	TMCG_OpenPGP_Keyring *ring = NULL;
	if (opt_k)
	{
		parse_ok = CallasDonnerhackeFinneyShawThayerRFC4880::
			PublicKeyringParse(armored_pubring, opt_verbose, ring);
		if (!parse_ok)
		{
			std::cerr << "WARNING: cannot use the given keyring" << std::endl;
			ring = new TMCG_OpenPGP_Keyring(); // create an empty keyring
		}
	}
	else
		ring = new TMCG_OpenPGP_Keyring(); // create an empty keyring
	if (filename.length() == 0)
	{
		// extract the public key from keyring based on issuer_fingerprint
		std::string fpr;
		CallasDonnerhackeFinneyShawThayerRFC4880::
			FingerprintConvertPlain(signature->issuerfpr, fpr);
		if (opt_verbose > 1)
			std::cerr << "INFO: lookup for issuer public key with" <<
				" fingerprint " << fpr << std::endl;
		const TMCG_OpenPGP_Pubkey *key = ring->find(fpr);
		if (key == NULL)
		{
			// try to extract the public key from keyring based on issuer
			std::string kid;
			CallasDonnerhackeFinneyShawThayerRFC4880::
				KeyidConvert(signature->issuer, kid);
			if (opt_verbose > 1)
				std::cerr << "INFO: lookup for issuer public key with" <<
					" keyid " << kid << std::endl;
			key = ring->find_by_keyid(kid);
			if (key == NULL)
			{
				std::cerr << "ERROR: issuer public key not found in keyring" <<
					std::endl; 
				delete ring;
				delete signature;
				return -1;
			}
		}
		tmcg_openpgp_octets_t pkts;
		key->Export(pkts);
		CallasDonnerhackeFinneyShawThayerRFC4880::
			ArmorEncode(TMCG_OPENPGP_ARMOR_PUBLIC_KEY_BLOCK, pkts,
				armored_pubkey);
	}
	parse_ok = CallasDonnerhackeFinneyShawThayerRFC4880::
		PublicKeyBlockParse(armored_pubkey, opt_verbose, primary);
	if (parse_ok)
	{
		primary->CheckSelfSignatures(ring, opt_verbose);
		if (!primary->valid && !opt_weak)
		{
			std::cerr << "ERROR: primary key is not valid" << std::endl;
			delete primary;
			delete ring;
			delete signature;
			return -1;
		}
		primary->CheckSubkeys(ring, opt_verbose);
		if (!opt_weak)
			primary->Reduce(); // keep only valid subkeys
		if (primary->weak(opt_verbose) && !opt_weak)
		{
			std::cerr << "ERROR: weak primary key is not allowed" << std::endl;
			delete primary;
			delete ring;
			delete signature;
			return -1;
		}
	}
	else
	{
		std::cerr << "ERROR: cannot use the provided public key" << std::endl;
		delete ring;
		delete signature;
		return -1;
	}

	// select corresponding public key of the issuer from subkeys
	bool subkey_selected = false;
	size_t subkey_idx = 0, keyusage = 0;
	time_t ckeytime = 0, ekeytime = 0;
	for (size_t j = 0; j < primary->subkeys.size(); j++)
	{
		if (((primary->subkeys[j]->AccumulateFlags() & 0x02) == 0x02) ||
		    (!primary->subkeys[j]->AccumulateFlags() &&
			((primary->subkeys[j]->pkalgo == TMCG_OPENPGP_PKALGO_RSA) || 
			(primary->subkeys[j]->pkalgo == TMCG_OPENPGP_PKALGO_RSA_SIGN_ONLY) ||
			(primary->subkeys[j]->pkalgo == TMCG_OPENPGP_PKALGO_DSA) ||
			(primary->subkeys[j]->pkalgo == TMCG_OPENPGP_PKALGO_ECDSA))))
		{
			if (CallasDonnerhackeFinneyShawThayerRFC4880::
				OctetsCompare(signature->issuer, primary->subkeys[j]->id))
			{
				subkey_selected = true;
				subkey_idx = j;
				keyusage = primary->subkeys[j]->AccumulateFlags();
				ckeytime = primary->subkeys[j]->creationtime;
				ekeytime = primary->subkeys[j]->expirationtime;
				break;
			}
		}
	}

	// check the primary key, if no admissible subkey has been selected
	if (!subkey_selected)
	{

		if (((primary->AccumulateFlags() & 0x02) != 0x02) &&
		    (!primary->AccumulateFlags() &&
			(primary->pkalgo != TMCG_OPENPGP_PKALGO_RSA) &&
			(primary->pkalgo != TMCG_OPENPGP_PKALGO_RSA_SIGN_ONLY) &&
			(primary->pkalgo != TMCG_OPENPGP_PKALGO_DSA) &&
			(primary->pkalgo != TMCG_OPENPGP_PKALGO_ECDSA)))
		{
			std::cerr << "ERROR: no admissible public key found" << std::endl;
			delete signature;
			delete primary;
			delete ring;
			return -1;
		}
		if (!CallasDonnerhackeFinneyShawThayerRFC4880::
			OctetsCompare(signature->issuer, primary->id))
		{
			std::cerr << "ERROR: no admissible public key found" << std::endl;
			delete signature;
			delete primary;
			delete ring;
			return -1;
		}
		keyusage = primary->AccumulateFlags();
		ckeytime = primary->creationtime;
		ekeytime = primary->expirationtime;
	}

	// additional validity checks on key and signature
	time_t current_time = time(NULL);
	// 1. key validity time (signatures made before key creation or
	//    after key expiry are not valid)
	if (signature->creationtime < ckeytime)
	{
		std::cerr << "ERROR: signature was made before key creation" <<
			std::endl;
		delete signature;
		delete primary;
		delete ring;
		return -2;
	}
	if (ekeytime && (signature->creationtime > (ckeytime + ekeytime)))
	{
		std::cerr << "ERROR: signature was made after key expiry" << std::endl;
		delete signature;
		delete primary;
		delete ring;
		return -2;
	}
	// 2. signature validity time (expired signatures are not valid)
	if (signature->expirationtime &&
		(current_time > (signature->creationtime + signature->expirationtime)))
	{
		std::cerr << "ERROR: signature is expired" << std::endl;
		delete signature;
		delete primary;
		delete ring;
		return -2;
	}
	// 3. key usage flags (signatures made by keys not with the "signing"
	//    capability are not valid)
	if (!opt_weak && ((keyusage & 0x02) != 0x02))
	{
		std::cerr << "ERROR: corresponding key was not intented for signing" <<
			std::endl;
		delete signature;
		delete primary;
		delete ring;
		return -2;
	}
	// 4. key validity time (expired keys are not valid)
	if (!opt_weak && ekeytime && (current_time > (ckeytime + ekeytime)))
	{
		std::cerr << "ERROR: corresponding key is expired" << std::endl;
		delete signature;
		delete primary;
		delete ring;
		return -2;
	}
	// 5. signature time (signatures made before the sigfrom or after the sigto
	//    timespec are not valid)
	if (signature->creationtime < sigfrom)
	{
		std::cerr << "ERROR: signature was made before given TIMESPEC" <<
			std::endl;
		delete signature;
		delete primary;
		delete ring;
		return -2;
	}
	if (signature->creationtime > sigto)
	{
		std::cerr << "ERROR: signature was made after given TIMESPEC" <<
			std::endl;
		delete signature;
		delete primary;
		delete ring;
		return -2;
	}

	// verify signature cryptographically
	bool verify_ok = false;
	if (subkey_selected)
		verify_ok = signature->Verify(primary->subkeys[subkey_idx]->key,
			opt_verbose);
	else
		verify_ok = signature->Verify(primary->key, opt_verbose);

	// check validity of embedded target signature, cf. [RFC 3628]
// TODO

	// output extracted target signature for further processing
	if (verify_ok)
	{
// TODO
	}

	// release signature
	delete signature;

	// release primary key and keyring
	delete primary;
	delete ring;

	if (!verify_ok)
	{
		if (opt_verbose)
			std::cerr << "INFO: Bad signature" << std::endl;
		return -3;
	}
	else
	{
		if (opt_verbose)
			std::cerr << "INFO: Good signature" << std::endl;
	}
	return 0;
}

