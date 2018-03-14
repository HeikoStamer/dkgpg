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

// include headers
#ifdef HAVE_CONFIG_H
	#include "dkgpg_config.h"
#endif

#include <vector>
#include <string>

#include <libTMCG.hh>
#include "dkg-io.hh"

int main
	(int argc, char **argv)
{
	static const char *usage = "dkg-encrypt [OPTIONS] KEYFILE";
	static const char *about = PACKAGE_STRING " " PACKAGE_URL;
	static const char *version = PACKAGE_VERSION " (" PACKAGE_NAME ")";

	std::string	kfilename, ifilename, ofilename, s;
	int		opt_verbose = 0;
	bool		opt_binary = false, opt_weak = false, opt_t = false;
	char		*opt_ifilename = NULL;
	char		*opt_ofilename = NULL;
	char		*opt_s = NULL;

	// parse argument list
	for (size_t i = 0; i < (size_t)(argc - 1); i++)
	{
		std::string arg = argv[i+1];
		// ignore options
		if ((arg.find("-i") == 0) || (arg.find("-o") == 0) || (arg.find("-s") == 0))
		{
			size_t idx = ++i;
			if ((arg.find("-i") == 0) && (idx < (size_t)(argc - 1)) && (opt_ifilename == NULL))
			{
				ifilename = argv[i+1];
				opt_ifilename = (char*)ifilename.c_str();
			}
			if ((arg.find("-o") == 0) && (idx < (size_t)(argc - 1)) && (opt_ofilename == NULL))
			{
				ofilename = argv[i+1];
				opt_ofilename = (char*)ofilename.c_str();
			}
			if ((arg.find("-s") == 0) && (idx < (size_t)(argc - 1)) && (opt_s == NULL))
			{
				s = argv[i+1];
				opt_s = (char*)s.c_str();
			}
			continue;
		}
		else if ((arg.find("--") == 0) || (arg.find("-b") == 0)  || (arg.find("-v") == 0) || 
			 (arg.find("-h") == 0) || (arg.find("-V") == 0) || (arg.find("-w") == 0) ||
			 (arg.find("-t") == 0))
		{
			if ((arg.find("-h") == 0) || (arg.find("--help") == 0))
			{
				std::cout << usage << std::endl;
				std::cout << about << std::endl;
				std::cout << "Arguments mandatory for long options are also mandatory for short options." << std::endl;
				std::cout << "  -b, --binary        write encrypted message in binary format (only if -i)" << std::endl;
				std::cout << "  -h, --help          print this help" << std::endl;
				std::cout << "  -i FILENAME         read message rather from FILENAME than STDIN" << std::endl;
				std::cout << "  -o FILENAME         write encrypted message rather to FILENAME than STDOUT" << std::endl;
				std::cout << "  -s STRING           select only encryption-capable subkeys containing STRING" << std::endl;
				std::cout << "  -t, --throw-keyids  throw included key IDs for somewhat improved privacy" << std::endl;
				std::cout << "  -v, --version       print the version number" << std::endl;
				std::cout << "  -V, --verbose       turn on verbose output" << std::endl;
				std::cout << "  -w, --weak          allow weak keys" << std::endl;
				return 0; // not continue
			}
			if ((arg.find("-b") == 0) || (arg.find("--binary") == 0))
				opt_binary = true;
			if ((arg.find("-t") == 0) || (arg.find("--throw-keyids") == 0))
				opt_t = true;
			if ((arg.find("-v") == 0) || (arg.find("--version") == 0))
			{
				std::cout << "dkg-encrypt v" << version << std::endl;
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
		kfilename = arg;
	}
#ifdef DKGPG_TESTSUITE
	kfilename = "Test1_dkg-pub.asc";
	opt_binary = true;
	ofilename = "Test1_output.bin";
	opt_ofilename = (char*)ofilename.c_str();
	opt_verbose = 1;
#endif

	// check command line arguments
	if (kfilename.length() == 0)
	{
		std::cerr << "ERROR: argument KEYFILE is missing; usage: " << usage << std::endl;
		return -1;
	}

	// initialize LibTMCG
	if (!init_libTMCG())
	{
		std::cerr << "ERROR: initialization of LibTMCG failed" << std::endl;
		return -1;
	}
	if (opt_verbose)
		std::cerr << "INFO: using LibTMCG version " << version_libTMCG() << std::endl;

	// read the public key
	std::string armored_pubkey;
	if (!read_key_file(kfilename, armored_pubkey))
		return -1;

	// parse the public key block and corresponding signatures
	TMCG_OpenPGP_Pubkey *primary = NULL;
	bool parse_ok = CallasDonnerhackeFinneyShawThayerRFC4880::
		PublicKeyBlockParse(armored_pubkey, opt_verbose, primary);
	if (parse_ok)
	{
		primary->CheckSelfSignatures(opt_verbose);
		if (!primary->valid)
		{
			std::cerr << "ERROR: primary key is not valid" << std::endl;
			delete primary;
			return -1;
		}
		primary->CheckSubkeys(opt_verbose);
		primary->Reduce(); // keep only valid subkeys
		if (primary->weak(opt_verbose) && !opt_weak)
		{
			std::cerr << "ERROR: weak primary key is not allowed" << std::endl;
			delete primary;
			return -1;
		}
	}
	else
	{
		std::cerr << "ERROR: cannot use the provided public key" << std::endl;
		if (primary)
			delete primary;
		return -1;
	}

	// select encryption-capable subkeys
	std::vector<TMCG_OpenPGP_Subkey*> selected;
	for (size_t j = 0; j < primary->subkeys.size(); j++)
	{
		// subkey not selected?
		std::string kid;
		CallasDonnerhackeFinneyShawThayerRFC4880::KeyidCompute(primary->subkeys[j]->sub_hashing, kid);
		if (opt_s && (kid.find(s) == kid.npos))
			continue;
		// encryption-capable subkey?
		if (((primary->subkeys[j]->AccumulateFlags() & 0x04) == 0x04) ||
		    ((primary->subkeys[j]->AccumulateFlags() & 0x08) == 0x08) ||
		    (!primary->subkeys[j]->AccumulateFlags() && ((primary->subkeys[j]->pkalgo == TMCG_OPENPGP_PKALGO_RSA) || 
				(primary->subkeys[j]->pkalgo == TMCG_OPENPGP_PKALGO_RSA_ENCRYPT_ONLY) || (primary->subkeys[j]->pkalgo == TMCG_OPENPGP_PKALGO_ELGAMAL))))
		{
			if (primary->subkeys[j]->weak(opt_verbose) && !opt_weak)
			{
				if (opt_verbose)
					std::cerr << "WARNING: weak subkey for encryption ignored" << std::endl;
			}
			else if ((primary->subkeys[j]->pkalgo != TMCG_OPENPGP_PKALGO_RSA) &&
			         (primary->subkeys[j]->pkalgo != TMCG_OPENPGP_PKALGO_RSA_ENCRYPT_ONLY) &&
			         (primary->subkeys[j]->pkalgo != TMCG_OPENPGP_PKALGO_ELGAMAL))
			{
				if (opt_verbose)
					std::cerr << "WARNING: subkey with unsupported public-key algorithm for encryption ignored" << std::endl;
			}
			else
			{
				selected.push_back(primary->subkeys[j]);
				if ((std::find(primary->subkeys[j]->psa.begin(), primary->subkeys[j]->psa.end(), 9) == primary->subkeys[j]->psa.end()) &&
				    (std::find(primary->psa.begin(), primary->psa.end(), 9) == primary->psa.end()))
				{
					if (opt_verbose)
						std::cerr << "WARNING: AES-256 is none of the preferred symmetric algorithms" << std::endl;
				}
				if (((primary->subkeys[j]->AccumulateFeatures() & 0x01) != 0x01) &&
				    ((primary->AccumulateFeatures() & 0x01) != 0x01))
				{
					if (opt_verbose)
						std::cerr << "WARNING: recipient does not state support for modification detection (MDC)" << std::endl;
				}
			}
		}
	}

	// check the primary key, if no encryption-capable subkeys have been selected
	if (!selected.size())
	{	
		if (((primary->AccumulateFlags() & 0x04) != 0x04) &&
		    ((primary->AccumulateFlags() & 0x08) != 0x08) &&
		    (!primary->AccumulateFlags() && (primary->pkalgo != TMCG_OPENPGP_PKALGO_RSA) &&
			(primary->pkalgo != TMCG_OPENPGP_PKALGO_RSA_ENCRYPT_ONLY) && (primary->pkalgo != TMCG_OPENPGP_PKALGO_ELGAMAL)))
		{
			std::cerr << "ERROR: no encryption-capable public key found" << std::endl;
			delete primary;
			return -1;
		}
		if (std::find(primary->psa.begin(), primary->psa.end(), TMCG_OPENPGP_SKALGO_AES256) == primary->psa.end())
		{
			if (opt_verbose)
				std::cerr << "WARNING: AES-256 is none of the preferred symmetric algorithms" << std::endl;
		}
		if ((primary->AccumulateFeatures() & 0x01) != 0x01)
		{
			if (opt_verbose)
				std::cerr << "WARNING: recipient does not state support for modification detection (MDC)" << std::endl;
		}
	}

	// read message from stdin or file
	tmcg_openpgp_octets_t msg;
#ifdef DKGPG_TESTSUITE
	std::string test_msg = "This is just a simple test message.";
	for (size_t i = 0; i < test_msg.length(); i++)
		msg.push_back(test_msg[i]);
#else
	if (opt_ifilename != NULL)
	{
		std::string input_msg;
		if (!read_message(opt_ifilename, input_msg))
		{
			delete primary;
			return -1;
		}
		for (size_t i = 0; i < input_msg.length(); i++)
			msg.push_back(input_msg[i]);
	}
	else
	{
		char c;
		while (std::cin.get(c))
			msg.push_back(c);
		std::cin.clear();
	}
#endif

	// encrypt the provided message
	gcry_error_t ret;
	tmcg_openpgp_octets_t lit, seskey, prefix, enc, mdc_hashing, hash, mdc, seipd;
	CallasDonnerhackeFinneyShawThayerRFC4880::PacketLitEncode(msg, lit);
	ret = CallasDonnerhackeFinneyShawThayerRFC4880::SymmetricEncryptAES256(lit, seskey, prefix, true, enc); // seskey and prefix only
	if (ret)
	{
		std::cerr << "ERROR: SymmetricEncryptAES256() failed (rc = " << gcry_err_code(ret) << ")" << std::endl;
		delete primary;
		return ret;
	}
	enc.clear();
	mdc_hashing.insert(mdc_hashing.end(), prefix.begin(), prefix.end()); // "it includes the prefix data described above" [RFC4880]
	mdc_hashing.insert(mdc_hashing.end(), lit.begin(), lit.end()); // "it includes all of the plaintext" [RFC4880]
	mdc_hashing.push_back(0xD3); // "and the also includes two octets of values 0xD3, 0x14" [RFC4880]
	mdc_hashing.push_back(0x14);
	hash.clear();
	CallasDonnerhackeFinneyShawThayerRFC4880::HashCompute(TMCG_OPENPGP_HASHALGO_SHA1, mdc_hashing, hash); // "passed through the SHA-1 hash function" [RFC4880]
	CallasDonnerhackeFinneyShawThayerRFC4880::PacketMdcEncode(hash, mdc);
	lit.insert(lit.end(), mdc.begin(), mdc.end()); // append Modification Detection Code packet
	seskey.clear(); // generate a fresh session key, but keep the previous prefix
	ret = CallasDonnerhackeFinneyShawThayerRFC4880::SymmetricEncryptAES256(lit, seskey, prefix, false, enc); // encryption of literal packet
	if (ret)
	{
		std::cerr << "ERROR: SymmetricEncryptAES256() failed (rc = " << gcry_err_code(ret) << ")" << std::endl;
		delete primary;
		return ret;
	}
	CallasDonnerhackeFinneyShawThayerRFC4880::PacketSeipdEncode(enc, seipd);

	// encrypt the session key (create PKESK packet)
	tmcg_openpgp_octets_t all;
	if (opt_verbose > 1)
		std::cerr << "INFO: " << selected.size() << " subkeys selected for encryption of session key" << std::endl;
	for (size_t j = 0; j < selected.size(); j++)
	{
		tmcg_openpgp_octets_t pkesk, subkeyid;
		if (opt_t)
		{
			// An implementation MAY accept or use a Key ID of zero as a "wild card"
			// or "speculative" Key ID. In this case, the receiving implementation
			// would try all available private keys, checking for a valid decrypted
			// session key. This format helps reduce traffic analysis of messages. [RFC4880]
			for (size_t i = 0; i < 8; i++)
				subkeyid.push_back(0x00);
		}
		else
			subkeyid.insert(subkeyid.end(), selected[j]->id.begin(), selected[j]->id.end());
		if ((selected[j]->pkalgo == TMCG_OPENPGP_PKALGO_RSA) ||
		    (selected[j]->pkalgo == TMCG_OPENPGP_PKALGO_RSA_ENCRYPT_ONLY))
		{
			gcry_mpi_t me;
			me = gcry_mpi_new(2048);
			ret = CallasDonnerhackeFinneyShawThayerRFC4880::AsymmetricEncryptRSA(seskey, selected[j]->key, me);
			if (ret)
			{
				std::cerr << "ERROR: AsymmetricEncryptRSA() failed (rc = " << gcry_err_code(ret) << ")" << std::endl;
				delete primary;
				return ret;
			}
			CallasDonnerhackeFinneyShawThayerRFC4880::PacketPkeskEncode(subkeyid, me, pkesk);
			gcry_mpi_release(me);
		}
		else if (selected[j]->pkalgo == TMCG_OPENPGP_PKALGO_ELGAMAL)
		{	
			// Note that OpenPGP ElGamal encryption in $Z^*_p$ provides only OW-CPA security under the CDH assumption. In
			// order to achieve at least IND-CPA (aka semantic) security under DDH assumption the encoded message $m$ must
			// be an element of the prime-order subgroup $G_q$ generated by $g$ (see algebraic structure of DKG).
			// Unfortunately, the probability that this happens is negligible, if the size of prime $q$ is much smaller
			// than the size of $p$. We cannot enforce $m\in G_q$ since $m$ is padded according to OpenPGP (PKCS#1).
			gcry_mpi_t gk, myk;
			gk = gcry_mpi_new(2048);
			myk = gcry_mpi_new(2048);
			ret = CallasDonnerhackeFinneyShawThayerRFC4880::AsymmetricEncryptElgamal(seskey, selected[j]->key, gk, myk);
			if (ret)
			{
				std::cerr << "ERROR: AsymmetricEncryptElgamal() failed (rc = " << gcry_err_code(ret) << ")" << std::endl;
				delete primary;
				return ret;
			}
			CallasDonnerhackeFinneyShawThayerRFC4880::PacketPkeskEncode(subkeyid, gk, myk, pkesk);
			gcry_mpi_release(gk);
			gcry_mpi_release(myk);
		}
		else
			std::cerr << "ERROR: public-key algorithm " << (int)selected[j]->pkalgo << " not supported" << std::endl;
		all.insert(all.end(), pkesk.begin(), pkesk.end());
	}
	if (!selected.size())
	{
		tmcg_openpgp_octets_t pkesk, keyid;
		if (opt_t)
		{
			// An implementation MAY accept or use a Key ID of zero as a "wild card"
			// or "speculative" Key ID. In this case, the receiving implementation
			// would try all available private keys, checking for a valid decrypted
			// session key. This format helps reduce traffic analysis of messages. [RFC4880]
			for (size_t i = 0; i < 8; i++)
				keyid.push_back(0x00);
		}
		else
			keyid.insert(keyid.end(), primary->id.begin(), primary->id.end()); 
		if ((primary->pkalgo == TMCG_OPENPGP_PKALGO_RSA) ||
		    (primary->pkalgo == TMCG_OPENPGP_PKALGO_RSA_ENCRYPT_ONLY))
		{
			gcry_mpi_t me;
			me = gcry_mpi_new(2048);
			ret = CallasDonnerhackeFinneyShawThayerRFC4880::AsymmetricEncryptRSA(seskey, primary->key, me);
			if (ret)
			{
				std::cerr << "ERROR: AsymmetricEncryptRSA() failed (rc = " << gcry_err_code(ret) << ")" << std::endl;
				delete primary;
				return ret;
			}
			CallasDonnerhackeFinneyShawThayerRFC4880::PacketPkeskEncode(keyid, me, pkesk);
			gcry_mpi_release(me);
		}
		else if (primary->pkalgo == TMCG_OPENPGP_PKALGO_ELGAMAL)
		{	
			// Note that OpenPGP ElGamal encryption in $Z^*_p$ provides only OW-CPA security under the CDH assumption. In
			// order to achieve at least IND-CPA (aka semantic) security under DDH assumption the encoded message $m$ must
			// be an element of the prime-order subgroup $G_q$ generated by $g$ (see algebraic structure of DKG).
			// Unfortunately, the probability that this happens is negligible, if the size of prime $q$ is much smaller
			// than the size of $p$. We cannot enforce $m\in G_q$ since $m$ is padded according to OpenPGP (PKCS#1).
			gcry_mpi_t gk, myk;
			gk = gcry_mpi_new(2048);
			myk = gcry_mpi_new(2048);
			ret = CallasDonnerhackeFinneyShawThayerRFC4880::AsymmetricEncryptElgamal(seskey, primary->key, gk, myk);
			if (ret)
			{
				std::cerr << "ERROR: AsymmetricEncryptElgamal() failed (rc = " << gcry_err_code(ret) << ")" << std::endl;
				delete primary;
				return ret;
			}
			CallasDonnerhackeFinneyShawThayerRFC4880::PacketPkeskEncode(keyid, gk, myk, pkesk);
			gcry_mpi_release(gk);
			gcry_mpi_release(myk);
		}
		else
		{
			std::cerr << "ERROR: public-key algorithm " << (int)primary->pkalgo << " not supported" << std::endl;
			delete primary;
			return -1;
		}
		all.insert(all.end(), pkesk.begin(), pkesk.end());
	}

	// concatenate SEIPD and encode the packages in ASCII armor and finally print result to stdout
	std::string armored_message;
	all.insert(all.end(), seipd.begin(), seipd.end());
	CallasDonnerhackeFinneyShawThayerRFC4880::ArmorEncode(TMCG_OPENPGP_ARMOR_MESSAGE, all, armored_message);

	// write out the result
	if (opt_ofilename != NULL)
	{
		if (opt_binary)
		{
			if (!write_message(opt_ofilename, all))
			{
				delete primary;
				return -1;
			}
		}
		else
		{
			if (!write_message(opt_ofilename, armored_message))
			{
				delete primary;
				return -1;
			}
		}
	}
	else
		std::cout << armored_message << std::endl;

	// release primary key structure
	delete primary;
	
	return 0;
}
