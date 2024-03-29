/*******************************************************************************
   This file is part of Distributed Privacy Guard (DKGPG).

 Copyright (C) 2017, 2018, 2019, 2020, 2022  Heiko Stamer <HeikoStamer@gmx.net>

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
#include "dkg-openpgp.hh"

int main
	(int argc, char **argv)
{
	static const char *usage = "dkg-encrypt [OPTIONS] [KEYSPEC]";
	static const char *about = PACKAGE_STRING " " PACKAGE_URL;
	static const char *version = PACKAGE_VERSION " (" PACKAGE_NAME ")";

	std::vector<std::string> keyspec;
	std::string	ifilename, ofilename, s, kfilename;
	int opt_verbose = 0;
	bool opt_binary = false, opt_weak = false, opt_t = false, opt_r = false;
	unsigned long int opt_a = 0;

	// parse argument list
	for (size_t i = 0; i < (size_t)(argc - 1); i++)
	{
		std::string arg = argv[i+1];
		// ignore options
		if ((arg.find("-i") == 0) || (arg.find("-o") == 0) ||
			(arg.find("-s") == 0) || (arg.find("-k") == 0) ||
			(arg.find("-a") == 0))
		{
			size_t idx = ++i;
			if ((arg.find("-i") == 0) && (idx < (size_t)(argc - 1)) &&
				(ifilename.length() == 0))
			{
				ifilename = argv[i+1];
			}
			if ((arg.find("-o") == 0) && (idx < (size_t)(argc - 1)) &&
				(ofilename.length() == 0))
			{
				ofilename = argv[i+1];
			}
			if ((arg.find("-s") == 0) && (idx < (size_t)(argc - 1)) &&
				(s.length() == 0))
			{
				s = argv[i+1];
			}
			if ((arg.find("-k") == 0) && (idx < (size_t)(argc - 1)) &&
				(kfilename.length() == 0))
			{
				kfilename = argv[i+1];
			}
			if ((arg.find("-a") == 0) && (idx < (size_t)(argc - 1)) &&
				(opt_a == 0))
			{
				opt_a = strtoul(argv[i+1], NULL, 10);
			}
			continue;
		}
		else if ((arg.find("--") == 0) || (arg.find("-b") == 0) ||
			(arg.find("-v") == 0) || (arg.find("-h") == 0) ||
			(arg.find("-V") == 0) || (arg.find("-w") == 0) ||
			(arg.find("-t") == 0) || (arg.find("-r") == 0))
		{
			if ((arg.find("-h") == 0) || (arg.find("--help") == 0))
			{
				std::cout << usage << std::endl;
				std::cout << about << std::endl;
				std::cout << "Arguments mandatory for long options are also" <<
					" mandatory for short options." << std::endl;
				std::cout << "  -a INTEGER          enforce use of AEAD" <<
					" algorithm INTEGER (cf. RFC 4880bis)" << std::endl;
				std::cout << "  -b, --binary        write encrypted message" <<
					" in binary format (only if -o used)" << std::endl;
				std::cout << "  -h, --help          print this help" <<
					std::endl;
				std::cout << "  -i FILENAME         read message rather" <<
					" from FILENAME than STDIN" << std::endl;
				std::cout << "  -k FILENAME         use keyring FILENAME" <<
					" containing the required keys" << std::endl;
				std::cout << "  -o FILENAME         write encrypted message" <<
					" rather to FILENAME than STDOUT" << std::endl;
				std::cout << "  -r, --recipients    select key(s) from given" <<
					" keyring by KEYSPEC" << std::endl; 
				std::cout << "  -s STRING           select only encryption" <<
					"-capable subkeys with fingerprint equals STRING" <<
					std::endl;
				std::cout << "  -t, --throw-keyids  throw included key IDs" <<
					" for somewhat improved privacy" << std::endl;
				std::cout << "  -v, --version       print the version" <<
					" number" << std::endl;
				std::cout << "  -V, --verbose       turn on verbose output" <<
					std::endl;
				std::cout << "  -w, --weak          allow weak public keys" <<
					std::endl;
				return 0; // not continue
			}
			if ((arg.find("-b") == 0) || (arg.find("--binary") == 0))
				opt_binary = true;
			if ((arg.find("-r") == 0) || (arg.find("--recipients") == 0))
				opt_r = true;
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
		keyspec.push_back(arg);
	}

	// lock memory
	bool force_secmem = false, should_unlock = false;
	if (!lock_memory())
	{
		std::cerr << "WARNING: locking memory failed; CAP_IPC_LOCK required" <<
			" for full memory protection" << std::endl;
		// at least try to use libgcrypt's secure memory
		force_secmem = true;
	}
	else
		should_unlock = true;

	// initialize LibTMCG
	if (!init_libTMCG(force_secmem))
	{
		std::cerr << "ERROR: initialization of LibTMCG failed" << std::endl;
		if (should_unlock)
			unlock_memory();
		return -1;
	}
	if (opt_verbose)
	{
		std::cerr << "INFO: using LibTMCG version " <<
			version_libTMCG() << std::endl;
	}

#ifdef DKGPG_TESTSUITE
	keyspec.push_back("Test1_dkg-pub.asc");
	if (!opt_binary)
		opt_binary = true;
	ofilename = "Test1_output.bin";
	opt_verbose = 2;
	if (tmcg_mpz_wrandom_ui() % 2)
		opt_t = true;
	if (tmcg_mpz_wrandom_ui() % 2)
		opt_a = 2; // sometimes test AEAD with OCB
#else
#ifdef DKGPG_TESTSUITE_Y
	keyspec.push_back("TestY-pub.asc");
	ofilename = "TestY_output.asc";
	opt_verbose = 2;
	if (tmcg_mpz_wrandom_ui() % 2)
		opt_t = true;
	if (tmcg_mpz_wrandom_ui() % 2)
		opt_a = 2; // sometimes test AEAD with OCB
#endif
#endif

	// read the (ASCII-armored) public keyring from file
	std::string armored_pubring;
	if (kfilename.length() > 0)
	{
		if (!autodetect_file(kfilename, TMCG_OPENPGP_ARMOR_PUBLIC_KEY_BLOCK,
			armored_pubring))
		{
			if (should_unlock)
				unlock_memory();
			return -1;
		}
	}

	// parse the keyring
	TMCG_OpenPGP_Keyring *ring = NULL;
	bool parse_ok;
	if (kfilename.length() > 0)
	{
		int opt_verbose_ring = opt_verbose;
		if (opt_verbose_ring > 0)
			opt_verbose_ring--;
		parse_ok = CallasDonnerhackeFinneyShawThayerRFC4880::
			PublicKeyringParse(armored_pubring, opt_verbose_ring, ring);
		if (!parse_ok)
		{
			std::cerr << "WARNING: cannot use the given keyring" << std::endl;
			ring = new TMCG_OpenPGP_Keyring(); // create an empty keyring
		}
	}
	else
		ring = new TMCG_OpenPGP_Keyring(); // create an empty keyring

	// read message from stdin or file
	tmcg_openpgp_octets_t msg;
#ifdef DKGPG_TESTSUITE
	std::string test_msg = "This is just a simple test message.";
	for (size_t i = 0; i < test_msg.length(); i++)
		msg.push_back(test_msg[i]);
#else
#ifdef DKGPG_TESTSUITE_Y
	std::string test_msg = "This is just another simple test message.";
	for (size_t i = 0; i < test_msg.length(); i++)
		msg.push_back(test_msg[i]);
#else
	if (ifilename.length() > 0)
	{
		if (!read_data(ifilename, msg))
		{
			delete ring;
			if (should_unlock)
				unlock_memory();
			return -1;
		}
	}
	else
	{
		char c;
		while (std::cin.get(c))
			msg.push_back(c);
		std::cin.clear();
	}
#endif
#endif

	// encrypt the provided message and create MDC
	gcry_error_t ret;
	tmcg_openpgp_octets_t lit, prefix, enc;
	tmcg_openpgp_secure_octets_t seskey;
	tmcg_openpgp_skalgo_t skalgo = TMCG_OPENPGP_SKALGO_AES256; // fixed AES256
	CallasDonnerhackeFinneyShawThayerRFC4880::PacketLitEncode(msg, lit);
	ret = CallasDonnerhackeFinneyShawThayerRFC4880::SymmetricEncryptAES256(lit,
		seskey, prefix, true, enc); // seskey and prefix only
	if (ret)
	{
		std::cerr << "ERROR: SymmetricEncryptAES256() failed (rc = " <<
			gcry_err_code(ret) << ")" << std::endl;
		delete ring;
		if (should_unlock)
			unlock_memory();
		return ret;
	}
	tmcg_openpgp_octets_t mdc_hashing, hash, mdc, seipd;
	enc.clear();
	// "it includes the prefix data described above" [RFC 4880]
	mdc_hashing.insert(mdc_hashing.end(), prefix.begin(), prefix.end());
	// "it includes all of the plaintext" [RFC 4880]
	mdc_hashing.insert(mdc_hashing.end(), lit.begin(), lit.end());
	// "and the also includes two octets of values 0xD3, 0x14" [RFC 4880]
	mdc_hashing.push_back(0xD3);
	mdc_hashing.push_back(0x14);
	hash.clear();
	// "passed through the SHA-1 hash function" [RFC 4880]
	CallasDonnerhackeFinneyShawThayerRFC4880::
		HashCompute(TMCG_OPENPGP_HASHALGO_SHA1, mdc_hashing, hash);
	CallasDonnerhackeFinneyShawThayerRFC4880::PacketMdcEncode(hash, mdc);
	lit.insert(lit.end(), mdc.begin(), mdc.end()); // append MDC packet
	// generate a fresh session key, but keep the previous prefix
	seskey.clear();
	ret = CallasDonnerhackeFinneyShawThayerRFC4880::SymmetricEncryptAES256(lit,
		seskey, prefix, false, enc); // encryption of literal packet + MDC
	if (ret)
	{
		std::cerr << "ERROR: SymmetricEncryptAES256() failed (rc = " <<
			gcry_err_code(ret) << ")" << std::endl;
		delete ring;
		if (should_unlock)
			unlock_memory();
		return ret;
	}
	CallasDonnerhackeFinneyShawThayerRFC4880::PacketSeipdEncode(enc, seipd);

	// additionally, encrypt the message with appropriate AEAD algorithm
	tmcg_openpgp_octets_t aead;
	tmcg_openpgp_aeadalgo_t aeadalgo = TMCG_OPENPGP_AEADALGO_OCB; // default
#if GCRYPT_VERSION_NUMBER < 0x010900
	// FIXME: remove, if libgcrypt >= 1.9.0 required by configure.ac
#else
	//aeadalgo = TMCG_OPENPGP_AEADALGO_EAX;
#endif
	if (opt_a != 0)
		aeadalgo = (tmcg_openpgp_aeadalgo_t)opt_a; // enforce given algorithm
	lit.clear(), enc.clear();
	CallasDonnerhackeFinneyShawThayerRFC4880::PacketLitEncode(msg, lit);
	tmcg_openpgp_octets_t ad, iv;
	tmcg_openpgp_byte_t cs = 10; // fixed chunk of size 2^16 bytes
	ad.push_back(0xD4); // packet tag in new format
	ad.push_back(0x01); // packet version number
	ad.push_back(skalgo); // cipher algorithm octet
	ad.push_back(aeadalgo); // AEAD algorithm octet
	ad.push_back(cs); // chunk size octet
	for (size_t i = 0; i < 8; i++)
		ad.push_back(0x00); // initial eight-octet big-endian chunk index
	ret = CallasDonnerhackeFinneyShawThayerRFC4880::SymmetricEncryptAEAD(lit,
		seskey, skalgo, aeadalgo, cs, ad, opt_verbose, iv, enc); 
	if (ret)
	{
		std::cerr << "ERROR: SymmetricEncryptAEAD() failed (rc = " <<
			gcry_err_code(ret) << ")" << std::endl;
		delete ring;
		if (should_unlock)
			unlock_memory();
		return ret;
	}
	CallasDonnerhackeFinneyShawThayerRFC4880::PacketAeadEncode(skalgo,
		aeadalgo, cs, iv, enc, aead);

	// perform a password-based symmetric encryption, if no keyspec given
	tmcg_openpgp_octets_t all;
	if (keyspec.size() == 0)
	{
		tmcg_openpgp_secure_string_t passphrase, passphrase_check;
		std::string ps1 = "Passphrase to protect this message";
		std::string ps2 = "Please repeat the given passphrase to continue";
		do
		{
			passphrase = "", passphrase_check = "";
			if (!get_passphrase(ps1, false, passphrase))
			{
				delete ring;
				if (should_unlock)
					unlock_memory();
				return -1;
			}
			if (!get_passphrase(ps2, false, passphrase_check))
			{
				delete ring;
				if (should_unlock)
					unlock_memory();
				return -1;
			}
			if (passphrase != passphrase_check)
			{
				std::cerr << "WARNING: passphrase does not match;" <<
					" please try again" << std::endl;
			}
			else if (passphrase == "")
			{
				std::cerr << "WARNING: empty passphrase is not" <<
					" permitted" << std::endl;
			}
		}
		while ((passphrase != passphrase_check) || (passphrase == ""));

		// encrypt session key with passphrase according to S2K
		tmcg_openpgp_octets_t plain, salt, iv2, es;
		tmcg_openpgp_hashalgo_t s2k_hashalgo = TMCG_OPENPGP_HASHALGO_SHA512;
		tmcg_openpgp_byte_t rand[8], count = 0xFD; // set resonable S2K count
		tmcg_openpgp_secure_octets_t kek;
		gcry_randomize(rand, sizeof(rand), GCRY_STRONG_RANDOM);
		for (size_t i = 0; i < sizeof(rand); i++)
			salt.push_back(rand[i]);
		CallasDonnerhackeFinneyShawThayerRFC4880::
			S2KCompute(s2k_hashalgo, 32, passphrase, salt, true, count, kek);
		if (opt_verbose > 2)
		{
			std::cerr << "INFO: kek.size() = " << kek.size() << std::endl;
			std::cerr << "INFO: seskey.size() = " << seskey.size() << std::endl;
			std::cerr << "INFO: seskey[0] = " << (int)seskey[0] << std::endl;
		}
		if ((seskey.size() == 35) && (kek.size() == 32))
		{
			// strip the always appended checksum from session key
			plain.insert(plain.end(), seskey.begin(), seskey.end()-2);
		}
		else
			std::cerr << "ERROR: bad session key for SKESK" << std::endl;
		if (opt_a != 0)
		{
			tmcg_openpgp_octets_t ad2;
			ad2.push_back(0xC3);
			ad2.push_back(0x05);
			ad2.push_back(skalgo);
			ad2.push_back(opt_a);
			ret = CallasDonnerhackeFinneyShawThayerRFC4880::
				SymmetricEncryptAEAD(plain, kek, skalgo, aeadalgo, 0, ad2,
				opt_verbose, iv2, es);
		}
		else
		{
			ret = encrypt_kek(plain, skalgo, kek, es);
		}
		if (ret)
		{
			delete ring;
			if (should_unlock)
				unlock_memory();
			return -20;
		}

		if (opt_verbose > 2)
		{
			std::cerr << "INFO: es.size() = " << es.size() << std::endl;
			std::cerr << "INFO: iv2.size() = " << iv2.size() << std::endl;
		}

		// create a corresponding SKESK packet
		CallasDonnerhackeFinneyShawThayerRFC4880::PacketTagEncode(3, all);
		if (opt_a != 0)
		{
			CallasDonnerhackeFinneyShawThayerRFC4880::
				PacketLengthEncode(6+salt.size()+iv2.size()+es.size(), all);
			all.push_back(5); // V5 format
			all.push_back(skalgo);
			all.push_back(aeadalgo);
			all.push_back(TMCG_OPENPGP_STRINGTOKEY_ITERATED); // Iterated+Salted
			all.push_back(s2k_hashalgo); // S2K hash algo
			all.insert(all.end(), salt.begin(), salt.end()); // salt
			all.push_back(count); // count, a one-octet, coded value
			all.insert(all.end(), iv2.begin(), iv2.end()); // AEAD IV
		}
		else
		{
			CallasDonnerhackeFinneyShawThayerRFC4880::
				PacketLengthEncode(5+salt.size()+es.size(), all);
			all.push_back(4); // V4 format
			all.push_back(skalgo);
			all.push_back(TMCG_OPENPGP_STRINGTOKEY_ITERATED); // Iterated+Salted
			all.push_back(s2k_hashalgo); // S2K hash algo
			all.insert(all.end(), salt.begin(), salt.end()); // salt
			all.push_back(count); // count, a one-octet, coded value
		}
		all.insert(all.end(), es.begin(), es.end()); // encrypted session key
	}

	// iterate through all specified encryption keys
	size_t features = 0xFF;
	for (size_t k = 0; k < keyspec.size(); k++)
	{
		TMCG_OpenPGP_Pubkey *primary = NULL;
		std::string armored_pubkey;
		if (opt_r)
		{
			// try to extract the public key from keyring by keyspec
			if (opt_verbose > 1)
			{
				std::cerr << "INFO: lookup for encryption key with" <<
					" fingerprint " << keyspec[k] << std::endl;
			}
			const TMCG_OpenPGP_Pubkey *key = ring->FindByKeyid(keyspec[k]);
			if (key == NULL)
			{
				std::cerr << "ERROR: encryption key not found in keyring" <<
					std::endl; 
				delete ring;
				if (should_unlock)
					unlock_memory();
				return -1;
			}
			tmcg_openpgp_octets_t pkts;
			key->Export(pkts);
			CallasDonnerhackeFinneyShawThayerRFC4880::
				ArmorEncode(TMCG_OPENPGP_ARMOR_PUBLIC_KEY_BLOCK, pkts,
					armored_pubkey);
		}
		else
		{
			// try to read the (ASCII-armored) public key from file
			if (!autodetect_file(keyspec[k],
				TMCG_OPENPGP_ARMOR_PUBLIC_KEY_BLOCK, armored_pubkey))
			{
				delete ring;
				if (should_unlock)
					unlock_memory();
				return -1;
			}
		}

		// parse the public key block and check corresponding signatures
		parse_ok = CallasDonnerhackeFinneyShawThayerRFC4880::
			PublicKeyBlockParse(armored_pubkey, opt_verbose, primary);
		if (parse_ok)
		{
			primary->CheckSelfSignatures(ring, opt_verbose);
			if (!primary->valid)
			{
				if (opt_weak)
				{
					std::cerr << "WARNING: primary key #" << k << " is not" <<
						" valid" << std::endl;
				}
				else
				{
					std::cerr << "ERROR: primary key #" << k << " is not" <<
						" valid" << std::endl;
					delete primary;
					delete ring;
					if (should_unlock)
						unlock_memory();
					return -2;
				}
			}
			primary->CheckSubkeys(ring, opt_verbose);
			primary->Reduce(); // keep only valid subkeys
			if (primary->Weak(opt_verbose) && !opt_weak)
			{
				std::cerr << "ERROR: primary key #" << k << " is weak" <<
					std::endl;
				delete primary;
				delete ring;
				if (should_unlock)
					unlock_memory();
				return -3;
			}
		}
		else
		{
			std::cerr << "ERROR: cannot use the provided public key #" << k <<
				std::endl;
			delete ring;
			if (should_unlock)
				unlock_memory();
			return -4;
		}

		// select encryption-capable subkeys
		std::vector<TMCG_OpenPGP_Subkey*> selected;
		for (size_t j = 0; j < primary->subkeys.size(); j++)
		{
			// subkey not selected?
			std::string kid, fpr;
			CallasDonnerhackeFinneyShawThayerRFC4880::
				KeyidConvert(primary->subkeys[j]->id, kid);
			CallasDonnerhackeFinneyShawThayerRFC4880::
				FingerprintConvertPlain(primary->subkeys[j]->fingerprint, fpr);
			if ((s.length() > 0) && (kid != s) && (fpr != s))
				continue;
			// encryption-capable subkey?
			if (((primary->subkeys[j]->AccumulateFlags() & 0x04) == 0x04) ||
			    ((primary->subkeys[j]->AccumulateFlags() & 0x08) == 0x08) ||
			    (!primary->subkeys[j]->AccumulateFlags() &&
					((primary->subkeys[j]->pkalgo == TMCG_OPENPGP_PKALGO_RSA) || 
					(primary->subkeys[j]->pkalgo ==
						TMCG_OPENPGP_PKALGO_RSA_ENCRYPT_ONLY) ||
					(primary->subkeys[j]->pkalgo == TMCG_OPENPGP_PKALGO_ELGAMAL) ||
					(primary->subkeys[j]->pkalgo == TMCG_OPENPGP_PKALGO_ECDH))))
			{
				if (primary->subkeys[j]->Weak(opt_verbose) && !opt_weak)
				{
					if (opt_verbose)
					{
						std::cerr << "WARNING: weak subkey of public key #" <<
							k << " ignored" << std::endl;
					}
				}
				else if ((primary->subkeys[j]->pkalgo != 
							TMCG_OPENPGP_PKALGO_RSA) &&
				         (primary->subkeys[j]->pkalgo !=
							TMCG_OPENPGP_PKALGO_RSA_ENCRYPT_ONLY) &&
				         (primary->subkeys[j]->pkalgo !=
							TMCG_OPENPGP_PKALGO_ELGAMAL) &&
					 (primary->subkeys[j]->pkalgo !=
							TMCG_OPENPGP_PKALGO_ECDH))
				{
					if (opt_verbose)
					{
						std::cerr << "WARNING: subkey of public key #" << k <<
							" with unsupported public-key algorithm ignored" <<
							std::endl;
					}
				}
				else
				{
					selected.push_back(primary->subkeys[j]);
					size_t skf = primary->subkeys[j]->AccumulateFeatures();
					size_t pkf = primary->AccumulateFeatures();
					features &= (skf | pkf);
					if ((std::find(primary->subkeys[j]->psa.begin(),
						primary->subkeys[j]->psa.end(),
						skalgo) == primary->subkeys[j]->psa.end()) &&
					    (std::find(primary->psa.begin(), primary->psa.end(),
							skalgo) == primary->psa.end()))
					{
						if (opt_verbose)
						{
							std::cerr << "WARNING: AES-256 is none of the" <<
								" preferred symmetric algorithms;" <<
								" use AES-256 anyway" << std::endl;
						}
					}
					if (((skf & 0x01) != 0x01) && !opt_a &&
					    ((pkf & 0x01) != 0x01))
					{
						if (opt_verbose)
						{
							std::cerr << "WARNING: recipient does not state" <<
								" support for modification detection (MDC);" <<
								"use MDC anyway" << std::endl;
						}
					}
					if (((skf & 0x02) != 0x02) && !opt_a &&
					    ((pkf & 0x02) != 0x02))
					{
						if (opt_verbose)
						{
							std::cerr << "WARNING: recipient does not state" <<
								" support for AEAD Encrypted Data Packet;" <<
								" AEAD disabled" << std::endl;
						}
					}
					if (((skf & 0x02) != 0x02) && opt_a &&
					    ((pkf & 0x02) != 0x02))
					{
						if (opt_verbose)
						{
							std::cerr << "WARNING: recipient does not state" <<
								" support for AEAD Encrypted Data Packet;" <<
								" AEAD enforced by option -a" << std::endl;
						}
					}
					if ((std::find(primary->subkeys[j]->paa.begin(),
						primary->subkeys[j]->paa.end(),
						aeadalgo) == primary->subkeys[j]->paa.end()) &&
					    (std::find(primary->paa.begin(), primary->paa.end(),
							aeadalgo) == primary->paa.end()))
					{
						if (opt_verbose)
						{
							std::cerr << "WARNING: selected algorithm is" <<
								" none of the preferred AEAD algorithms;";
						}
						if (!opt_a)
						{
							if (opt_verbose)
								std::cerr << " AEAD disabled" << std::endl;
							aead.clear(); // fallback to SEIPD packet
						}
						else
						{
							if (opt_verbose)
							{
								std::cerr << "AEAD mode enforced by option" <<
									" -a" << std::endl;
							}
						}
					}
				}
			}
		}

		// check primary key, if no encryption-capable subkeys have been
		// selected previously
		if ((selected.size() == 0) && primary->valid)
		{
			// encryption-capable key or RSA key without flags?
			if (((primary->AccumulateFlags() & 0x04) == 0x04) ||
			    ((primary->AccumulateFlags() & 0x08) == 0x08))
			{
				if (opt_verbose)
				{
					std::cerr << "INFO: primary key #" << k << " is" <<
						" encryption-capable and will be used" << std::endl;
				}
			}
			else if ((primary->AccumulateFlags() == 0) &&
					((primary->pkalgo == TMCG_OPENPGP_PKALGO_RSA) ||
					(primary->pkalgo == TMCG_OPENPGP_PKALGO_RSA_ENCRYPT_ONLY)))
			{
				if (opt_verbose)
				{
					std::cerr << "WARNING: primary key #" << k << " of type" <<
						" RSA without key flags found and used" << std::endl;
				}
			}
			else
			{
				std::cerr << "ERROR: no encryption-capable public key" <<
					" found for key #" << k << std::endl;
				delete primary;
				delete ring;
				if (should_unlock)
					unlock_memory();
				return -5;
			}
			size_t pkf = primary->AccumulateFeatures();
			features &= pkf;
			if (std::find(primary->psa.begin(), primary->psa.end(),
				skalgo) == primary->psa.end())
			{
				if (opt_verbose)
				{
					std::cerr << "WARNING: AES-256 is none of the preferred" <<
						" symmetric algorithms; use AES-256 anyway" <<
						std::endl;
				}
			}
			if (((pkf & 0x01) != 0x01) && !opt_a)
			{
				if (opt_verbose)
				{
					std::cerr << "WARNING: recipient does not state support" <<
						" for modification detection (MDC);" <<
						"use MDC protection anyway" << std::endl;
				}
			}
			if (((pkf & 0x02) != 0x02) && !opt_a)
			{
				if (opt_verbose)
				{
					std::cerr << "WARNING: recipient does not state support" <<
						" for AEAD Encrypted Data Packet; AEAD disabled" <<
						std::endl;
				}
			}
			if (((pkf & 0x02) != 0x02) && opt_a)
			{
				if (opt_verbose)
				{
					std::cerr << "WARNING: recipient does not state support" <<
						" for AEAD Encrypted Data Packet; AEAD enforced by" <<
						" option -a" << std::endl;
				}
			}
			if (std::find(primary->paa.begin(), primary->paa.end(),
				aeadalgo) == primary->paa.end())
			{
				if (opt_verbose)
				{
					std::cerr << "WARNING: selected algorithm is none of the" <<
						" preferred AEAD algorithms;";
				}
				if (!opt_a)
				{
					if (opt_verbose)
						std::cerr << " AEAD disabled" << std::endl;
					aead.clear(); // fallback to SEIPD packet
				}
				else
				{
					if (opt_verbose)
					{
						std::cerr << "AEAD mode enforced by option -a" <<
							std::endl;
					}
				}
			}
		}
		else if ((selected.size() == 0) && !primary->valid)
		{
			std::cerr << "ERROR: no valid primary key found to last resort" <<
				" for key #" << k << std::endl;
			delete primary;
			delete ring;
			if (should_unlock)
				unlock_memory();
			return -6;
		}

		// encrypt the session key (create PKESK packet)
		if (opt_verbose > 1)
		{
			std::cerr << "INFO: " << selected.size() << " subkey(s) selected" <<
				" for encryption of session key" << std::endl;
		}
		for (size_t j = 0; j < selected.size(); j++)
		{
			tmcg_openpgp_octets_t pkesk, subkeyid;
			if (opt_t)
			{
				// An implementation MAY accept or use a Key ID of zero as a
				// "wild card" or "speculative" Key ID. In this case, the
				// receiving implementation would try all available private
				// keys, checking for a valid decrypted session key. This
				// format helps reduce traffic analysis of messages. [RFC4880]
				for (size_t i = 0; i < 8; i++)
					subkeyid.push_back(0x00);
			}
			else
			{
				subkeyid.insert(subkeyid.end(),
					selected[j]->id.begin(), selected[j]->id.end());
			}
			if (!encrypt_session_key(selected[j], seskey, subkeyid, pkesk))
			{
				delete primary;
				delete ring;
				if (should_unlock)
					unlock_memory();
				return -1;
			}
			all.insert(all.end(), pkesk.begin(), pkesk.end());
		}
		if (selected.size() == 0)
		{
			tmcg_openpgp_octets_t pkesk, keyid;
			if (opt_t)
			{
				// An implementation MAY accept or use a Key ID of zero as a
				// "wild card" or "speculative" Key ID. In this case, the
				// receiving implementation would try all available private
				// keys, checking for a valid decrypted session key. This
				// format helps reduce traffic analysis of messages. [RFC4880]
				for (size_t i = 0; i < 8; i++)
					keyid.push_back(0x00);
			}
			else
			{
				keyid.insert(keyid.end(),
					primary->id.begin(), primary->id.end());
			}
			if (!encrypt_session_key(primary, seskey, keyid, pkesk))
			{
				delete primary;
				delete ring;
				if (should_unlock)
					unlock_memory();
				return -1;
			}
			all.insert(all.end(), pkesk.begin(), pkesk.end());
		}

		// release primary key
		delete primary;
	}

	// release keyring and locked memory
	delete ring;
	if (should_unlock)
		unlock_memory();

	// append the encrypted data packet(s) according to supported features
	if (((features & 0x02) == 0x02) && (aead.size() > 0) &&
		(keyspec.size() > 0))
	{
		// append AEAD, because all selected recipients/keys have support
		all.insert(all.end(), aead.begin(), aead.end());
	}
	else if (opt_a && (aead.size() > 0))
	{
		// append AEAD, because it use has been enforced by option -a
		all.insert(all.end(), aead.begin(), aead.end());
	}
	else
	{
		// append SEIPD, because some selected recipients/keys have no support
		all.insert(all.end(), seipd.begin(), seipd.end());
	}

	// encode all packages in ASCII armor
	std::string armored_message;
	CallasDonnerhackeFinneyShawThayerRFC4880::
		ArmorEncode(TMCG_OPENPGP_ARMOR_MESSAGE, all, armored_message);

	// write out the result
	if (ofilename.length() > 0)
	{
		if (opt_binary)
		{
			if (!write_message(ofilename, all))
				return -1;
		}
		else
		{
			if (!write_message(ofilename, armored_message))
				return -1;
		}
	}
	else
		std::cout << armored_message;

	return 0;
}

