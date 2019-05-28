/*******************************************************************************
   This file is part of Distributed Privacy Guard (DKGPG).

 Copyright (C) 2019  Heiko Stamer <HeikoStamer@gmx.net>

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

#include <string>
#include <vector>

#include <libTMCG.hh>

#include "dkg-io.hh"

void fuzzy_append_some
	(tmcg_openpgp_octets_t &out, const size_t min, const size_t mod)
{
	size_t len = min + (tmcg_mpz_wrandom_ui() % mod);
	for (size_t i = 0; i < len; i++)
		out.push_back(tmcg_mpz_wrandom_ui() % 256);
}

void fuzzy_signature
	(tmcg_openpgp_octets_t &out, const bool corrupt); // forward declaration

void fuzzy_subpacket
	(tmcg_openpgp_octets_t &out, const bool corrupt)
{
	tmcg_openpgp_octets_t subpkt;
	tmcg_openpgp_byte_t type = tmcg_mpz_wrandom_ui() % 35;
	switch (type)
	{
		case 4:
		case 7:
			if (corrupt)
				fuzzy_append_some(subpkt, 0, 3);
			else
				subpkt.push_back(tmcg_mpz_wrandom_ui() % 2);
			break;
		case 2:
		case 3:
		case 9:
			if (corrupt)
				fuzzy_append_some(subpkt, 0, 9);
			else
			{
				time_t sigtime = tmcg_mpz_wrandom_ui();
				CallasDonnerhackeFinneyShawThayerRFC4880::
					PacketTimeEncode(sigtime, subpkt);
			}
			break;
		case 16: // Issuer
			if (corrupt)
				fuzzy_append_some(subpkt, 0, 65);
			else
			{
				for (size_t i = 0; i < 8; i++)
					subpkt.push_back(tmcg_mpz_wrandom_ui() % 256);
			}
			break;
		case 11:
		case 21:
		case 22:
		case 34:
			if (corrupt)
				fuzzy_append_some(subpkt, 8000, 1);
			else
				fuzzy_append_some(subpkt, 1, 8);
			break;
		case 32: // Embedded Signature
			{
				tmcg_openpgp_octets_t sig;
				fuzzy_signature(sig, corrupt);
				CallasDonnerhackeFinneyShawThayerRFC4880::
					PacketBodyExtract(sig, 0, subpkt);
			}
			break;
		case 33: // Issuer Fingerprint
			if (corrupt)
				fuzzy_append_some(subpkt, 0, 65);
			else
			{
				if (tmcg_mpz_wrandom_ui() % 2)
				{
					subpkt.push_back(4); // V4
					for (size_t i = 0; i < 20; i++)
						subpkt.push_back(tmcg_mpz_wrandom_ui() % 256);
				}
				else
				{
					subpkt.push_back(5); // V5
					for (size_t i = 0; i < 32; i++)
						subpkt.push_back(tmcg_mpz_wrandom_ui() % 256);
				}
			}
			break;
		default:
			fuzzy_append_some(subpkt, 512, 512);
	}
	bool critical = true;
	if (tmcg_mpz_wrandom_ui() % 2)
		critical = false;
	CallasDonnerhackeFinneyShawThayerRFC4880::
		SubpacketEncode(type, critical, subpkt, out);
}

void fuzzy_signature
	(tmcg_openpgp_octets_t &out, const bool corrupt)
{
	tmcg_openpgp_signature_t type;
	switch (tmcg_mpz_wrandom_ui() % 16)
	{
		case 1:
			type = TMCG_OPENPGP_SIGNATURE_BINARY_DOCUMENT;
			break;
		case 2:
			type = TMCG_OPENPGP_SIGNATURE_CANONICAL_TEXT_DOCUMENT;
			break;
		case 3:
			type = TMCG_OPENPGP_SIGNATURE_STANDALONE;
			break;
		case 4:
			type = TMCG_OPENPGP_SIGNATURE_GENERIC_CERTIFICATION;
			break;
		case 5:
			type = TMCG_OPENPGP_SIGNATURE_PERSONA_CERTIFICATION;
			break;
		case 6:
			type = TMCG_OPENPGP_SIGNATURE_CASUAL_CERTIFICATION;
			break;
		case 7:
			type = TMCG_OPENPGP_SIGNATURE_POSITIVE_CERTIFICATION;
			break;
		case 8:
			type = TMCG_OPENPGP_SIGNATURE_SUBKEY_BINDING;
			break;
		case 9:
			type = TMCG_OPENPGP_SIGNATURE_PRIMARY_KEY_BINDING;
			break;
		case 10:
			type = TMCG_OPENPGP_SIGNATURE_DIRECTLY_ON_A_KEY;
			break;
		case 11:
			type = TMCG_OPENPGP_SIGNATURE_KEY_REVOCATION;
			break;
		case 12:
			type = TMCG_OPENPGP_SIGNATURE_SUBKEY_REVOCATION;
			break;
		case 13:
			type = TMCG_OPENPGP_SIGNATURE_CERTIFICATION_REVOCATION;
			break;
		case 14:
			type = TMCG_OPENPGP_SIGNATURE_TIMESTAMP;
			break;
		case 15:
			type = TMCG_OPENPGP_SIGNATURE_THIRD_PARTY_CONFIRMATION;
			break;
		default:
			type = (tmcg_openpgp_signature_t)0x03; // out of spec
	}
	tmcg_openpgp_pkalgo_t pkalgo;
	switch (tmcg_mpz_wrandom_ui() % 22)
	{
		case 1:
			pkalgo = TMCG_OPENPGP_PKALGO_RSA;
			break;
		case 2:
			pkalgo = TMCG_OPENPGP_PKALGO_RSA_ENCRYPT_ONLY;
			break;
		case 3:
			pkalgo = TMCG_OPENPGP_PKALGO_RSA_SIGN_ONLY;
			break;
		case 4:
			pkalgo = TMCG_OPENPGP_PKALGO_ELGAMAL;
			break;
		case 5:
			pkalgo = TMCG_OPENPGP_PKALGO_DSA;
			break;
		case 6:
			pkalgo = TMCG_OPENPGP_PKALGO_ECDH;
			break;
		case 7:
			pkalgo = TMCG_OPENPGP_PKALGO_ECDSA;
			break;
		case 8:
			pkalgo = TMCG_OPENPGP_PKALGO_EDDSA;
			break;
		case 9:
			pkalgo = TMCG_OPENPGP_PKALGO_EXPERIMENTAL0;
			break;
		case 10:
			pkalgo = TMCG_OPENPGP_PKALGO_EXPERIMENTAL1;
			break;
		case 11:
			pkalgo = TMCG_OPENPGP_PKALGO_EXPERIMENTAL2;
			break;
		case 12:
			pkalgo = TMCG_OPENPGP_PKALGO_EXPERIMENTAL3;
			break;
		case 13:
			pkalgo = TMCG_OPENPGP_PKALGO_EXPERIMENTAL4;
			break;
		case 14:
			pkalgo = TMCG_OPENPGP_PKALGO_EXPERIMENTAL5;
			break;
		case 15:
			pkalgo = TMCG_OPENPGP_PKALGO_EXPERIMENTAL6;
			break;
		case 16:
			pkalgo = TMCG_OPENPGP_PKALGO_EXPERIMENTAL7;
			break;
		case 17:
			pkalgo = TMCG_OPENPGP_PKALGO_EXPERIMENTAL8;
			break;
		case 18:
			pkalgo = TMCG_OPENPGP_PKALGO_EXPERIMENTAL9;
			break;
		case 19:
			pkalgo = TMCG_OPENPGP_PKALGO_EXPERIMENTAL10;
			break;
		case 20:
			pkalgo = (tmcg_openpgp_pkalgo_t)20; // out of spec (ElGamal)
			break;
		case 21:
			pkalgo = (tmcg_openpgp_pkalgo_t)21; // out of spec (X9.42)
			break;
		default:
			pkalgo = (tmcg_openpgp_pkalgo_t)0x00; // out of spec
	}
	tmcg_openpgp_hashalgo_t hashalgo;
	switch (tmcg_mpz_wrandom_ui() % 26)
	{
		case 1:
			hashalgo = TMCG_OPENPGP_HASHALGO_MD5;
			break;
		case 2:
			hashalgo = TMCG_OPENPGP_HASHALGO_SHA1;
			break;
		case 3:
			hashalgo = TMCG_OPENPGP_HASHALGO_RMD160;
			break;
		case 4:
			hashalgo = (tmcg_openpgp_hashalgo_t)4; // out of spec (double-width SHA)
			break;
		case 5:
			hashalgo = (tmcg_openpgp_hashalgo_t)5; // out of spec (MD2)
			break;
		case 6:
			hashalgo = (tmcg_openpgp_hashalgo_t)6; // out of spec (TIGER192)
			break;
		case 7:
			hashalgo = (tmcg_openpgp_hashalgo_t)7; // out of spec (HAVAL)
			break;
		case 8:
			hashalgo = TMCG_OPENPGP_HASHALGO_SHA256;
			break;
		case 9:
			hashalgo = TMCG_OPENPGP_HASHALGO_SHA384;
			break;
		case 10:
			hashalgo = TMCG_OPENPGP_HASHALGO_SHA512;
			break;
		case 11:
			hashalgo = TMCG_OPENPGP_HASHALGO_SHA224;
			break;
		case 12:
			hashalgo = TMCG_OPENPGP_HASHALGO_SHA3_256;
			break;
		case 13:
			hashalgo = (tmcg_openpgp_hashalgo_t)13; // out of spec
			break;
		case 14:
			hashalgo = TMCG_OPENPGP_HASHALGO_SHA3_512;
			break;
		case 15:
			hashalgo = TMCG_OPENPGP_HASHALGO_EXPERIMENTAL0;
			break;
		case 16:
			hashalgo = TMCG_OPENPGP_HASHALGO_EXPERIMENTAL1;
			break;
		case 17:
			hashalgo = TMCG_OPENPGP_HASHALGO_EXPERIMENTAL2;
			break;
		case 18:
			hashalgo = TMCG_OPENPGP_HASHALGO_EXPERIMENTAL3;
			break;
		case 19:
			hashalgo = TMCG_OPENPGP_HASHALGO_EXPERIMENTAL4;
			break;
		case 20:
			hashalgo = TMCG_OPENPGP_HASHALGO_EXPERIMENTAL5;
			break;
		case 21:
			hashalgo = TMCG_OPENPGP_HASHALGO_EXPERIMENTAL6;
			break;
		case 22:
			hashalgo = TMCG_OPENPGP_HASHALGO_EXPERIMENTAL7;
			break;
		case 23:
			hashalgo = TMCG_OPENPGP_HASHALGO_EXPERIMENTAL8;
			break;
		case 24:
			hashalgo = TMCG_OPENPGP_HASHALGO_EXPERIMENTAL9;
			break;
		case 25:
			hashalgo = TMCG_OPENPGP_HASHALGO_EXPERIMENTAL10;
			break;
		default:
			hashalgo = TMCG_OPENPGP_HASHALGO_UNKNOWN; // out of spec
	}
	tmcg_openpgp_octets_t trailer, hspd, uspd, left;
	trailer.push_back(4); // V4 format
	trailer.push_back(type); // type
	trailer.push_back(pkalgo); // public-key algorithm
	trailer.push_back(hashalgo); // hash algorithm
	do
	{
		hspd.clear(), uspd.clear();
		for (size_t i = 0; i < tmcg_mpz_wrandom_ui() % 10; i++)
			fuzzy_subpacket(hspd, corrupt);
		for (size_t i = 0; i < tmcg_mpz_wrandom_ui() % 10; i++)
			fuzzy_subpacket(uspd, corrupt);
	}
	while ((hspd.size() > 20000) || (uspd.size() > 20000));
	trailer.push_back((hspd.size() >> 8) & 0xFF); // hashed subpacket data
	trailer.push_back(hspd.size() & 0xFF);
	trailer.insert(trailer.end(), hspd.begin(), hspd.end());
	trailer.push_back((uspd.size() >> 8) & 0xFF); // unhashed subpacket data
	trailer.push_back(uspd.size() & 0xFF);
	trailer.insert(trailer.end(), uspd.begin(), uspd.end());
	for (size_t i = 0; i < (1 + tmcg_mpz_wrandom_ui() % 3); i++)
		left.push_back(tmcg_mpz_wrandom_ui() % 256);
	gcry_mpi_t r, s; // create fake-signature values
	r = gcry_mpi_new(2048);
	gcry_mpi_randomize(r, tmcg_mpz_wrandom_ui() % 32000, GCRY_WEAK_RANDOM);
	s = gcry_mpi_new(2048);
	gcry_mpi_randomize(s, tmcg_mpz_wrandom_ui() % 32000, GCRY_WEAK_RANDOM);
	switch (pkalgo)
	{
		case TMCG_OPENPGP_PKALGO_RSA:
		case TMCG_OPENPGP_PKALGO_RSA_SIGN_ONLY:
			CallasDonnerhackeFinneyShawThayerRFC4880::
				PacketSigEncode(trailer, left, s, out);
			break;
		case TMCG_OPENPGP_PKALGO_DSA:
		case TMCG_OPENPGP_PKALGO_ECDSA:
		case TMCG_OPENPGP_PKALGO_EDDSA:
		case TMCG_OPENPGP_PKALGO_EXPERIMENTAL7:
			CallasDonnerhackeFinneyShawThayerRFC4880::
				PacketSigEncode(trailer, left, r, s, out);
			break;
		default:
			CallasDonnerhackeFinneyShawThayerRFC4880::
				PacketSigEncode(trailer, left, s, out);
	}
	gcry_mpi_release(r), gcry_mpi_release(s);
}

int main
	(int argc, char **argv)
{
	static const char *usage = "dkg-fuzzer [OPTIONS] PACKETCLASS";
	static const char *about = PACKAGE_STRING " " PACKAGE_URL;
	static const char *version = PACKAGE_VERSION " (" PACKAGE_NAME ")";
	std::string pktcls, ofilename;
	int opt_verbose = 0;
	bool opt_binary = false, opt_corrupt = false;
	char *opt_ofilename = NULL;

	for (size_t i = 0; i < (size_t)(argc - 1); i++)
	{
		std::string arg = argv[i+1];
		// ignore options
		if ((arg.find("-o") == 0))
		{
			size_t idx = ++i;
			if ((arg.find("-o") == 0) && (idx < (size_t)(argc - 1)) &&
				(opt_ofilename == NULL))
			{
				ofilename = argv[i+1];
				opt_ofilename = (char*)ofilename.c_str();
			}
		}
		else if ((arg.find("--") == 0) || (arg.find("-v") == 0) ||
			(arg.find("-h") == 0) || (arg.find("-V") == 0) ||
			(arg.find("-b") == 0) || (arg.find("-c") == 0))
		{
			if ((arg.find("-h") == 0) || (arg.find("--help") == 0))
			{
				std::cout << usage << std::endl;
				std::cout << about << std::endl;
				std::cout << "Arguments mandatory for long options are also" <<
					" mandatory for short options." << std::endl;
				std::cout << "  -b, --binary   write generated sample in" <<
					" binary format (only if -o used)" << std::endl;
				std::cout << "  -c, --corrupt  allow somehow corrupted" <<
					" samples" << std::endl;
				std::cout << "  -h, --help     print this help" << std::endl;
				std::cout << "  -o FILENAME    write generated sample to" <<
					" FILENAME" << std::endl;
				std::cout << "  -v, --version  print the version number" <<
					std::endl;
				std::cout << "  -V, --verbose  turn on verbose output" <<
					std::endl;
				return 0; // not continue
			}
			if ((arg.find("-b") == 0) || (arg.find("--binary") == 0))
				opt_binary = true;
			if ((arg.find("-c") == 0) || (arg.find("--corrupt") == 0))
				opt_corrupt = true;
			if ((arg.find("-v") == 0) || (arg.find("--version") == 0))
			{
				std::cout << "dkg-fuzzer v" << version << std::endl;
				return 0; // not continue
			}
			if ((arg.find("-V") == 0) || (arg.find("--verbose") == 0))
				opt_verbose++; // increase verbosity
			continue;
		}
		else if (arg.find("-") == 0)
		{
			std::cerr << "ERROR: unknown option \"" << arg << "\"" << std::endl;
			return -1;
		}
		pktcls = arg;
	}

	// initialize LibTMCG
	if (!init_libTMCG())
	{
		std::cerr << "ERROR: initialization of LibTMCG failed" << std::endl;
		return -1;
	}
	if (opt_verbose)
	{
		std::cerr << "INFO: using LibTMCG version " << version_libTMCG() <<
			std::endl;
	}

	// do fuzzy things
	tmcg_openpgp_octets_t pkts;
	if ((pktcls == "SIGNATURE") || (pktcls == "signature"))
		fuzzy_signature(pkts, opt_corrupt);

	if (pkts.size() > 0)
	{
		std::string pstr;
		CallasDonnerhackeFinneyShawThayerRFC4880::
			ArmorEncode(TMCG_OPENPGP_ARMOR_SIGNATURE, pkts, pstr);
		if (opt_ofilename != NULL)
		{
			if (opt_binary)
			{
				if (!write_message(ofilename, pkts))
					return -1;
			}
			else
			{
				if (!write_message(ofilename, pstr))
					return -1;
			}
		}
		else
			std::cout << pstr << std::endl;
	}
	else
	{
		std::cerr << "ERROR: OpenPGP packet class \"" << pktcls << "\" not" <<
			" supported" << std::endl;
		return -1;
	}
	
	return 0;
}

