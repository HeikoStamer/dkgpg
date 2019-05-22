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

int main
	(int argc, char **argv)
{
	static const char *usage = "dkg-fuzzer [OPTIONS] PACKETCLASS";
	static const char *about = PACKAGE_STRING " " PACKAGE_URL;
	static const char *version = PACKAGE_VERSION " (" PACKAGE_NAME ")";
	std::string pktcls, ofilename;
	int opt_verbose = 0;
	bool opt_binary = false;
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
			(arg.find("-b") == 0))
		{
			if ((arg.find("-h") == 0) || (arg.find("--help") == 0))
			{
				std::cout << usage << std::endl;
				std::cout << about << std::endl;
				std::cout << "Arguments mandatory for long options are also" <<
					" mandatory for short options." << std::endl;
				std::cout << "  -b, --binary   write generated sample in" <<
					" binary format (only if -o used)" << std::endl;
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
	if ((pktcls == "SIGNATURE") || (pktcls == "signature"))
	{
		tmcg_openpgp_signature_t type =	
			(tmcg_openpgp_signature_t)(tmcg_mpz_wrandom_ui() %
				(TMCG_OPENPGP_SIGNATURE_THIRD_PARTY_CONFIRMATION + 1));
		tmcg_openpgp_pkalgo_t pkalgo = 
			(tmcg_openpgp_pkalgo_t)(tmcg_mpz_wrandom_ui() %
				(TMCG_OPENPGP_PKALGO_EDDSA + 1));
//				(TMCG_OPENPGP_PKALGO_EXPERIMENTAL10 + 1));
		tmcg_openpgp_hashalgo_t hashalgo = 
			(tmcg_openpgp_hashalgo_t)(tmcg_mpz_wrandom_ui() %
				(TMCG_OPENPGP_HASHALGO_SHA3_512 + 1));
//				(TMCG_OPENPGP_HASHALGO_EXPERIMENTAL10 + 1));

		tmcg_openpgp_octets_t trailer, hash, left, sig, fpr;
		time_t csigtime = tmcg_mpz_wrandom_ui();
		time_t sigexptime = tmcg_mpz_wrandom_ui();
		std::string URI;
		for (size_t i = 0; i < tmcg_mpz_wrandom_ui() % 256; i++)
			URI += "A";
		if (tmcg_mpz_wrandom_ui() % 2)
		{
			for (size_t i = 0; i < 20; i++)
				fpr.push_back(tmcg_mpz_wrandom_ui() % 256); // V4 key
		}
		else
		{
			for (size_t i = 0; i < 32; i++)
				fpr.push_back(tmcg_mpz_wrandom_ui() % 256); // V5 key
		}
		CallasDonnerhackeFinneyShawThayerRFC4880::
			PacketSigPrepareDetachedSignature(type, pkalgo, hashalgo,
				csigtime, sigexptime, URI, fpr, trailer);
		for (size_t i = 0; i < (1 + tmcg_mpz_wrandom_ui() % 3); i++)
			left.push_back(tmcg_mpz_wrandom_ui() % 256);

		gcry_mpi_t r, s;
		r = gcry_mpi_new(2048);
		gcry_mpi_randomize(r, tmcg_mpz_wrandom_ui() % 32000, GCRY_WEAK_RANDOM);
		s = gcry_mpi_new(2048);
		gcry_mpi_randomize(s, tmcg_mpz_wrandom_ui() % 32000, GCRY_WEAK_RANDOM);
		switch (pkalgo)
		{
			case TMCG_OPENPGP_PKALGO_RSA:
			case TMCG_OPENPGP_PKALGO_RSA_SIGN_ONLY:
				CallasDonnerhackeFinneyShawThayerRFC4880::
					PacketSigEncode(trailer, left, s, sig);
				break;
			case TMCG_OPENPGP_PKALGO_DSA:
			case TMCG_OPENPGP_PKALGO_ECDSA:
			case TMCG_OPENPGP_PKALGO_EDDSA:
			case TMCG_OPENPGP_PKALGO_EXPERIMENTAL7:
				CallasDonnerhackeFinneyShawThayerRFC4880::
					PacketSigEncode(trailer, left, r, s, sig);
				break;
			default:
				CallasDonnerhackeFinneyShawThayerRFC4880::
					PacketSigEncode(trailer, left, s, sig);
		}
		gcry_mpi_release(r), gcry_mpi_release(s);

		// prepare the output
		std::string sigstr;
		CallasDonnerhackeFinneyShawThayerRFC4880::
			ArmorEncode(TMCG_OPENPGP_ARMOR_SIGNATURE, sig, sigstr);
		if (opt_ofilename != NULL)
		{
			if (opt_binary)
			{
				if (!write_message(ofilename, sig))
					return -1;
			}
			else
			{
				if (!write_message(ofilename, sigstr))
					return -1;
			}
		}
		else
			std::cout << sigstr << std::endl;
	}
	else
	{
		std::cerr << "ERROR: OpenPGP packet class \"" << pktcls << "\" not" <<
			" supported" << std::endl;
		return -1;
	}
	
	return 0;
}

