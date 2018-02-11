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
#include <map>
#include <string>
#include <algorithm>
#include <ctime>

#include <libTMCG.hh>

#include "dkg-common.hh"

std::vector<std::string>		peers;

std::string				passphrase, userid, ifilename, kfilename;
tmcg_openpgp_octets_t			keyid, subkeyid, pub, sub, uidsig, subsig, sec, ssb, uid;
std::map<size_t, size_t>		idx2dkg, dkg2idx;
mpz_t					dss_p, dss_q, dss_g, dss_h, dss_x_i, dss_xprime_i, dss_y;
size_t					dss_n, dss_t, dss_i;
std::vector<size_t>			dss_qual, dss_x_rvss_qual;
std::vector< std::vector<mpz_ptr> >	dss_c_ik;
mpz_t					dkg_p, dkg_q, dkg_g, dkg_h, dkg_x_i, dkg_xprime_i, dkg_y;
size_t					dkg_n, dkg_t, dkg_i;
std::vector<size_t>			dkg_qual;
std::vector<mpz_ptr>			dkg_v_i;
std::vector< std::vector<mpz_ptr> >	dkg_c_ik;
gcry_mpi_t 				dsa_p, dsa_q, dsa_g, dsa_y, dsa_x, elg_p, elg_q, elg_g, elg_y, elg_x;
gcry_mpi_t				dsa_r, dsa_s, elg_r, elg_s, rsa_n, rsa_e, rsa_md;
gcry_mpi_t 				gk, myk, sig_r, sig_s;
gcry_mpi_t				revdsa_r, revdsa_s, revelg_r, revelg_s, revrsa_md;

int 					opt_verbose = 0;
bool					libgcrypt_secmem = false;
bool 					opt_binary = false;
char					*opt_ifilename = NULL;

int main
	(int argc, char **argv)
{
	static const char *usage = "dkg-verify [OPTIONS] -i INPUTFILE KEYFILE";
	static const char *about = PACKAGE_STRING " " PACKAGE_URL;
	static const char *version = PACKAGE_VERSION " (" PACKAGE_NAME ")";
	char *opt_sigfrom = NULL, *opt_sigto = NULL;
	std::string sigfrom_str, sigto_str;
	struct tm sigfrom_tm = { 0 }, sigto_tm = { 0 };
	time_t sigfrom = 1243810800, sigto = time(NULL);

	// parse command line arguments
	for (size_t i = 0; i < (size_t)(argc - 1); i++)
	{
		std::string arg = argv[i+1];
		if (arg.find("-i") == 0)
		{
			size_t idx = ++i;
			if ((arg.find("-i") == 0) && (idx < (size_t)(argc - 1)) && (opt_ifilename == NULL))
			{
				ifilename = argv[i+1];
				opt_ifilename = (char*)ifilename.c_str();
			}
			continue;
		}
		else if (arg.find("-f") == 0)
		{
			size_t idx = ++i;
			if ((arg.find("-f") == 0) && (idx < (size_t)(argc - 1)) && (opt_sigfrom == NULL))
			{
				sigfrom_str = argv[i+1];
				opt_sigfrom = (char*)sigfrom_str.c_str();
			}
			continue;
		}
		else if (arg.find("-t") == 0)
		{
			size_t idx = ++i;
			if ((arg.find("-t") == 0) && (idx < (size_t)(argc - 1)) && (opt_sigto == NULL))
			{
				sigto_str = argv[i+1];
				opt_sigto = (char*)sigto_str.c_str();
			}
			continue;
		}
		else if ((arg.find("--") == 0) || (arg.find("-b") == 0) || (arg.find("-v") == 0) || (arg.find("-h") == 0) || (arg.find("-V") == 0))
		{
			if ((arg.find("-h") == 0) || (arg.find("--help") == 0))
			{
				std::cout << usage << std::endl;
				std::cout << about << std::endl;
				std::cout << "Arguments mandatory for long options are also mandatory for short options." << std::endl;
				std::cout << "  -b, --binary   consider KEYFILE as binary input" << std::endl;
				std::cout << "  -f TIMESPEC    signature made before given TIMESPEC is not valid" << std::endl;
				std::cout << "  -h, --help     print this help" << std::endl;
				std::cout << "  -i FILENAME    verify detached signature on FILENAME" << std::endl;
				std::cout << "  -t TIMESPEC    signature made after given TIMESPEC is not valid" << std::endl;
				std::cout << "  -v, --version  print the version number" << std::endl;
				std::cout << "  -V, --verbose  turn on verbose output" << std::endl;
				return 0; // not continue
			}
			if ((arg.find("-b") == 0) || (arg.find("--binary") == 0))
				opt_binary = true;
			if ((arg.find("-v") == 0) || (arg.find("--version") == 0))
			{
				std::cout << "dkg-verify v" << version << std::endl;
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
		kfilename = arg;
	}
#ifdef DKGPG_TESTSUITE
	kfilename = "Test1_dkg-pub.asc";
	ifilename = "Test1_output.bin";
	opt_ifilename = (char*)ifilename.c_str();
	opt_verbose = 1;
#endif
	// check command line arguments
	if ((kfilename.length() == 0) || (ifilename.length() == 0))
	{
		std::cerr << "ERROR: some filename missing; usage: " << usage << std::endl;
		return -1;
	}
	if (opt_sigfrom)
	{
		strptime(opt_sigfrom, "%Y-%m-%d_%H:%M:%S", &sigfrom_tm);
		sigfrom = mktime(&sigfrom_tm);
		if (sigfrom == ((time_t) -1))
		{
			perror("dkg-verify (mktime)");
			std::cerr << "ERROR: cannot convert TIMESPEC; required format: YYYY-MM-DD_HH:MM:SS" << std::endl;
			return -1;
		}
	}
	if (opt_sigto)
	{
		strptime(opt_sigto, "%Y-%m-%d_%H:%M:%S", &sigto_tm);
		sigto = mktime(&sigto_tm);
		if (sigto == ((time_t) -1))
		{
			perror("dkg-verify (mktime)");
			std::cerr << "ERROR: cannot convert TIMESPEC; required format: YYYY-MM-DD_HH:MM:SS" << std::endl;
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
		std::cout << "INFO: using LibTMCG version " << version_libTMCG() << std::endl;

	// read and parse the public key (no ElGamal subkey required)
	std::string armored_pubkey;
	if (opt_binary && !read_binary_key_file(kfilename, TMCG_OPENPGP_ARMOR_PUBLIC_KEY_BLOCK, armored_pubkey))
		return -1;
	if (!opt_binary && !read_key_file(kfilename, armored_pubkey))
		return -1;
	init_mpis();
	time_t ckeytime = 0, ekeytime = 0, csubkeytime = 0, esubkeytime = 0;
	tmcg_openpgp_byte_t keyusage = 0, keystrength = 1;
	if (!parse_public_key(armored_pubkey, ckeytime, ekeytime, csubkeytime, esubkeytime, keyusage, keystrength, false))
	{
		std::cerr << "ERROR: cannot parse resp. use the provided public key" << std::endl;
		release_mpis();
		return -1;
	}
	if (!keystrength)
	{
		std::cerr << "ERROR: provided public key is too weak" << std::endl;
		release_mpis();
		return -1;
	}

	// read the signature from stdin
	std::string signature;
#ifdef DKGPG_TESTSUITE
	std::string sigfilename = "Test1_output.sig";
	if (!read_message(sigfilename, signature))
	{
		release_mpis();
		return -1;
	}
#else
	char c;
	while (std::cin.get(c))
		signature += c;
	std::cin.clear();
#endif

	// parse the signature
	tmcg_openpgp_octets_t trailer;
	tmcg_openpgp_byte_t hashalgo = 0, sigstrength = 1;
	time_t csigtime = 0, sigexptime = 0;
	bool sigV3 = false;
	if (!parse_signature(signature, 0x00, csigtime, sigexptime, hashalgo, trailer, sigV3, sigstrength))
	{
		std::cerr << "ERROR: cannot parse resp. use the provided signature" << std::endl;
		release_mpis();
		return -1;
	}
	if (!sigstrength)
	{
		std::cerr << "ERROR: provided signature is too weak" << std::endl;
		release_mpis();
		return -1;
	}

	// additional validity checks on key and signature
	time_t current_time = time(NULL);
	// 1. key validity time (signatures made before key creation or after key expiry are not valid)
	if (csigtime < ckeytime)
	{
		std::cout << "ERROR: signature was made before key creation" << std::endl;
		return -2;
	}
	if (ekeytime && (csigtime > (ckeytime + ekeytime)))
	{
		std::cout << "ERROR: signature was made after key expiry" << std::endl;
		return -2;
	}
	// 2. signature validity time (expired signatures are not valid)
	if (sigexptime && (current_time > (csigtime + sigexptime)))
	{
		std::cout << "ERROR: signature is expired" << std::endl;
		return -2;
	}
	// 3. key usage flags (signatures made by keys not with the "signing" capability are not valid)
	if ((keyusage & 0x02) != 0x02)
	{
		std::cout << "ERROR: corresponding key was not intented for signing" << std::endl;
		return -2;
	}
	// 4. key validity time (expired keys are not valid)
	if (ekeytime && (current_time > (ckeytime + ekeytime)))
	{
		std::cout << "ERROR: corresponding key is expired" << std::endl;
		return -2;
	}
	// 5. signature time (signatures made before the sigfrom or after the sigto timespec are not valid)
	if (csigtime < sigfrom)
	{
		std::cout << "ERROR: signature was made before given TIMESPEC" << std::endl;
		return -2;
	}
	if (csigtime > sigto)
	{
		std::cout << "ERROR: signature was made after given TIMESPEC" << std::endl;
		return -2;
	}

	// compute the hash of the input file
	if (opt_verbose)
		std::cout << "INFO: hashing the input file \"" << opt_ifilename << "\"" << std::endl;
	tmcg_openpgp_octets_t hash, left;
	bool hashret = false;
	if (sigV3)
		hashret = CallasDonnerhackeFinneyShawThayerRFC4880::BinaryDocumentHashV3(opt_ifilename, trailer, hashalgo, hash, left);
	else
		hashret = CallasDonnerhackeFinneyShawThayerRFC4880::BinaryDocumentHash(opt_ifilename, trailer, hashalgo, hash, left);
	if (!hashret)
	{
		std::cerr << "ERROR: BinaryDocumentHash() failed; cannot process input file \"" << opt_ifilename << "\"" << std::endl;
		release_mpis();
		return -1;
	}

	// verify the signature
	gcry_error_t ret;
	gcry_sexp_t dsakey;
	size_t erroff;
	ret = gcry_sexp_build(&dsakey, &erroff, "(public-key (dsa (p %M) (q %M) (g %M) (y %M)))", dsa_p, dsa_q, dsa_g, dsa_y);
	if (ret)
	{
		std::cerr << "ERROR: parsing DSA key material failed (rc = " << gcry_err_code(ret) << ", str = " <<
			gcry_strerror(ret) << ")" << std::endl;
		release_mpis();
		return ret;
	}
	ret = CallasDonnerhackeFinneyShawThayerRFC4880::AsymmetricVerifyDSA(hash, dsakey, sig_r, sig_s);
	if (ret)
	{
		std::cerr << "ERROR: AsymmetricVerifyDSA() failed (rc = " << gcry_err_code(ret) << ", str = " <<
			gcry_strerror(ret) << ")" << std::endl;
		release_mpis();
		gcry_sexp_release(dsakey);
		return ret;
	}

	// release mpis and keys
	release_mpis();
	gcry_sexp_release(dsakey);

	if (opt_verbose)
		std::cout << "INFO: Good signature for input file \"" << opt_ifilename << "\"" << std::endl;
	
	return 0;
}
