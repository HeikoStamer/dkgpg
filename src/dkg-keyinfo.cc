/*******************************************************************************
   This file is part of Distributed Privacy Guard (DKGPG).

 Copyright (C) 2017  Heiko Stamer <HeikoStamer@gmx.net>

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

#include <iomanip>
#include <sstream>
#include <vector>
#include <map>
#include <string>
#include <algorithm>
#include <cstdio>
#include <ctime>

#include <libTMCG.hh>

#include "dkg-common.hh"

std::vector<std::string>		peers;

std::string				passphrase, userid;
tmcg_octets_t				keyid, subkeyid, pub, sub, uidsig, subsig, sec, ssb, uid;
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
gcry_mpi_t 				gk, myk, sig_r, sig_s;

int 					opt_verbose = 0;

#define PRIMES_SIZE 669
unsigned long int 			primes[] = {
						2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43,
						47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101,
						103, 107, 109, 113, 127, 131, 137, 139, 149, 151,
						157, 163, 167, 173, 179, 181, 191, 193, 197, 199,
						211, 223, 227, 229, 233, 239, 241, 251, 257, 263,
						269, 271, 277, 281, 283, 293, 307, 311, 313, 317,
						331, 337, 347, 349, 353, 359, 367, 373, 379, 383,
						389, 397, 401, 409, 419, 421, 431, 433, 439, 443,
						449, 457, 461, 463, 467, 479, 487, 491, 499, 503,
						509, 521, 523, 541, 547, 557, 563, 569, 571, 577,
						587, 593, 599, 601, 607, 613, 617, 619, 631, 641,
						643, 647, 653, 659, 661, 673, 677, 683, 691, 701,
						709, 719, 727, 733, 739, 743, 751, 757, 761, 769,
						773, 787, 797, 809, 811, 821, 823, 827, 829, 839,
						853, 857, 859, 863, 877, 881, 883, 887, 907, 911,
						919, 929, 937, 941, 947, 953, 967, 971, 977, 983,
						991, 997, 1009, 1013, 1019, 1021, 1031, 1033,
						1039, 1049, 1051, 1061, 1063, 1069, 1087, 1091,
						1093, 1097, 1103, 1109, 1117, 1123, 1129, 1151,
						1153, 1163, 1171, 1181, 1187, 1193, 1201, 1213,
						1217, 1223, 1229, 1231, 1237, 1249, 1259, 1277,
						1279, 1283, 1289, 1291, 1297, 1301, 1303, 1307,
						1319, 1321, 1327, 1361, 1367, 1373, 1381, 1399,
						1409, 1423, 1427, 1429, 1433, 1439, 1447, 1451,
						1453, 1459, 1471, 1481, 1483, 1487, 1489, 1493,
						1499, 1511, 1523, 1531, 1543, 1549, 1553, 1559,
						1567, 1571, 1579, 1583, 1597, 1601, 1607, 1609,
						1613, 1619, 1621, 1627, 1637, 1657, 1663, 1667,
						1669, 1693, 1697, 1699, 1709, 1721, 1723, 1733,
						1741, 1747, 1753, 1759, 1777, 1783, 1787, 1789,
						1801, 1811, 1823, 1831, 1847, 1861, 1867, 1871,
						1873, 1877, 1879, 1889, 1901, 1907, 1913, 1931,
						1933, 1949, 1951, 1973, 1979, 1987, 1993, 1997,
						1999, 2003, 2011, 2017, 2027, 2029, 2039, 2053,
						2063, 2069, 2081, 2083, 2087, 2089, 2099, 2111,
						2113, 2129, 2131, 2137, 2141, 2143, 2153, 2161,
						2179, 2203, 2207, 2213, 2221, 2237, 2239, 2243,
						2251, 2267, 2269, 2273, 2281, 2287, 2293, 2297,
						2309, 2311, 2333, 2339, 2341, 2347, 2351, 2357,
						2371, 2377, 2381, 2383, 2389, 2393, 2399, 2411,
						2417, 2423, 2437, 2441, 2447, 2459, 2467, 2473,
						2477, 2503, 2521, 2531, 2539, 2543, 2549, 2551,
						2557, 2579, 2591, 2593, 2609, 2617, 2621, 2633,
						2647, 2657, 2659, 2663, 2671, 2677, 2683, 2687,
						2689, 2693, 2699, 2707, 2711, 2713, 2719, 2729,
						2731, 2741, 2749, 2753, 2767, 2777, 2789, 2791,
						2797, 2801, 2803, 2819, 2833, 2837, 2843, 2851,
						2857, 2861, 2879, 2887, 2897, 2903, 2909, 2917,
						2927, 2939, 2953, 2957, 2963, 2969, 2971, 2999,
						3001, 3011, 3019, 3023, 3037, 3041, 3049, 3061,
						3067, 3079, 3083, 3089, 3109, 3119, 3121, 3137,
						3163, 3167, 3169, 3181, 3187, 3191, 3203, 3209,
						3217, 3221, 3229, 3251, 3253, 3257, 3259, 3271,
						3299, 3301, 3307, 3313, 3319, 3323, 3329, 3331,
						3343, 3347, 3359, 3361, 3371, 3373, 3389, 3391,
						3407, 3413, 3433, 3449, 3457, 3461, 3463, 3467,
						3469, 3491, 3499, 3511, 3517, 3527, 3529, 3533,
						3539, 3541, 3547, 3557, 3559, 3571, 3581, 3583,
						3593, 3607, 3613, 3617, 3623, 3631, 3637, 3643,
						3659, 3671, 3673, 3677, 3691, 3697, 3701, 3709,
						3719, 3727, 3733, 3739, 3761, 3767, 3769, 3779,
						3793, 3797, 3803, 3821, 3823, 3833, 3847, 3851,
						3853, 3863, 3877, 3881, 3889, 3907, 3911, 3917,
						3919, 3923, 3929, 3931, 3943, 3947, 3967, 3989,
						4001, 4003, 4007, 4013, 4019, 4021, 4027, 4049,
						4051, 4057, 4073, 4079, 4091, 4093, 4099, 4111,
						4127, 4129, 4133, 4139, 4153, 4157, 4159, 4177,
						4201, 4211, 4217, 4219, 4229, 4231, 4241, 4243,
						4253, 4259, 4261, 4271, 4273, 4283, 4289, 4297,
						4327, 4337, 4339, 4349, 4357, 4363, 4373, 4391,
						4397, 4409, 4421, 4423, 4441, 4447, 4451, 4457,
						4463, 4481, 4483, 4493, 4507, 4513, 4517, 4519,
						4523, 4547, 4549, 4561, 4567, 4583, 4591, 4597,
						4603, 4621, 4637, 4639, 4643, 4649, 4651, 4657,
						4663, 4673, 4679, 4691, 4703, 4721, 4723, 4729,
						4733, 4751, 4759, 4783, 4787, 4789, 4793, 4799,
						4801, 4813, 4817, 4831, 4861, 4871, 4877, 4889,
						4903, 4909, 4919, 4931, 4933, 4937, 4943, 4951,
						4957, 4967, 4969, 4973, 4987, 4993, 4999, 0
};

int main
	(int argc, char *const *argv)
{
	static const char *usage = "dkg-keyinfo [OPTIONS] PEER";
	static const char *about = PACKAGE_STRING " " PACKAGE_URL;
	static const char *version = PACKAGE_VERSION " (" PACKAGE_NAME ")";
	std::string migrate_peer_from, migrate_peer_to;

	// parse argument list
	for (size_t i = 0; i < (size_t)(argc - 1); i++)
	{
		std::string arg = argv[i+1];
		if (arg.find("-m") == 0)
		{
			size_t idx = ++i + 1; // Note: this option has two arguments
			if ((arg.find("-m") == 0) && (idx < (size_t)(argc - 1)) && (migrate_peer_from.length() == 0) && (migrate_peer_to.length() == 0))
				migrate_peer_from = argv[i+1], migrate_peer_to = argv[i+2];
			++i; // Note: this option has two arguments
			continue;
		}
		else if ((arg.find("--") == 0) || (arg.find("-v") == 0) || (arg.find("-h") == 0) || (arg.find("-V") == 0))
		{
			if ((arg.find("-h") == 0) || (arg.find("--help") == 0))
			{
				std::cout << usage << std::endl;
				std::cout << about << std::endl;
				std::cout << "Arguments mandatory for long options are also mandatory for short options." << std::endl;
				std::cout << "  -h, --help           print this help" << std::endl;
				std::cout << "  -m OLDPEER NEWPEER   migrate OLDPEER identity to NEWPEER" << std::endl;
				std::cout << "  -v, --version        print the version number" << std::endl;
				std::cout << "  -V, --verbose        turn on verbose output" << std::endl;
				return 0; // not continue
			}
			if ((arg.find("-v") == 0) || (arg.find("--version") == 0))
			{
				std::cout << "dkg-keyinfo v" << version << std::endl;
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
		// store argument for peer list
		if (arg.length() <= 255)
		{
			peers.push_back(arg);
		}
		else
		{
			std::cerr << "ERROR: peer identity \"" << arg << "\" too long" << std::endl;
			return -1;
		}
	}
#ifdef DKGPG_TESTSUITE
	peers.push_back("Test1");
	opt_verbose = 1;
#endif

	// check command line arguments
	if (peers.size() < 1)
	{
		std::cerr << "ERROR: no peer given as argument; usage: " << usage << std::endl;
		return -1;
	}
	if (peers.size() != 1)
	{
		std::cerr << "ERROR: too many peers given" << std::endl;
		return -1;
	}

	// initialize LibTMCG
	if (!init_libTMCG())
	{
		std::cerr << "ERROR: initialization of LibTMCG failed" << std::endl;
		return -1;
	}
	if (opt_verbose)
		std::cout << "INFO: using LibTMCG version " << version_libTMCG() << std::endl;

	// read and parse the private key
	std::string armored_seckey, thispeer = peers[0];
	if (!read_key_file(thispeer + "_dkg-sec.asc", armored_seckey))
		return -1;
	init_mpis();
	std::vector<std::string> CAPL;
	time_t ckeytime = 0, ekeytime = 0;
	if (!parse_private_key(armored_seckey, ckeytime, ekeytime, CAPL))
	{
		release_mpis();
		keyid.clear(), subkeyid.clear(), pub.clear(), sub.clear(), uidsig.clear(), subsig.clear();
		dss_qual.clear(), dss_x_rvss_qual.clear(), dss_c_ik.clear(), dkg_qual.clear(), dkg_v_i.clear(), dkg_c_ik.clear();
		init_mpis();
		// protected with password
#ifdef DKGPG_TESTSUITE
		passphrase = "Test";
#else
		if (!get_passphrase("Please enter passphrase to unlock your private key", passphrase))
		{
			release_mpis();
			return -1;
		}
#endif
		if (!parse_private_key(armored_seckey, ckeytime, ekeytime, CAPL))
		{
			std::cerr << "ERROR: wrong passphrase to unlock private key" << std::endl;
			release_mpis();
			return -1;
		}
	}

	// create an instance of tDSS by stored parameters from private key
	std::stringstream dss_in;
	if (dss_n == 0L)
	{
		// cheat CheckGroup() with $h$ for non-tDSS individual DSA key
		mpz_set_ui(dss_h, 42L);
		mpz_powm(dss_h, dss_g, dss_h, dss_p);
	}
	dss_in << dss_p << std::endl << dss_q << std::endl << dss_g << std::endl << dss_h << std::endl;
	dss_in << dss_n << std::endl << dss_t << std::endl << dss_i << std::endl;
	dss_in << dss_x_i << std::endl << dss_xprime_i << std::endl << dss_y << std::endl;
	dss_in << dss_qual.size() << std::endl;
	for (size_t i = 0; i < dss_qual.size(); i++)
		dss_in << dss_qual[i] << std::endl;
	dss_in << dss_p << std::endl << dss_q << std::endl << dss_g << std::endl << dss_h << std::endl;
	dss_in << dss_n << std::endl << dss_t << std::endl << dss_i << std::endl;
	dss_in << dss_x_i << std::endl << dss_xprime_i << std::endl << dss_y << std::endl;
	dss_in << dss_qual.size() << std::endl;
	for (size_t i = 0; i < dss_qual.size(); i++)
		dss_in << dss_qual[i] << std::endl;
	dss_in << dss_p << std::endl << dss_q << std::endl << dss_g << std::endl << dss_h << std::endl;
	dss_in << dss_n << std::endl << dss_t << std::endl << dss_i << std::endl << dss_t << std::endl;
	dss_in << dss_x_i << std::endl << dss_xprime_i << std::endl;
	dss_in << "0" << std::endl << "0" << std::endl;
	dss_in << dss_x_rvss_qual.size() << std::endl;
	for (size_t i = 0; i < dss_x_rvss_qual.size(); i++)
		dss_in << dss_x_rvss_qual[i] << std::endl;
	assert((dss_c_ik.size() == dss_n));
	for (size_t i = 0; i < dss_c_ik.size(); i++)
	{
		for (size_t j = 0; j < dss_c_ik.size(); j++)
			dss_in << "0" << std::endl << "0" << std::endl;
		assert((dss_c_ik[i].size() == (dss_t + 1)));
		for (size_t k = 0; k < dss_c_ik[i].size(); k++)
			dss_in << dss_c_ik[i][k] << std::endl;
	}
	if (opt_verbose)
		std::cout << "CanettiGennaroJareckiKrawczykRabinDSS(in, ...)" << std::endl;
	CanettiGennaroJareckiKrawczykRabinDSS *dss = new CanettiGennaroJareckiKrawczykRabinDSS(dss_in);
	if (!dss->CheckGroup())
	{
		std::cerr << "ERROR: tDSS domain parameters are not correctly generated!" << std::endl;
		delete dss;
		release_mpis();
		return -1;
	}
	if (dss_n == 0)
	{
		mpz_set_ui(dss_h, 0L); // restore $h$ for non-tDSS individual DSA key
		mpz_set_ui(dss->h, 0L);
	}

	GennaroJareckiKrawczykRabinDKG *dkg = NULL;
	if (sub.size())
	{
		// create an instance of DKG by stored parameters from private key
		std::stringstream dkg_in;
		dkg_in << dkg_p << std::endl << dkg_q << std::endl << dkg_g << std::endl << dkg_h << std::endl;
		dkg_in << dkg_n << std::endl << dkg_t << std::endl << dkg_i << std::endl;
		dkg_in << dkg_x_i << std::endl << dkg_xprime_i << std::endl << dkg_y << std::endl;
		dkg_in << dkg_qual.size() << std::endl;
		for (size_t i = 0; i < dkg_qual.size(); i++)
			dkg_in << dkg_qual[i] << std::endl;
		for (size_t i = 0; i < dkg_n; i++)
			dkg_in << "1" << std::endl; // y_i not yet stored
		for (size_t i = 0; i < dkg_n; i++)
			dkg_in << "0" << std::endl; // z_i not yet stored
		assert((dkg_v_i.size() == dkg_n));
		for (size_t i = 0; i < dkg_v_i.size(); i++)
			dkg_in << dkg_v_i[i] << std::endl;
		assert((dkg_c_ik.size() == dkg_n));
		for (size_t i = 0; i < dkg_n; i++)
		{
			for (size_t j = 0; j < dkg_n; j++)
				dkg_in << "0" << std::endl << "0" << std::endl; // s_ij and sprime_ij not yet stored
			assert((dkg_c_ik[i].size() == (dkg_t + 1)));
			for (size_t k = 0; k < dkg_c_ik[i].size(); k++)
				dkg_in << dkg_c_ik[i][k] << std::endl;
		}
		if (opt_verbose)
			std::cout << "GennaroJareckiKrawczykRabinDKG(in, ...)" << std::endl;
		dkg = new GennaroJareckiKrawczykRabinDKG(dkg_in);
		if (!dkg->CheckGroup())
		{
			std::cerr << "ERROR: DKG domain parameters are not correctly generated!" << std::endl;
			delete dss, delete dkg;
			release_mpis();
			return -1;
		}
		if (!dkg->CheckKey())
		{
			std::cerr << "ERROR: DKG CheckKey() failed!" << std::endl;
			delete dss, delete dkg;
			release_mpis();
			return -1;
		}
	}

	// show information
	std::ios oldcoutstate(NULL);
	oldcoutstate.copyfmt(std::cout);
	std::cout << "OpenPGP V4 Key ID of primary key: " << std::endl << std::hex << std::uppercase << "\t";
	for (size_t i = 0; i < keyid.size(); i++)
		std::cout << std::setfill('0') << std::setw(2) << std::right << (int)keyid[i] << " ";
	std::cout << std::dec << std::endl;
	tmcg_octets_t pub_hashing, fpr;
	for (size_t i = 6; i < pub.size(); i++)
		pub_hashing.push_back(pub[i]);
	CallasDonnerhackeFinneyShawThayerRFC4880::FingerprintCompute(pub_hashing, fpr);
	std::cout << "OpenPGP V4 fingerprint of primary key: " << std::endl << std::hex << std::uppercase << "\t";
	for (size_t i = 0; i < fpr.size(); i++)
		std::cout << std::setfill('0') << std::setw(2) << std::right << (int)fpr[i] << " ";
	std::cout << std::dec << std::endl;
	std::cout << "OpenPGP Key Creation Time: " << std::endl << "\t" << ctime(&ckeytime);
	std::cout << "OpenPGP Key Expiration Time: " << std::endl << "\t";
	if (ekeytime == 0)
		std::cout << "undefined" << std::endl;
	else
	{
		ekeytime += ckeytime; // validity period of the key after key creation time
		std::cout << ctime(&ekeytime);
	}
	std::cout << "OpenPGP User ID: " << std::endl << "\t";
	std::cout << userid << std::endl;
	std::cout << "Security level of domain parameter set: " << std::endl << "\t";
	std::cout << "|p| = " << mpz_sizeinbase(dss->p, 2L) << " bit, ";
	std::cout << "|q| = " << mpz_sizeinbase(dss->q, 2L) << " bit, ";
	std::cout << "|g| = " << mpz_sizeinbase(dss->g, 2L) << " bit";
	if (dss_n != 0)
		std::cout << ", |h| = " << mpz_sizeinbase(dss->h, 2L) << " bit";
	std::cout << std::endl << "\t";
	std::cout << "p is ";
	if (!mpz_probab_prime_p(dss->p, TMCG_MR_ITERATIONS))
		std::cout << "NOT ";
	std::cout << "probable prime" << std::endl << "\t";
	mpz_t pm1;
	mpz_init_set(pm1, dss->p);
	mpz_sub_ui(pm1, pm1, 1L);
	std::cout << "(p-1) = ";
	for (size_t i = 0; i < PRIMES_SIZE; i++)
	{
		if (mpz_divisible_ui_p(pm1, primes[i]))
			std::cout << primes[i] << " * ";
	}
	std::cout << "...";
	if (mpz_divisible_p(pm1, dss->q))
		std::cout << " * q";
	std::cout << std::endl << "\t";
	std::cout << "q is ";
	if (!mpz_probab_prime_p(dss->q, TMCG_MR_ITERATIONS))
		std::cout << "NOT ";
	std::cout << "probable prime" << std::endl << "\t";
	mpz_set(pm1, dss->q);
	mpz_sub_ui(pm1, pm1, 1L);
	std::cout << "(q-1) = ";
	for (size_t i = 0; i < PRIMES_SIZE; i++)
	{
		if (mpz_divisible_ui_p(pm1, primes[i]))
			std::cout << primes[i] << " * ";
	}
	std::cout << "..." << std::endl << "\t";
	std::cout << "g is ";
	mpz_powm(pm1, dss->g, dss->q, dss->p);
	if (mpz_cmp_ui(pm1, 1L))
		std::cout << "NOT ";
	std::cout << "generator of G_q" << std::endl << "\t";
	std::cout << "h is ";
	mpz_powm(pm1, dss->h, dss->q, dss->p);
	if (mpz_cmp_ui(pm1, 1L))
		std::cout << "NOT ";
	std::cout << "generator of G_q" << std::endl;
	std::cout << "Security level of public key: " << std::endl << "\t";
	std::cout << "|y| = " << mpz_sizeinbase(dss->y, 2L) << " bit";
	std::cout << std::endl << "\t";
	std::cout << "y is ";
	mpz_powm(pm1, dss->y, dss->q, dss->p);
	if (mpz_cmp_ui(pm1, 1L))
		std::cout << "NOT ";
	std::cout << "element of G_q" << std::endl;
	mpz_clear(pm1);
	if (dss_n != 0)
	{
		std::cout << "Threshold parameter set of primary key (tDSS): " << std::endl << "\t";
		std::cout << "n = " << dss->n << ", s = " << dss->t << std::endl;
		std::cout << "Set of non-disqualified parties of primary key (tDSS): " << std::endl << "\t" << "QUAL = { ";
		for (size_t i = 0; i < dss->QUAL.size(); i++)
			std::cout << "P_" << dss->QUAL[i] << " ";
		std::cout << "}" << std::endl;
		if (dss->dkg->x_rvss->QUAL.size())
		{
			std::cout << "Set of non-disqualified parties of x_rvss subprotocol: " << std::endl << "\t" << "QUAL = { ";
			for (size_t i = 0; i < dss->dkg->x_rvss->QUAL.size(); i++)
				std::cout << "P_" << dss->dkg->x_rvss->QUAL[i] << " ";
			std::cout << "}" << std::endl;
		}
		std::cout << "Unique identifier of this party (tDSS): " << std::endl << "\t";
		std::cout << "P_" << dss->i << std::endl;
		std::cout << "Canonicalized peer list (CAPL): " << std::endl;
		for (size_t i = 0; i < CAPL.size(); i++)
			std::cout << "\t" << "P_" << ((dss->dkg->x_rvss->QUAL.size())?(i):(dss->QUAL[i])) << "\t" << CAPL[i] << std::endl;
	}
	if (sub.size() && (dkg != NULL))
	{
		std::cout << "OpenPGP V4 Key ID of subkey: " << std::endl << std::hex << std::uppercase << "\t";
		for (size_t i = 0; i < subkeyid.size(); i++)
			std::cout << std::setfill('0') << std::setw(2) << std::right << (int)subkeyid[i] << " ";
		std::cout << std::dec << std::endl;
		tmcg_octets_t sub_hashing, sub_fpr;
		for (size_t i = 6; i < sub.size(); i++)
			sub_hashing.push_back(sub[i]);
		CallasDonnerhackeFinneyShawThayerRFC4880::FingerprintCompute(sub_hashing, sub_fpr);
		std::cout << "OpenPGP V4 fingerprint of subkey: " << std::endl << std::hex << std::uppercase << "\t";
		for (size_t i = 0; i < sub_fpr.size(); i++)
			std::cout << std::setfill('0') << std::setw(2) << std::right << (int)sub_fpr[i] << " ";
		std::cout << std::dec << std::endl;
		std::cout << "Security level of domain parameter set: " << std::endl << "\t"; 
		std::cout << "|p| = " << mpz_sizeinbase(dkg->p, 2L) << " bit, ";
		std::cout << "|q| = " << mpz_sizeinbase(dkg->q, 2L) << " bit, ";
		std::cout << "|g| = " << mpz_sizeinbase(dkg->g, 2L) << " bit, ";
		std::cout << "|h| = " << mpz_sizeinbase(dkg->h, 2L) << " bit" << std::endl << "\t";
		std::cout << "p is ";
		if (!mpz_probab_prime_p(dkg->p, TMCG_MR_ITERATIONS))
			std::cout << "NOT ";
		std::cout << "probable prime" << std::endl << "\t";
		mpz_init_set(pm1, dkg->p);
		mpz_sub_ui(pm1, pm1, 1L);
		std::cout << "(p-1) = ";
		for (size_t i = 0; i < PRIMES_SIZE; i++)
		{
			if (mpz_divisible_ui_p(pm1, primes[i]))
				std::cout << primes[i] << " * ";
		}
		std::cout << "...";
		if (mpz_divisible_p(pm1, dkg->q))
			std::cout << " * q";
		std::cout << std::endl << "\t";
		std::cout << "q is ";
		if (!mpz_probab_prime_p(dkg->q, TMCG_MR_ITERATIONS))
			std::cout << "NOT ";
		std::cout << "probable prime" << std::endl << "\t";
		mpz_set(pm1, dkg->q);
		mpz_sub_ui(pm1, pm1, 1L);
		std::cout << "(q-1) = ";
		for (size_t i = 0; i < PRIMES_SIZE; i++)
		{
			if (mpz_divisible_ui_p(pm1, primes[i]))
				std::cout << primes[i] << " * ";
		}
		std::cout << "..." << std::endl << "\t";
		std::cout << "g is ";
		mpz_powm(pm1, dkg->g, dkg->q, dkg->p);
		if (mpz_cmp_ui(pm1, 1L))
			std::cout << "NOT ";
		std::cout << "generator of G_q" << std::endl << "\t";
		std::cout << "h is ";
		mpz_powm(pm1, dkg->h, dkg->q, dkg->p);
		if (mpz_cmp_ui(pm1, 1L))
			std::cout << "NOT ";
		std::cout << "generator of G_q" << std::endl;
		std::cout << "Security level of public key: " << std::endl << "\t";
		std::cout << "|y| = " << mpz_sizeinbase(dkg->y, 2L) << " bit";
		std::cout << std::endl << "\t";
		std::cout << "y is ";
		mpz_powm(pm1, dkg->y, dkg->q, dkg->p);
		if (mpz_cmp_ui(pm1, 1L))
			std::cout << "NOT ";
		std::cout << "element of G_q" << std::endl;
		mpz_clear(pm1);
		std::cout << "Threshold parameter set of subkey (DKG): " << std::endl << "\t";
		std::cout << "n = " << dkg->n << ", t = " << dkg->t << std::endl;
		std::cout << "Set of non-disqualified parties of subkey (DKG): " << std::endl << "\t" << "QUAL = { ";
		for (size_t i = 0; i < dkg->QUAL.size(); i++)
			std::cout << "P_" << dkg->QUAL[i] << " ";
		std::cout << "}" << std::endl;
		std::cout << "Unique identifier of this party (DKG): " << std::endl << "\t";
		std::cout << "P_" << dkg->i << std::endl;
		std::cout << "Public verification keys (DKG): " << std::endl;
		for (size_t i = 0; i < dkg->v_i.size(); i++)
			std::cout << "\t" << "v_" << i << " = " << dkg->v_i[i] << std::endl;
	}

	// restore default formatting
	std::cout.copyfmt(oldcoutstate);

	// migrate peer identity, if requested by option "-m OLDPEER NEWPEER"
	if (migrate_peer_from.length() && migrate_peer_to.length())
	{
		if ((dss_n != 0) && (CAPL.size() > 0))
		{
			std::vector<std::string> CAPL_new;
			size_t capl_idx = CAPL.size();
			for (size_t i = 0; i < CAPL.size(); i++)
			{
				if (migrate_peer_from == CAPL[i])
					capl_idx = i;
				CAPL_new.push_back(CAPL[i]);
			}
			if (capl_idx == CAPL.size())
			{
				std::cerr << "ERROR: migration peer \"" << migrate_peer_from << "\" not contained in CAPL" << std::endl;
				if (sub.size() && (dkg != NULL))
					delete dkg;
				delete dss;
				release_mpis();
				return -1;
			}
			else
				CAPL_new[capl_idx] = migrate_peer_to; // migration to NEWPEER
			// canonicalize new peer list and check for persitent lexicographical order
			std::sort(CAPL_new.begin(), CAPL_new.end());
			std::vector<std::string>::iterator it = std::unique(CAPL_new.begin(), CAPL_new.end());
			CAPL_new.resize(std::distance(CAPL_new.begin(), it));
			if (CAPL_new.size() == CAPL.size())
			{
				for (size_t i = 0; i < CAPL_new.size(); i++)
				{
					if ((i != capl_idx) && (CAPL_new[i] != CAPL[i]))
					{
						std::cerr << "ERROR: migration from peer \"" << migrate_peer_from << "\" to \"" <<
							migrate_peer_to << "\" failed (wrong order of CAPL)" << std::endl;
						if (sub.size() && (dkg != NULL))
							delete dkg;
						delete dss;
						release_mpis();
						return -1;
					}
				}
			}
			else
			{
				std::cerr << "ERROR: migration from peer \"" << migrate_peer_from << "\" to \"" << 
					migrate_peer_to << "\" failed (identity occupied)" << std::endl;
				if (sub.size() && (dkg != NULL))
					delete dkg;
				delete dss;
				release_mpis();
				return -1;
			}
			// create an OpenPGP DSA-based primary key using refreshed values from tDSS
			gcry_mpi_t p, q, g, h, y, n, t, i, qualsize, x_rvss_qualsize, x_i, xprime_i;
			std::vector<gcry_mpi_t> qual, x_rvss_qual;
			std::vector< std::vector<gcry_mpi_t> > c_ik;
			p = gcry_mpi_new(2048);
			if (!mpz_get_gcry_mpi(p, dss->p))
			{
				std::cerr << "ERROR: migrate -- mpz_get_gcry_mpi() failed for p" << std::endl;
				gcry_mpi_release(p);
				if (sub.size() && (dkg != NULL))
					delete dkg;
				delete dss;
				release_mpis();
				return -1;
			}
			q = gcry_mpi_new(2048);
			if (!mpz_get_gcry_mpi(q, dss->q))
			{
				std::cerr << "ERROR: migrate -- mpz_get_gcry_mpi() failed for q" << std::endl;
				gcry_mpi_release(p);
				gcry_mpi_release(q);
				if (sub.size() && (dkg != NULL))
					delete dkg;
				delete dss;
				release_mpis();
				return -1;	
			}
			g = gcry_mpi_new(2048);
			if (!mpz_get_gcry_mpi(g, dss->g))
			{
				std::cerr << "ERROR: migrate -- mpz_get_gcry_mpi() failed for g" << std::endl;
				gcry_mpi_release(p);
				gcry_mpi_release(q);
				gcry_mpi_release(g);
				if (sub.size() && (dkg != NULL))
					delete dkg;
				delete dss;
				release_mpis();
				return -1;
			}
			h = gcry_mpi_new(2048);
			if (!mpz_get_gcry_mpi(h, dss->h))
			{
				std::cerr << "ERROR: migrate -- mpz_get_gcry_mpi() failed for h" << std::endl;
				gcry_mpi_release(p);
				gcry_mpi_release(q);
				gcry_mpi_release(g);
				gcry_mpi_release(h);
				if (sub.size() && (dkg != NULL))
					delete dkg;
				delete dss;
				release_mpis();
				return -1;
			}
			y = gcry_mpi_new(2048);
			if (!mpz_get_gcry_mpi(y, dss->y))
			{
				std::cerr << "ERROR: migrate -- mpz_get_gcry_mpi() failed for y" << std::endl;
				gcry_mpi_release(p);
				gcry_mpi_release(q);
				gcry_mpi_release(g);
				gcry_mpi_release(h);
				gcry_mpi_release(y);
				if (sub.size() && (dkg != NULL))
					delete dkg;
				delete dss;
				release_mpis();
				return -1;
			}
			x_i = gcry_mpi_new(2048);
			if (!mpz_get_gcry_mpi(x_i, dss->x_i))
			{
				std::cerr << "ERROR: migrate -- mpz_get_gcry_mpi() failed for x_i" << std::endl;
				gcry_mpi_release(p);
				gcry_mpi_release(q);
				gcry_mpi_release(g);
				gcry_mpi_release(h);
				gcry_mpi_release(y);
				gcry_mpi_release(x_i);
				if (sub.size() && (dkg != NULL))
					delete dkg;
				delete dss;
				release_mpis();
				return -1;
			}
			xprime_i = gcry_mpi_new(2048);
			if (!mpz_get_gcry_mpi(xprime_i, dss->xprime_i))
			{
				std::cerr << "ERROR: migrate -- mpz_get_gcry_mpi() failed for xprime_i" << std::endl;
				gcry_mpi_release(p);
				gcry_mpi_release(q);
				gcry_mpi_release(g);
				gcry_mpi_release(h);
				gcry_mpi_release(y);
				gcry_mpi_release(x_i);
				gcry_mpi_release(xprime_i);
				if (sub.size() && (dkg != NULL))
					delete dkg;
				delete dss;
				release_mpis();
				return -1;
			}
			n = gcry_mpi_set_ui(NULL, dss->n);
			t = gcry_mpi_set_ui(NULL, dss->t);
			i = gcry_mpi_set_ui(NULL, dss->i);
			qualsize = gcry_mpi_set_ui(NULL, dss->QUAL.size());
			for (size_t j = 0; j < dss->QUAL.size(); j++)
			{
				gcry_mpi_t tmp = gcry_mpi_set_ui(NULL, dss->QUAL[j]);
				qual.push_back(tmp);
			}
			x_rvss_qualsize = gcry_mpi_set_ui(NULL, dss->dkg->x_rvss->QUAL.size());
			for (size_t j = 0; j < dss->dkg->x_rvss->QUAL.size(); j++)
			{
				gcry_mpi_t tmp = gcry_mpi_set_ui(NULL, dss->dkg->x_rvss->QUAL[j]);
				x_rvss_qual.push_back(tmp);
			}
			c_ik.resize(dss->n);
			for (size_t j = 0; j < c_ik.size(); j++)
			{
				for (size_t k = 0; k <= dss->t; k++)
				{
					gcry_mpi_t tmp;
					tmp = gcry_mpi_new(2048);
					if (!mpz_get_gcry_mpi(tmp, dss->dkg->x_rvss->C_ik[j][k]))
					{
						std::cerr << "ERROR: migrate -- mpz_get_gcry_mpi() failed for dss->dkg->x_rvss->C_ik[j][k]" << std::endl;
						gcry_mpi_release(p);
						gcry_mpi_release(q);
						gcry_mpi_release(g);
						gcry_mpi_release(h);
						gcry_mpi_release(y);
						gcry_mpi_release(x_i);
						gcry_mpi_release(xprime_i);
						gcry_mpi_release(n);
						gcry_mpi_release(t);
						gcry_mpi_release(i);
						gcry_mpi_release(qualsize);
						for (size_t jj = 0; jj < qual.size(); jj++)
							gcry_mpi_release(qual[jj]);
						gcry_mpi_release(x_rvss_qualsize);
						for (size_t jj = 0; jj < x_rvss_qual.size(); jj++)
							gcry_mpi_release(x_rvss_qual[jj]);
						for (size_t jj = 0; jj < c_ik.size(); jj++)
							for (size_t kk = 0; kk < c_ik[jj].size(); kk++)
								gcry_mpi_release(c_ik[jj][kk]);
						gcry_mpi_release(tmp);
						if (sub.size() && (dkg != NULL))
							delete dkg;
						delete dss;
						release_mpis();
						return -1;
					}
					c_ik[j].push_back(tmp);
				}
			}
			sec.clear(); // clear old private key (tDSS)
			CallasDonnerhackeFinneyShawThayerRFC4880::PacketSecEncodeExperimental107(ckeytime, p, q, g, h, y, 
				n, t, i, qualsize, qual, x_rvss_qualsize, x_rvss_qual, CAPL_new, c_ik, x_i, xprime_i, passphrase, sec);
			gcry_mpi_release(p);
			gcry_mpi_release(q);
			gcry_mpi_release(g);
			gcry_mpi_release(h);
			gcry_mpi_release(y);
			gcry_mpi_release(x_i);
			gcry_mpi_release(xprime_i);
			gcry_mpi_release(n);
			gcry_mpi_release(t);
			gcry_mpi_release(i);
			gcry_mpi_release(qualsize);
			for (size_t j = 0; j < qual.size(); j++)
				gcry_mpi_release(qual[j]);
			gcry_mpi_release(x_rvss_qualsize);
			for (size_t j = 0; j < x_rvss_qual.size(); j++)
				gcry_mpi_release(x_rvss_qual[j]);
			for (size_t j = 0; j < c_ik.size(); j++)
				for (size_t k = 0; k < c_ik[j].size(); k++)
					gcry_mpi_release(c_ik[j][k]);
			// export updated private key in OpenPGP armor format
			tmcg_octets_t all;
			std::string armor;
			std::stringstream secfilename;
			secfilename << thispeer << "_dkg-sec.asc";
			all.insert(all.end(), sec.begin(), sec.end());
			all.insert(all.end(), uid.begin(), uid.end());
			all.insert(all.end(), uidsig.begin(), uidsig.end());
			if (sub.size())
			{
				all.insert(all.end(), ssb.begin(), ssb.end());
				all.insert(all.end(), subsig.begin(), subsig.end());
			}
			CallasDonnerhackeFinneyShawThayerRFC4880::ArmorEncode(5, all, armor);
			if (opt_verbose > 1)
				std::cout << armor << std::endl;
			std::ofstream secofs((secfilename.str()).c_str(), std::ofstream::out | std::ofstream::trunc);
			if (!secofs.good())
			{
				std::cerr << "ERROR: opening private key file failed" << std::endl;
				if (sub.size() && (dkg != NULL))
					delete dkg;
				delete dss;
				release_mpis();
				return -1;
			}
			secofs << armor;
			if (!secofs.good())
			{
				std::cerr << "ERROR: writing private key file failed" << std::endl;
				if (sub.size() && (dkg != NULL))
					delete dkg;
				delete dss;
				release_mpis();
				return -1;
			}
			secofs.close();
			if (opt_verbose)
				std::cout << "INFO: migration from peer \"" << migrate_peer_from << "\" to \"" << migrate_peer_to << "\" finished" << std::endl;
		}
		else
			std::cerr << "WARNING: migration not possible due to missing or bad tDSS key" << std::endl;
	}

	// release
	if (sub.size() && (dkg != NULL))
		delete dkg;
	delete dss;
	release_mpis();
	
	return 0;
}

