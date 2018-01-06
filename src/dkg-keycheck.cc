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

#include <iomanip>
#include <vector>
#include <map>
#include <string>
#include <algorithm>
#include <cstdio>
#include <ctime>

#include <libTMCG.hh>

#include "dkg-common.hh"

std::vector<std::string>		peers;

std::string				passphrase, userid, ifilename, kfilename;
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
gcry_mpi_t				dsa_r, dsa_s, elg_r, elg_s;
gcry_mpi_t 				gk, myk, sig_r, sig_s;

int 					opt_verbose = 0;
bool 					opt_binary = false;

#define TRIVIAL_SIZE 1024
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
	(int argc, char **argv)
{
	static const char *usage = "dkg-keycheck [OPTIONS] KEYFILE";
	static const char *about = PACKAGE_STRING " " PACKAGE_URL;
	static const char *version = PACKAGE_VERSION " (" PACKAGE_NAME ")";

	// parse command line arguments
	for (size_t i = 0; i < (size_t)(argc - 1); i++)
	{
		std::string arg = argv[i+1];
		if ((arg.find("--") == 0) || (arg.find("-b") == 0) || (arg.find("-v") == 0) || (arg.find("-h") == 0) || (arg.find("-V") == 0))
		{
			if ((arg.find("-h") == 0) || (arg.find("--help") == 0))
			{
				std::cout << usage << std::endl;
				std::cout << about << std::endl;
				std::cout << "Arguments mandatory for long options are also mandatory for short options." << std::endl;
				std::cout << "  -b, --binary   consider KEYFILE as binary input" << std::endl;
				std::cout << "  -h, --help     print this help" << std::endl;
				std::cout << "  -v, --version  print the version number" << std::endl;
				std::cout << "  -V, --verbose  turn on verbose output" << std::endl;
				return 0; // not continue
			}
			if ((arg.find("-b") == 0) || (arg.find("--binary") == 0))
				opt_binary = true;
			if ((arg.find("-v") == 0) || (arg.find("--version") == 0))
			{
				std::cout << "dkg-keycheck v" << version << std::endl;
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
		std::cout << "INFO: using LibTMCG version " << version_libTMCG() << std::endl;

	// read and parse the public key (no ElGamal subkey required)
	std::string armored_pubkey;
	if (opt_binary && !read_binary_key_file(kfilename, 6, armored_pubkey))
		return -1;
	if (!opt_binary && !read_key_file(kfilename, armored_pubkey))
		return -1;
	init_mpis();
	time_t ckeytime = 0, ekeytime = 0;
	if (!parse_public_key(armored_pubkey, ckeytime, ekeytime, false))
	{
		std::cerr << "ERROR: cannot use the provided public key" << std::endl;
		release_mpis();
		return -1;
	}

	// convert mpis
	if (!mpz_set_gcry_mpi(dsa_p, dss_p) || !mpz_set_gcry_mpi(dsa_q, dss_q) || !mpz_set_gcry_mpi(dsa_g, dss_g) || !mpz_set_gcry_mpi(dsa_y, dss_y))
	{
		std::cerr << "ERROR: cannot convert DSA key material" << std::endl;
		release_mpis();
		return -1;
	}
	if (!mpz_set_gcry_mpi(elg_p, dkg_p) || !mpz_set_gcry_mpi(elg_g, dkg_g) || !mpz_set_gcry_mpi(elg_y, dkg_y))
	{
		std::cerr << "ERROR: cannot convert ElGamal key material" << std::endl;
		release_mpis();
		return -1;
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
	std::cout << "Security level of DSA domain parameter set: " << std::endl << "\t";
	std::cout << "|p| = " << mpz_sizeinbase(dss_p, 2L) << " bit, ";
	std::cout << "|q| = " << mpz_sizeinbase(dss_q, 2L) << " bit, ";
	std::cout << "|g| = " << mpz_sizeinbase(dss_g, 2L) << " bit";
	std::cout << std::endl << "\t";
	std::cout << "p is ";
	if (!mpz_probab_prime_p(dss_p, TMCG_MR_ITERATIONS))
		std::cout << "NOT ";
	std::cout << "probable prime" << std::endl << "\t";
	mpz_t pm1;
	mpz_init_set(pm1, dss_p);
	mpz_sub_ui(pm1, pm1, 1L);
	std::cout << "(p-1) = ";
	for (size_t i = 0; i < PRIMES_SIZE; i++)
	{
		if (mpz_divisible_ui_p(pm1, primes[i]))
			std::cout << primes[i] << " * ";
	}
	std::cout << "...";
	if (mpz_divisible_p(pm1, dss_q))
		std::cout << " * q";
	std::cout << std::endl << "\t";
	std::cout << "q is ";
	if (!mpz_probab_prime_p(dss_q, TMCG_MR_ITERATIONS))
		std::cout << "NOT ";
	std::cout << "probable prime" << std::endl << "\t";
	mpz_set(pm1, dss_q);
	mpz_sub_ui(pm1, pm1, 1L);
	std::cout << "(q-1) = ";
	for (size_t i = 0; i < PRIMES_SIZE; i++)
	{
		if (mpz_divisible_ui_p(pm1, primes[i]))
			std::cout << primes[i] << " * ";
	}
	std::cout << "..." << std::endl << "\t";
	std::cout << "g is ";
	mpz_powm(pm1, dss_g, dss_q, dss_p);
	if (mpz_cmp_ui(pm1, 1L))
		std::cout << "NOT ";
	std::cout << "generator of G_q" << std::endl << "\t";
	mpz_t tmp, foo, bar;
	mpz_init(tmp), mpz_init_set_ui(foo, 2L), mpz_init(bar);
	std::cout << "g is ";
	mpz_sub_ui(pm1, dss_p, 1L);
	mpz_tdiv_qr(bar, tmp, pm1, dss_q);
	mpz_powm(tmp, foo, bar, dss_p);
	if (mpz_cmp(tmp, dss_g))
		std::cout << "not ";
	std::cout << "canonical (i.e. 2^((p-1)/q) mod p)" << std::endl;
	mpz_clear(foo), mpz_clear(bar);
	std::cout << "Security level of public key: " << std::endl << "\t";
	std::cout << "|y| = " << mpz_sizeinbase(dss_y, 2L) << " bit";
	std::cout << std::endl << "\t";
	std::cout << "y is ";
	mpz_powm(pm1, dss_y, dss_q, dss_p);
	if (mpz_cmp_ui(pm1, 1L))
		std::cout << "NOT ";
	std::cout << "element of G_q" << std::endl << "\t";
	mpz_t tmp_r;
	mpz_init(tmp_r);
	if (!mpz_set_gcry_mpi(dsa_r, tmp_r))
		std::cerr << "ERROR: bad signature (cannot convert dsa_r)" << std::endl << "\t";
	bool trivial = false, suspicious = false;
	for (size_t i = 0; i < TRIVIAL_SIZE; i++)
	{
		mpz_powm_ui(pm1, dss_g, i, dss_p);
		if (!mpz_cmp(dss_y, pm1))
		{
			trivial = true;
			break;
		}
		mpz_mod(pm1, pm1, dss_q);
		if (!mpz_cmp(tmp_r, pm1))
		{
			suspicious = true;
			break;
		}
		if (i > 0)
		{
			mpz_set_ui(tmp, i);
			mpz_neg(tmp, tmp);
			mpz_powm(pm1, dss_g, tmp, dss_p);
			if (!mpz_cmp(dss_y, pm1))
			{
				trivial = true;
				break;
			}
			mpz_mod(pm1, pm1, dss_q);
			if (!mpz_cmp(tmp_r, pm1))
			{
				suspicious = true;
				break;
			}
		}
	}
	if (sub.size())
	{
		if (!mpz_set_gcry_mpi(elg_r, tmp))
			std::cerr << "ERROR: bad signature (cannot convert elg_r)" << std::endl << "\t";
		if (!mpz_cmp(tmp, tmp_r))
			std::cout << "r is EQUAL for both signatures (e.g. same k used)" << std::endl << "\t";
		mpz_set(tmp_r, tmp);
		for (size_t i = 0; i < TRIVIAL_SIZE; i++)
		{
			mpz_powm_ui(pm1, dss_g, i, dss_p);
			mpz_mod(pm1, pm1, dss_q);
			if (!mpz_cmp(tmp_r, pm1))
			{
				suspicious = true;
				break;
			}
			if (i > 0)
			{
				mpz_set_ui(tmp, i);
				mpz_neg(tmp, tmp);
				mpz_powm(pm1, dss_g, tmp, dss_p);
				mpz_mod(pm1, pm1, dss_q);
				if (!mpz_cmp(tmp_r, pm1))
				{
					suspicious = true;
					break;
				}
			}
		}
	}
	if (!trivial)
		std::cout << "y is not trivial" << std::endl << "\t";
	else
		std::cout << "y is TRIVIAL, i.e., y = g^c mod p (for some |c| < " << TRIVIAL_SIZE << ")" << std::endl << "\t";
	if (suspicious)
		std::cout << "r is SUSPICIOUS (small k used)" << std::endl << "\t";
	std::cout << "Legendre-Jacobi symbol (y/p) is " << mpz_jacobi(dss_y, dss_p) << std::endl;
	mpz_clear(pm1);
	mpz_clear(tmp);
	mpz_clear(tmp_r);
	if (sub.size())
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
		std::cout << "|p| = " << mpz_sizeinbase(dkg_p, 2L) << " bit, ";
		std::cout << "|g| = " << mpz_sizeinbase(dkg_g, 2L) << " bit" << std::endl << "\t";
		std::cout << "p is ";
		if (!mpz_probab_prime_p(dkg_p, TMCG_MR_ITERATIONS))
			std::cout << "NOT ";
		std::cout << "probable prime" << std::endl << "\t";
		mpz_init_set(pm1, dkg_p);
		mpz_sub_ui(pm1, pm1, 1L);
		std::vector<unsigned int> small_factors;
		std::cout << "(p-1) = ";
		for (size_t i = 0; i < PRIMES_SIZE; i++)
		{
			if (mpz_divisible_ui_p(pm1, primes[i]))
			{
				std::cout << primes[i] << " * ";
				small_factors.push_back(primes[i]);
			}
		}
		std::cout << "...";
		if (mpz_divisible_p(pm1, dss_q))
			std::cout << " * q";
		std::cout << std::endl << "\t";
		if (mpz_cmp_ui(dkg_g, 256L) <= 0)
		{
			std::cout << "g = " << dkg_g << std::endl << "\t";
		}
		std::cout << "g is ";
		mpz_powm(pm1, dkg_g, dss_q, dkg_p);
		if (mpz_cmp_ui(pm1, 1L))
			std::cout << "NOT ";
		std::cout << "generator of G_q" << std::endl << "\t";
		mpz_init(tmp), mpz_init(bar);
		std::cout << "subgroup generated by g ";
		mpz_sub_ui(pm1, dkg_p, 1L);
		for (std::vector<unsigned int>::const_iterator sfi = small_factors.begin(); sfi != small_factors.end(); ++sfi)
		{
			mpz_set_ui(bar, *sfi);
			mpz_powm(tmp, dkg_g, bar, dkg_p);
			if (!mpz_cmp_ui(tmp, 1L))
				std::cout << "is VERY SMALL (" << *sfi << " elements) ";
			else
				std::cout << "is okay ";
		}
		std::cout << std::endl;
		mpz_clear(bar);
		std::cout << "Security level of public key: " << std::endl << "\t";
		std::cout << "|y| = " << mpz_sizeinbase(dkg_y, 2L) << " bit";
		std::cout << std::endl << "\t";
		std::cout << "y is ";
		mpz_powm(pm1, dkg_y, dss_q, dkg_p);
		if (mpz_cmp_ui(pm1, 1L))
			std::cout << "NOT ";
		std::cout << "element of G_q" << std::endl << "\t";
		trivial = false;
		for (size_t i = 0; i < TRIVIAL_SIZE; i++)
		{
			mpz_powm_ui(pm1, dkg_g, i, dkg_p);
			if (!mpz_cmp(dkg_y, pm1))
			{
				trivial = true;
				break;
			}
			if (i > 0)
			{
				mpz_set_ui(tmp, i);
				mpz_neg(tmp, tmp);
				mpz_powm(pm1, dkg_g, tmp, dkg_p);
				if (!mpz_cmp(dkg_y, pm1))
				{
					trivial = true;
					break;
				}
			}
		}
		mpz_clear(tmp);
		if (!trivial)
			std::cout << "y is not trivial" << std::endl << "\t";
		else
			std::cout << "y is TRIVIAL, i.e., y = g^c mod p (for some |c| < " << TRIVIAL_SIZE << ")" << std::endl << "\t";
		std::cout << "Legendre-Jacobi symbol (y/p) is " << mpz_jacobi(dkg_y, dkg_p) << std::endl;
		mpz_clear(pm1);
	}

	// restore default formatting
	std::cout.copyfmt(oldcoutstate);

	// release mpis and keys
	release_mpis();
	
	return 0;
}
