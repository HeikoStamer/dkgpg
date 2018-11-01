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

#include <iostream>
#include <sstream>
#include <vector>
#include <map>
#include <string>
#include <algorithm>
#include <cstdio>
#include <ctime>
#include <climits>

#include <libTMCG.hh>
#include "dkg-io.hh"

#define TRIVIAL_SIZE 1024
#define PRIMES_SIZE 669
unsigned long int primes[] = {
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

bool decomp
	(mpz_srcptr a, std::map<size_t, size_t> &result)
{
	mpz_t foo;
	bool full = false;

	result.clear();
	mpz_init_set(foo, a);
	for (size_t i = 0; i < PRIMES_SIZE; i++)
	{
		size_t power = 0;
		while (mpz_divisible_ui_p(foo, primes[i]))
		{
			power++;
			mpz_divexact_ui(foo, foo, primes[i]);
		}
		if (power)
			result[primes[i]] = power;
	}
	if (!mpz_cmp_ui(foo, 1L))
		full = true;
	mpz_clear(foo);
	return full;
}

bool order
	(mpz_srcptr a, mpz_srcptr phi_m,
	 const std::map<size_t, size_t> &phi_m_decomp, mpz_srcptr m,
	 mpz_ptr result)
{
	mpz_t foo;
	
	if (!mpz_cmp_ui(a, 1L))
	{
		mpz_set_ui(result, 1L);
		return true; // a is the identity element
	}
	mpz_init(foo);
	mpz_powm(foo, a, phi_m, m);
	if (mpz_cmp_ui(foo, 1L))
	{
		mpz_clear(foo);
		return false; // a is not an element of group G_m
	}
	else
	{
		mpz_t bar, baz;
		mpz_init(bar), mpz_init(baz);
		mpz_set(foo, phi_m);
		for (std::map<size_t, size_t>::const_iterator it = phi_m_decomp.begin();
			 it != phi_m_decomp.end(); ++it)
		{
			for (size_t i = 0; i < it->second; i++)
			{
				mpz_divexact_ui(bar, foo, it->first);
				mpz_powm(baz, a, bar, m);
				if (!mpz_cmp_ui(baz, 1L))
					mpz_set(foo, bar);
				else
					break;
			}
		}
		mpz_clear(bar), mpz_clear(baz);
	}
	mpz_set(result, foo);
	mpz_clear(foo);
	return true;
}

bool crt
	(const tmcg_mpz_vector_t &n, const std::vector<mpz_ptr> &a, mpz_ptr result)
{
	mpz_t sum, prod, foo, bar;

	if (n.size() != a.size())
		return false;
	mpz_init_set_ui(sum, 0L), mpz_init_set_ui(prod, 1L);
	mpz_init(foo), mpz_init(bar);
	for (size_t i = 0; i < n.size(); i++)
		mpz_mul(prod, prod, n[i]);
	for (size_t i = 0; i < n.size(); i++)
	{
		mpz_tdiv_q(foo, prod, n[i]);
		if (!mpz_invert(bar, foo, n[i]))
		{
			mpz_clear(sum), mpz_clear(prod);
			mpz_clear(foo), mpz_clear(bar);
			return false;
		}
		mpz_mul(bar, bar, foo);
		mpz_mul(bar, bar, a[i]);
		mpz_add(sum, sum, n[i]);
	}
	mpz_mod(result, sum, prod);
	mpz_clear(sum),	mpz_clear(prod);
	mpz_clear(foo), mpz_clear(bar);
	return true;
}

bool dlog
	(mpz_srcptr a, mpz_srcptr g, mpz_srcptr order_g,
	 const std::map<size_t, size_t> &order_g_decomp, mpz_srcptr m,
	 mpz_ptr result)
{
	mpz_t foo, bar, baz;
	bool found = false;
	std::vector<mpz_ptr> moduli, remainders;

	mpz_init(foo), mpz_init(bar), mpz_init(baz);
	mpz_powm(foo, a, order_g, m);
	if (mpz_cmp_ui(foo, 1L))
	{
		mpz_clear(foo), mpz_clear(bar), mpz_clear(baz);
		return false;
	}
	for (std::map<size_t, size_t>::const_iterator it = order_g_decomp.begin();
		 it != order_g_decomp.end(); ++it)
	{
		mpz_t idx, prime_to_power;
		mpz_init_set_ui(idx, 0L);
		mpz_init_set_ui(prime_to_power, 1L);
		for (size_t i = 0; i < it->second; i++)
			mpz_mul_ui(prime_to_power, prime_to_power, it->first);
		mpz_tdiv_q(foo, order_g, prime_to_power);
		mpz_powm(bar, g, foo, m);
		mpz_powm(baz, a, foo, m);
		found = false;
		do
		{
			mpz_powm(foo, bar, idx, m);
			if (!mpz_cmp(foo, baz))
			{
				mpz_ptr tmp1 = new mpz_t(), tmp2 = new mpz_t();
				mpz_init_set(tmp1, idx), mpz_init_set(tmp2, prime_to_power);
				remainders.push_back(tmp1);
				moduli.push_back(tmp2);
				found = true;
				break;
			}
			mpz_add_ui(idx, idx, 1L);
		}
		while (mpz_cmp(idx, prime_to_power));
		mpz_clear(idx);
		mpz_clear(prime_to_power);
		if (!found)
		{
			mpz_clear(foo), mpz_clear(bar), mpz_clear(baz);
			return false;
		}
	}
	mpz_clear(foo), mpz_clear(bar), mpz_clear(baz);
	found = crt(moduli, remainders, result);
	for (size_t i = 0; i < moduli.size(); i++)
	{
		mpz_clear(moduli[i]);
		delete [] moduli[i];
	}
	for (size_t i = 0; i < remainders.size(); i++)
	{
		mpz_clear(remainders[i]);
		delete [] remainders[i];
	}
	return found;
}

// check for ROCA fingerprint (stupid Infineon RSALib certified by BSI)
bool roca_check
	(mpz_srcptr rsa_modulus)
{
	bool roca_fingerprint = false;
	std::vector<size_t> roca_max_prime_idx;
	roca_max_prime_idx.push_back(39); // these values are from the ROCA paper
	roca_max_prime_idx.push_back(71);
	roca_max_prime_idx.push_back(126);
	roca_max_prime_idx.push_back(225);
	for (std::vector<size_t>::const_iterator it = roca_max_prime_idx.begin();
		 it != roca_max_prime_idx.end(); ++it)
	{
		mpz_t roca_generator, roca_generator_order, roca_m, roca_phi_m, tmp;
		mpz_init_set_ui(roca_generator, 65537L);
		mpz_init(roca_generator_order);
		mpz_init_set_ui(roca_m, 1L);
		mpz_init_set_ui(roca_phi_m, 1L);
		for (size_t i = 0; i < *it; i++)
		{
			mpz_mul_ui(roca_m, roca_m, primes[i]);
			mpz_mul_ui(roca_phi_m, roca_phi_m, (primes[i] - 1L));
		}
		std::map<size_t, size_t> roca_phi_m_decomp;
		if (!decomp(roca_phi_m, roca_phi_m_decomp))
		{
			std::cerr << "BUG: decomp() for roca_phi_m failed" << std::endl;
			mpz_clear(roca_generator);
			mpz_clear(roca_generator_order);
			mpz_clear(roca_m);
			mpz_clear(roca_phi_m);
			break;
		}
		if (!order(roca_generator, roca_phi_m, roca_phi_m_decomp, roca_m,
			roca_generator_order))
		{
			std::cerr << "BUG: order() for roca_generator failed" << std::endl;
			mpz_clear(roca_generator);
			mpz_clear(roca_generator_order);
			mpz_clear(roca_m);
			mpz_clear(roca_phi_m);
			break;
		}
		std::map<size_t, size_t> roca_generator_order_decomp;
		if (!decomp(roca_generator_order, roca_generator_order_decomp))
		{
			std::cerr << "BUG: decomp() for roca_generator_order failed" <<
				std::endl;
			mpz_clear(roca_generator);
			mpz_clear(roca_generator_order);
			mpz_clear(roca_m);
			mpz_clear(roca_phi_m);
			break;
		}
		mpz_init(tmp);
		if (dlog(rsa_modulus, roca_generator, roca_generator_order,
			roca_generator_order_decomp, roca_m, tmp))
		{
			roca_fingerprint = true;
		}
		mpz_clear(roca_generator);
		mpz_clear(roca_generator_order);
		mpz_clear(roca_m);
		mpz_clear(roca_phi_m);
		mpz_clear(tmp);
	}
	if (roca_fingerprint)
		return true;
	return false;
}

int rsa_check
	(mpz_srcptr rsa_n, mpz_srcptr rsa_e)
{
	int ret = 0;
	std::cout << "Public-key algorithm: " << std::endl << "\tRSA" << std::endl;
	std::cout << "Security level of public key: " << std::endl << "\t";
	std::cout << "|n| = " << mpz_sizeinbase(rsa_n, 2L) << " bit, ";
	if (mpz_cmp_ui(rsa_e, ULONG_MAX) < 0)
		std::cout << "e = " << mpz_get_ui(rsa_e);
	else
		std::cout << "|e| = " << mpz_sizeinbase(rsa_e, 2L) << " bit";
	std::cout << std::endl << "\t";
	std::cout << "n ";
	if (mpz_probab_prime_p(rsa_n, TMCG_MR_ITERATIONS))
	{
		std::cout << "IS PROBABLE PRIME" << std::endl << "\t";
		ret = -3; // return with non-null status code
	}
	else
		std::cout << "is not probable prime" << std::endl << "\t";
	for (size_t i = 1; i < 4; i++)
	{
		if (mpz_congruent_ui_p(rsa_n, i, 4L))
			std::cout << "n is congruent " << i << " mod 4" <<
				std::endl << "\t";
	}
	std::cout << "n = ";
	for (size_t i = 0; i < PRIMES_SIZE; i++)
	{
		if (mpz_divisible_ui_p(rsa_n, primes[i]))
		{
			std::cout << primes[i] << " * ";
			ret = -3; // return with non-null status code
		}
	}
	std::cout << "..." << std::endl << "\t";
	std::cout << "Legendre-Jacobi symbol (i/n): ";
	size_t pos = 0, neg = 0;
	for (size_t i = 1; i < 10000000; i++)
	{
		mpz_t tmp;
		mpz_init_set_ui(tmp, i);
		int jac = mpz_jacobi(tmp, rsa_n);
		if (jac == -1)
			neg++;
		if (jac == 1)
			pos++;
		if (jac == 0)
			std::cout << " ZERO for i = " << i << " ";
		mpz_clear(tmp);
	}
	std::cout << "#(+1) = " << pos << " #(-1) = " << neg << std::endl << "\t";
	if (roca_check(rsa_n))
	{
		std::cout << "n is SUSPICIOUS for the ROCA vulnerability" <<
			std::endl << "\t";
		ret = -3; // return with non-null status code
	}
	std::cout << "e is ";
	if (!mpz_probab_prime_p(rsa_e, TMCG_MR_ITERATIONS))
	{
		std::cout << "NOT ";
		ret = -3; // return with non-null status code
	}
	std::cout << "probable prime" << std::endl << "\t";
	std::cout << "e is ";
	if (mpz_cmp_ui(rsa_e, 41) < 0)
	{
		std::cout << "VERY SMALL" << std::endl;
		ret = -3; // return with non-null status code
	}
	else
		std::cout << "okay" << std::endl;
	return ret;
}

int rsa_check
	(mpz_srcptr rsa_p, mpz_srcptr rsa_q, mpz_srcptr rsa_d, mpz_srcptr rsa_n, mpz_srcptr rsa_e)
{
	int ret = 0;
	size_t nbits = mpz_sizeinbase(rsa_n, 2L);
	mpz_t pm1, qm1, tmp, foo, bar;
	std::cout << "\t";
	if (!mpz_probab_prime_p(rsa_p, TMCG_MR_ITERATIONS))
	{
		std::cout << "p IS NOT PROBABLE PRIME" << std::endl << "\t";
		ret = -3; // return with non-null status code
	}
	if (!mpz_probab_prime_p(rsa_q, TMCG_MR_ITERATIONS))
	{
		std::cout << "q IS NOT PROBABLE PRIME" << std::endl << "\t";
		ret = -3; // return with non-null status code
	}
	mpz_init_set(pm1, rsa_p), mpz_init_set(qm1, rsa_q); 
	mpz_sub_ui(pm1, pm1, 1L), mpz_sub_ui(qm1, qm1, 1L);
	mpz_init(tmp);
	mpz_gcd(tmp, pm1, rsa_e);
	if (mpz_cmp_ui(tmp, 1L))
	{
		std::cout << "p and e ARE NOT RELATIVELY PRIME" << std::endl << "\t";
		ret = -3; // return with non-null status code
	}
	mpz_gcd(tmp, qm1, rsa_e);
	if (mpz_cmp_ui(tmp, 1L))
	{
		std::cout << "q and e ARE NOT RELATIVELY PRIME" << std::endl << "\t";
		ret = -3; // return with non-null status code
	}
	mpz_init(foo), mpz_init(bar);
	mpz_mul(foo, rsa_p, rsa_q);
	if (mpz_cmp(foo, rsa_n) != 0)
	{
		std::cout << "n IS NOT p * q" << std::endl << "\t";
		ret = -3; // return with non-null status code
	}
	mpz_sub(foo, rsa_q, rsa_p);
	mpz_abs(foo, foo);
	mpz_set_ui(bar, 1L);
	mpz_mul_2exp(bar, bar, (nbits / 2) - 100);
	if (mpz_cmp(foo, bar) <= 0)
	{
		std::cout << "|p - q| IS NOT > 2^(nlen/2 - 100)" << std::endl << "\t";
		ret = -3; // return with non-null status code
	}
	mpz_set_ui(bar, 1L);
	mpz_mul_2exp(bar, bar, (nbits / 2) - 1);
	if (mpz_cmp(rsa_p, bar) <= 0)
	{
		std::cout << "p IS NOT > 2^(nlen/2 - 1)" << std::endl << "\t";
		ret = -3; // return with non-null status code
	}
	if (mpz_cmp(rsa_q, bar) <= 0)
	{
		std::cout << "q IS NOT > 2^(nlen/2 - 1)" << std::endl << "\t";
		ret = -3; // return with non-null status code
	}
	mpz_set_ui(bar, 1L);
	mpz_mul_2exp(bar, bar, (nbits / 2));
	if (mpz_cmp(rsa_d, bar) <= 0)
	{
		std::cout << "d IS NOT > 2^(nlen/2)" << std::endl << "\t";
		ret = -3; // return with non-null status code
	}
	mpz_lcm(tmp, pm1, qm1);
	if (mpz_cmp(rsa_d, tmp) >= 0)
	{
		std::cout << "d IS NOT < lcm(p-1,q-1)" << std::endl << "\t";
		ret = -3; // return with non-null status code
	}
	if (!mpz_invert(foo, rsa_e, tmp))
	{
		std::cout << "e IS NOT INVERTIBLE mod lcm(p-1,q-1)" << std::endl << "\t";
		ret = -3; // return with non-null status code
	}
	if (mpz_cmp(foo, rsa_d))
	{
		std::cout << "d IS NOT e^(-1) mod lcm(p-1,q-1)" << std::endl << "\t";
		ret = -3; // return with non-null status code
	}
	mpz_clear(foo), mpz_clear(bar);
	mpz_clear(tmp), mpz_clear(pm1), mpz_clear(qm1);
	if (ret == 0)
		std::cout << "RSA private key -- no conspicuousness found";
	else
		std::cout << "RSA private key -- CONSPICUOUSNESS found";
	std::cout << std::endl;	
	return ret;
}

int dsa_check
	(mpz_srcptr dsa_p, mpz_srcptr dsa_q, mpz_srcptr dsa_g, mpz_srcptr dsa_y)
{
	int ret = 0;
	std::cout << "Public-key algorithm: " << std::endl << "\tDSA" << std::endl;
	std::cout << "Security level of DSA domain parameter set: " <<
		std::endl << "\t";
	std::cout << "|p| = " << mpz_sizeinbase(dsa_p, 2L) << " bit, ";
	std::cout << "|q| = " << mpz_sizeinbase(dsa_q, 2L) << " bit, ";
	std::cout << "|g| = " << mpz_sizeinbase(dsa_g, 2L) << " bit";
	std::cout << std::endl << "\t";
	std::cout << "p is ";
	if (!mpz_probab_prime_p(dsa_p, TMCG_MR_ITERATIONS))
	{
		std::cout << "NOT ";
		ret = -3; // return with non-null status code
	}
	std::cout << "probable prime" << std::endl << "\t";
	mpz_t pm1;
	mpz_init_set(pm1, dsa_p);
	mpz_sub_ui(pm1, pm1, 1L);
	std::map<size_t, size_t> pm1_decomp;
	std::cout << "(p-1) = ";
	decomp(pm1, pm1_decomp);
	for (std::map<size_t, size_t>::const_iterator it = pm1_decomp.begin();
		 it != pm1_decomp.end(); ++it)
	{
		std::cout << it->first;
		if (it->second > 1)
			std::cout << "^" << it->second;
		std::cout << " * ";
	}
	std::cout << "...";
	if (mpz_divisible_p(pm1, dsa_q))
		std::cout << " * q";
	std::cout << std::endl << "\t";
	std::cout << "q is ";
	if (!mpz_probab_prime_p(dsa_q, TMCG_MR_ITERATIONS))
	{
		std::cout << "NOT ";
		ret = -3; // return with non-null status code
	}
	std::cout << "probable prime" << std::endl << "\t";
	mpz_set(pm1, dsa_q);
	mpz_sub_ui(pm1, pm1, 1L);
	std::cout << "(q-1) = ";
	decomp(pm1, pm1_decomp);
	for (std::map<size_t, size_t>::const_iterator it = pm1_decomp.begin();
		 it != pm1_decomp.end(); ++it)
	{
		std::cout << it->first;
		if (it->second > 1)
			std::cout << "^" << it->second;
		std::cout << " * ";
	}		
	std::cout << "..." << std::endl << "\t";
	std::cout << "g is ";
	mpz_powm(pm1, dsa_g, dsa_q, dsa_p);
	if (mpz_cmp_ui(pm1, 1L))
	{
		std::cout << "NOT ";
		ret = -3; // return with non-null status code
	}
	std::cout << "generator of G_q" << std::endl << "\t";
	mpz_t tmp, foo, bar;
	mpz_init(tmp), mpz_init_set_ui(foo, 2L), mpz_init(bar);
	std::cout << "g is ";
	mpz_sub_ui(pm1, dsa_p, 1L);
	mpz_tdiv_qr(bar, tmp, pm1, dsa_q);
	mpz_powm(tmp, foo, bar, dsa_p);
	if (mpz_cmp(tmp, dsa_g))
		std::cout << "not ";
	std::cout << "canonical (i.e. 2^((p-1)/q) mod p)" << std::endl;
	mpz_clear(foo), mpz_clear(bar);
	std::cout << "Security level of public key: " << std::endl << "\t";
	std::cout << "|y| = " << mpz_sizeinbase(dsa_y, 2L) << " bit";
	std::cout << std::endl << "\t";
	std::cout << "y is ";
	mpz_powm(pm1, dsa_y, dsa_q, dsa_p);
	if (mpz_cmp_ui(pm1, 1L))
	{
		std::cout << "NOT ";
		ret = -3; // return with non-null status code
	}
	std::cout << "element of G_q" << std::endl << "\t";
	bool trivial = false;
	for (size_t i = 0; i < TRIVIAL_SIZE; i++)
	{
		mpz_powm_ui(pm1, dsa_g, i, dsa_p);
		if (!mpz_cmp(dsa_y, pm1))
			trivial = true;
		mpz_mod(pm1, pm1, dsa_q);
		if ((i > 0) && mpz_invert(tmp, dsa_g, dsa_p))
		{
			mpz_set_ui(tmp, i);
			mpz_neg(tmp, tmp);
			mpz_powm(pm1, dsa_g, tmp, dsa_p);
			if (!mpz_cmp(dsa_y, pm1))
				trivial = true;
			mpz_mod(pm1, pm1, dsa_q);
		}
	}
	if (!trivial)
		std::cout << "y is not trivial" << std::endl << "\t";
	else
	{
		std::cout << "y is TRIVIAL, i.e., y = g^c mod p (for some |c| < " <<
			TRIVIAL_SIZE << ")" << std::endl << "\t";
		ret = -3; // return with non-null status code
	}
	std::cout << "Legendre-Jacobi symbol (y/p) is " <<
		mpz_jacobi(dsa_y, dsa_p) << std::endl;
	mpz_clear(pm1);
	mpz_clear(tmp);
	return ret;
}

int elg_check
	(mpz_srcptr elg_p, mpz_srcptr elg_g, mpz_srcptr elg_y, mpz_srcptr dsa_q)
{
	int ret = 0;
	mpz_t pm1, tmp, bar;
	std::cout << "Public-key algorithm: " << std::endl <<
		"\tElGamal" << std::endl;
	std::cout << "Security level of domain parameter set: " <<
		std::endl << "\t";
	std::cout << "|p| = " << mpz_sizeinbase(elg_p, 2L) << " bit, ";
	std::cout << "|g| = " << mpz_sizeinbase(elg_g, 2L) << " bit" <<
		std::endl << "\t";
	std::cout << "p is ";
	if (!mpz_probab_prime_p(elg_p, TMCG_MR_ITERATIONS))
	{
		std::cout << "NOT ";
		ret = -3; // return with non-null status code
	}
	std::cout << "probable prime" << std::endl << "\t";
	mpz_init_set(pm1, elg_p);
	mpz_sub_ui(pm1, pm1, 1L);
	std::map<size_t, size_t> pm1_decomp;
	std::cout << "(p-1) = ";
	decomp(pm1, pm1_decomp);
	for (std::map<size_t, size_t>::const_iterator it = pm1_decomp.begin();
		 it != pm1_decomp.end(); ++it)
	{
		std::cout << it->first;
		if (it->second > 1)
			std::cout << "^" << it->second;
		std::cout << " * ";
	}
	std::cout << "...";
	if (mpz_cmp_ui(dsa_q, 0L) && mpz_divisible_p(pm1, dsa_q))
		std::cout << " * q";
	std::cout << std::endl << "\t";
	if (mpz_cmp_ui(elg_g, 256L) <= 0)
	{
		std::cout << "g = " << elg_g << std::endl << "\t";
	}
	if (mpz_cmp_ui(dsa_q, 0L))
	{
		std::cout << "g is ";
		mpz_powm(pm1, elg_g, dsa_q, elg_p);
		if (mpz_cmp_ui(pm1, 1L))
			std::cout << "NOT ";
		std::cout << "generator of G_q" << std::endl << "\t";
	}
	mpz_init(tmp), mpz_init(bar);
	std::cout << "subgroup generated by g ";
	mpz_sub_ui(pm1, elg_p, 1L);
	for (std::map<size_t, size_t>::const_iterator it = pm1_decomp.begin();
		 it != pm1_decomp.end(); ++it)
	{
		mpz_ui_pow_ui(bar, it->first, it->second);
		mpz_powm(tmp, elg_g, bar, elg_p);
		if (!mpz_cmp_ui(tmp, 1L))
		{
			std::cout << "is VERY SMALL (" << it->first << "^" <<
				it->second << " elements) ";
			ret = -3; // return with non-null status code
		}
		else
			std::cout << "is okay ";
	}
	std::cout << std::endl;
	mpz_clear(bar);
	std::cout << "Security level of public key: " << std::endl << "\t";
	std::cout << "|y| = " << mpz_sizeinbase(elg_y, 2L) << " bit";
	std::cout << std::endl << "\t";
	if (mpz_cmp_ui(dsa_q, 0L))
	{
		std::cout << "y is ";
		mpz_powm(pm1, elg_y, dsa_q, elg_p);
		if (mpz_cmp_ui(pm1, 1L))
			std::cout << "NOT ";
		std::cout << "element of G_q" << std::endl << "\t";
	}
	bool trivial = false;
	for (size_t i = 0; i < TRIVIAL_SIZE; i++)
	{
		mpz_powm_ui(pm1, elg_g, i, elg_p);
		if (!mpz_cmp(elg_y, pm1))
			trivial = true;
		if (i > 0)
		{
			mpz_set_ui(tmp, i);
			mpz_neg(tmp, tmp);
			mpz_powm(pm1, elg_g, tmp, elg_p);
			if (!mpz_cmp(elg_y, pm1))
				trivial = true;
		}
	}
	mpz_clear(tmp);
	if (!trivial)
		std::cout << "y is not trivial" << std::endl << "\t";
	else
	{
		std::cout << "y is TRIVIAL, i.e., y = g^c mod p (for some |c| < " <<
			TRIVIAL_SIZE << ")" << std::endl << "\t";
		ret = -3; // return with non-null status code
	}
	std::cout << "Legendre-Jacobi symbol (y/p) is " <<
		mpz_jacobi(elg_y, elg_p) << std::endl;
	mpz_clear(pm1);
	return ret;
}

int sig_check_dsa
	(mpz_srcptr dsa_p, mpz_srcptr dsa_q, mpz_srcptr dsa_g, mpz_srcptr dsa_y,
	 mpz_srcptr dsa_r)
{
	int ret = 0;
	if (!mpz_cmp_ui(dsa_r, 1L))
	{
		std::cout << "r is WEAK (i.e. k = 0)" << std::endl << "\t";
		ret = -4; // return with non-null status code
	}
	mpz_t pm1, tmp;
	bool suspicious = false;
	mpz_init(pm1), mpz_init(tmp);
	mpz_mod(pm1, dsa_y, dsa_q);
	if (!mpz_cmp(dsa_r, pm1))
	{
		std::cout << "r is WEAK (i.e. k = x)" << std::endl << "\t";
		ret = -4; // return with non-null status code
	}
	for (size_t i = 0; i < TRIVIAL_SIZE; i++)
	{
		mpz_powm_ui(tmp, dsa_g, i, dsa_p);
		mpz_mod(tmp, tmp, dsa_q);
		if (!mpz_cmp(dsa_r, tmp))
			suspicious = true;
		if (i > 0)
		{
			mpz_set_ui(tmp, i);
			mpz_neg(tmp, tmp);
			mpz_powm(pm1, dsa_g, tmp, dsa_p);
			mpz_mod(pm1, pm1, dsa_q);
			if (!mpz_cmp(dsa_r, pm1))
				suspicious = true;
		}
	}
	if (suspicious)
	{
		std::cout << "r is SUSPICIOUS (small k used)" << std::endl << "\t";
		ret = -4; // return with non-null status code
	}
	mpz_clear(pm1), mpz_clear(tmp);
	return ret;
}

int main
	(int argc, char **argv)
{
	static const char *usage = "dkg-keycheck [OPTIONS] KEYFILE";
	static const char *about = PACKAGE_STRING " " PACKAGE_URL;
	static const char *version = PACKAGE_VERSION " (" PACKAGE_NAME ")";

	std::string	kfilename, filename, ofilename;
	int			opt_verbose = 0;
	bool		opt_b = false, opt_r = false, opt_p = false, opt_y = false;
	char		*opt_k = NULL;
	char		*opt_o = NULL;

	// parse command line arguments
	for (size_t i = 0; i < (size_t)(argc - 1); i++)
	{
		std::string arg = argv[i+1];
		// handle some options
		if ((arg.find("-k") == 0))
		{
			size_t idx = ++i;
			if ((idx < (size_t)(argc - 1)) && (opt_k == NULL))
			{
				kfilename = argv[i+1];
				opt_k = (char*)kfilename.c_str();
			}
			continue;
		}
		else if ((arg.find("-o") == 0))
		{
			size_t idx = ++i;
			if ((idx < (size_t)(argc - 1)) && (opt_o == NULL))
			{
				ofilename = argv[i+1];
				opt_o = (char*)ofilename.c_str();
			}
			continue;
		}
		else if ((arg.find("--") == 0) || (arg.find("-b") == 0) || 
		    (arg.find("-r") == 0) || (arg.find("-v") == 0) ||
		    (arg.find("-h") == 0) || (arg.find("-V") == 0) ||
			(arg.find("-p") == 0) || (arg.find("-y") == 0))
		{
			if ((arg.find("-h") == 0) || (arg.find("--help") == 0))
			{
				std::cout << usage << std::endl;
				std::cout << about << std::endl;
				std::cout << "Arguments mandatory for long options are also" <<
					" mandatory for short options." << std::endl;
				std::cout << "  -b, --binary   consider KEYFILE and FILENAME" <<
					" as binary input" << std::endl;
				std::cout << "  -h, --help     print this help" << std::endl;
				std::cout << "  -k FILENAME    use keyring FILENAME" <<
					" containing external revocation keys" << std::endl;
				std::cout << "  -o FILENAME    export (reduced) public key" << 
					" to FILENAME" << std::endl;
				std::cout << "  -p, --private  read from private key block" <<
					std::endl;
				std::cout << "  -r, --reduce   check only valid subkeys" <<
					std::endl;
				std::cout << "  -v, --version  print the version number" <<
					std::endl;
				std::cout << "  -V, --verbose  turn on verbose output" <<
					std::endl;
				std::cout << "  -y, --yaot     list keys from keyring" <<
					" FILENAME with user ID containing KEYFILE" << std::endl;
				return 0; // not continue
			}
			if ((arg.find("-b") == 0) || (arg.find("--binary") == 0))
				opt_b = true;
			if ((arg.find("-p") == 0) || (arg.find("--private") == 0))
				opt_p = true;
			if ((arg.find("-r") == 0) || (arg.find("--reduce") == 0))
				opt_r = true;
			if ((arg.find("-y") == 0) || (arg.find("--yaot") == 0))
				opt_y = true;
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
		filename = arg;
	}

#ifdef DKGPG_TESTSUITE_Y
	if (tmcg_mpz_wrandom_ui() % 2)
	{
		filename = "TestY-pub.asc";
	}
	else
	{
		filename = "TestY-sec.asc";
		opt_p = true;
	}
	opt_verbose = 2;
#endif

	// check command line arguments
	if (!opt_y && filename.length() == 0)
	{
		std::cerr << "ERROR: argument KEYFILE is missing; usage: " <<
			usage << std::endl;
		return -1;
	}
	if (opt_y && (opt_k == NULL))
	{
		std::cerr << "ERROR: no keyring specified (option -k missing)" <<
			std::endl;
		return -1;
	} 

	// lock memory
	bool force_secmem = false;
	if (opt_p)
	{
		if (!lock_memory())
		{
			std::cerr << "WARNING: locking memory failed; CAP_IPC_LOCK" <<
				" required for full memory protection" << std::endl;
			// at least try to use libgcrypt's secure memory
			force_secmem = true;
		}
	}

	// initialize LibTMCG
	if (!init_libTMCG(force_secmem))
	{
		std::cerr << "ERROR: initialization of LibTMCG failed" << std::endl;
		return -1;
	}
	if (opt_verbose)
		std::cerr << "INFO: using LibTMCG version " <<
			version_libTMCG() << std::endl;

	// choose input format of key file
	tmcg_openpgp_armor_t format = TMCG_OPENPGP_ARMOR_PUBLIC_KEY_BLOCK; 
	if (opt_p)
		format = TMCG_OPENPGP_ARMOR_PRIVATE_KEY_BLOCK;

	// read the key file
	std::string armored_pubkey;
	if (!opt_y)
	{
		if (opt_b)
		{
			if (!read_binary_key_file(filename, format, armored_pubkey))
				return -1;
		}
		else
		{
			if (!read_key_file(filename, armored_pubkey))
				return -1;
		}
	}

	// read the keyring
	tmcg_openpgp_armor_t kformat = TMCG_OPENPGP_ARMOR_PUBLIC_KEY_BLOCK;
	std::string armored_pubring;
	if (opt_k != NULL)
	{
		if (opt_b)
		{
			if (!read_binary_key_file(kfilename, kformat, armored_pubring))
				return -1;
		}
		else
		{
			if (!read_key_file(kfilename, armored_pubring))
				return -1;
		}
	}

	// parse the keyring, the public key and corresponding signatures
	TMCG_OpenPGP_Prvkey *prv = NULL;
	TMCG_OpenPGP_Pubkey *primary = NULL;
	TMCG_OpenPGP_Keyring *ring = NULL;
	bool parse_ok;
	if (opt_k != NULL)
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
	if (opt_y)
	{
		int ret = 0;
		if (ring->List(filename) == 0)
			ret = -1;
		delete ring;
		return ret;
	}
	else if (opt_p)
	{
		tmcg_openpgp_secure_string_t passphrase = ""; // try an empty passphrase
		parse_ok = CallasDonnerhackeFinneyShawThayerRFC4880::
			PrivateKeyBlockParse(armored_pubkey, opt_verbose, passphrase, prv);
		if (!parse_ok)
		{
#ifdef DKGPG_TESTSUITE_Y
			passphrase = "TestY";
#else
			if (!get_passphrase("Enter passphrase to unlock private key", false,
				passphrase))
			{
				std::cerr << "ERROR: cannot read passphrase" << std::endl;
				delete ring;
				return -1;
			}
#endif
			parse_ok = CallasDonnerhackeFinneyShawThayerRFC4880::
				PrivateKeyBlockParse(armored_pubkey, opt_verbose, passphrase,
				prv);
		}
	}
	else
		parse_ok = CallasDonnerhackeFinneyShawThayerRFC4880::
			PublicKeyBlockParse(armored_pubkey, opt_verbose, primary);
	if (parse_ok)
	{
		if (opt_p)
		{
			primary = prv->pub; // get the public key from private key
			prv->RelinkPublicSubkeys(); // relink the contained subkeys
		}
		primary->CheckSelfSignatures(ring, opt_verbose);
		primary->CheckSubkeys(ring, opt_verbose);
		if (opt_r)
			primary->Reduce();
		if (primary->Weak(opt_verbose) && opt_verbose)
			std::cerr << "WARNING: weak primary key detected" << std::endl;
		if (opt_o != NULL)
		{
			tmcg_openpgp_octets_t pub;
			std::string armor;
			primary->Export(pub);
			CallasDonnerhackeFinneyShawThayerRFC4880::
				ArmorEncode(TMCG_OPENPGP_ARMOR_PUBLIC_KEY_BLOCK, pub, armor);
			if (!write_message(ofilename, armor))
			{
				delete primary;
				delete ring;
				return -1;
			} 
		}
	}
	else
	{
		std::cerr << "ERROR: cannot use the provided public key" << std::endl;
		delete ring;
		return -1;
	}

	// show information w.r.t. primary key
	int ret = 0;
	std::string kid, fpr;
	CallasDonnerhackeFinneyShawThayerRFC4880::
		KeyidCompute(primary->pub_hashing, kid);
	CallasDonnerhackeFinneyShawThayerRFC4880::
		FingerprintComputePretty(primary->pub_hashing, fpr);
	std::cout << "OpenPGP V4 Key ID of primary key: " << std::endl << "\t";
	std::cout << kid << std::endl;
	std::cout << "OpenPGP V4 fingerprint of primary key: " << std::endl << "\t";
	std::cout << fpr << std::endl;
	std::cout << "OpenPGP Key Creation Time: " <<
		std::endl << "\t" << ctime(&primary->creationtime);
	std::cout << "OpenPGP Key Expiration Time: " << std::endl << "\t";
	if (primary->expirationtime == 0)
		std::cout << "undefined" << std::endl;
	else
	{
		// compute validity period of the primary key after key creation time
		time_t ekeytime = primary->creationtime + primary->expirationtime;
		if (ekeytime < time(NULL))
		{
			std::cout << "[EXPIRED] ";
			ret = -2; // return with non-null status code
		}
		std::cout << ctime(&ekeytime);
	}
	std::cout << "OpenPGP Revocation Keys: " << std::endl;
	for (size_t i = 0; i < primary->revkeys.size(); i++)
	{
		tmcg_openpgp_revkey_t rk = primary->revkeys[i];
		tmcg_openpgp_octets_t f(rk.key_fingerprint,
			 rk.key_fingerprint+sizeof(rk.key_fingerprint));
		CallasDonnerhackeFinneyShawThayerRFC4880::
			FingerprintConvertPretty(f, fpr);
		std::cout << "\t" << fpr << std::endl;
	}
	if (primary->revkeys.size() == 0)
		std::cout << "\t" << "none" << std::endl;
	size_t allflags = primary->AccumulateFlags();
	std::cout << "OpenPGP Key Flags: " << std::endl << "\t";
	// The key may be used to certify other keys.
	if ((allflags & 0x01) == 0x01)
		std::cout << "C";
	// The key may be used to sign data.
	if ((allflags & 0x02) == 0x02)
		std::cout << "S";
	// The key may be used encrypt communications.
	if ((allflags & 0x04) == 0x04)
		std::cout << "E";
	// The key may be used encrypt storage.
	if ((allflags & 0x08) == 0x08)
		std::cout << "e";
	// The private component of this key may have
	// been split by a secret-sharing mechanism.
	if ((allflags & 0x10) == 0x10)
		std::cout << "D";
	// The key may be used for authentication.
	if ((allflags & 0x20) == 0x20)
		std::cout << "A";
	// The private component of this key may be
	// in the possession of more than one person.
	if ((allflags & 0x80) == 0x80)
		std::cout << "G";
	if (allflags == 0x00)
		std::cout << "undefined";
	std::cout << std::endl;
	std::vector<TMCG_OpenPGP_Signature*> sigs;
	if ((primary->pkalgo == TMCG_OPENPGP_PKALGO_RSA) ||
		(primary->pkalgo == TMCG_OPENPGP_PKALGO_RSA_SIGN_ONLY))
	{
		mpz_t rsa_n, rsa_e;
		mpz_init(rsa_n), mpz_init(rsa_e);
		if (!tmcg_mpz_set_gcry_mpi(primary->rsa_n, rsa_n) ||
			!tmcg_mpz_set_gcry_mpi(primary->rsa_e, rsa_e))
		{
			std::cerr << "ERROR: cannot convert RSA key material" << std::endl;
			mpz_clear(rsa_n), mpz_clear(rsa_e);
			if (opt_p)
				delete prv;
			else
				delete primary;
			delete ring;
			return -1;
		}
		ret = rsa_check(rsa_n, rsa_e);
		mpz_clear(rsa_n), mpz_clear(rsa_e);
	}
	else if (primary->pkalgo == TMCG_OPENPGP_PKALGO_DSA)
	{
		mpz_t dsa_p, dsa_q, dsa_g, dsa_y, dsa_r;
		mpz_init(dsa_p), mpz_init(dsa_q), mpz_init(dsa_g), mpz_init(dsa_y);
		mpz_init(dsa_r);
		if (!tmcg_mpz_set_gcry_mpi(primary->dsa_p, dsa_p) ||
			!tmcg_mpz_set_gcry_mpi(primary->dsa_q, dsa_q) ||
		    !tmcg_mpz_set_gcry_mpi(primary->dsa_g, dsa_g) ||
			!tmcg_mpz_set_gcry_mpi(primary->dsa_y, dsa_y))
		{
			std::cerr << "ERROR: cannot convert DSA key material" << std::endl;
			mpz_clear(dsa_p), mpz_clear(dsa_q), mpz_clear(dsa_g);
			mpz_clear(dsa_y), mpz_clear(dsa_r);
			if (opt_p)
				delete prv;
			else
				delete primary;
			delete ring;
			return -1;
		}
		ret = dsa_check(dsa_p, dsa_q, dsa_g, dsa_y);
		// additional part for checking DSA signatures
		for (size_t i = 0; i < primary->selfsigs.size(); i++)
		{
			if (primary->selfsigs[i]->pkalgo == TMCG_OPENPGP_PKALGO_DSA)
			{
				if (!tmcg_mpz_set_gcry_mpi(primary->selfsigs[i]->dsa_r, dsa_r))
				{
					std::cerr << "WARNING: bad signature (cannot convert" <<
						" dsa_r)" << std::endl << "\t";
				}
				else
				{
					ret = sig_check_dsa(dsa_p, dsa_q, dsa_g, dsa_y, dsa_r);
					sigs.push_back(primary->selfsigs[i]);
				}
			}
			else
				std::cerr << "WARNING: inconsistent public-key algorithm" <<
					std::endl << "\t";
		}
		for (size_t i = 0; i < primary->keyrevsigs.size(); i++)
		{
			if (primary->keyrevsigs[i]->pkalgo == TMCG_OPENPGP_PKALGO_DSA)
			{
				if (!tmcg_mpz_set_gcry_mpi(primary->keyrevsigs[i]->dsa_r, dsa_r))
				{
					std::cerr << "WARNING: bad signature (cannot convert" <<
						" dsa_r)" << std::endl << "\t";
				}
				else
				{
					ret = sig_check_dsa(dsa_p, dsa_q, dsa_g, dsa_y, dsa_r);
					sigs.push_back(primary->keyrevsigs[i]);
				}
			}
			else
				std::cerr << "WARNING: inconsistent public-key algorithm" <<
					std::endl << "\t";
		}
		for (size_t i = 0; i < primary->certrevsigs.size(); i++)
		{
			if (primary->certrevsigs[i]->pkalgo == TMCG_OPENPGP_PKALGO_DSA)
			{
				if (!tmcg_mpz_set_gcry_mpi(primary->certrevsigs[i]->dsa_r, dsa_r))
				{
					std::cerr << "WARNING: bad signature (cannot convert" <<
						" dsa_r)" << std::endl << "\t";
				}
				else
				{
					ret = sig_check_dsa(dsa_p, dsa_q, dsa_g, dsa_y, dsa_r);
					sigs.push_back(primary->certrevsigs[i]);
				}
			}
			else
				std::cerr << "WARNING: inconsistent public-key algorithm" <<
					std::endl << "\t";
		}
		for (size_t j = 0; j < primary->userids.size(); j++)
		{
			for (size_t i = 0; i < primary->userids[j]->selfsigs.size(); i++)
			{
				TMCG_OpenPGP_Signature *sig = primary->userids[j]->selfsigs[i]; 
				if (sig->pkalgo == TMCG_OPENPGP_PKALGO_DSA)
				{
					if (!tmcg_mpz_set_gcry_mpi(sig->dsa_r, dsa_r))
					{
						std::cerr << "WARNING: bad signature (cannot convert" <<
							" dsa_r)" << std::endl << "\t";
					}
					else
					{
						ret = sig_check_dsa(dsa_p, dsa_q, dsa_g, dsa_y, dsa_r);
						sigs.push_back(sig);
					}
				}
				else
					std::cerr << "WARNING: inconsistent public-key algorithm" <<
						std::endl << "\t";
			}
			for (size_t i = 0; i < primary->userids[j]->revsigs.size(); i++)
			{
				TMCG_OpenPGP_Signature *sig = primary->userids[j]->revsigs[i];
				if (sig->pkalgo == TMCG_OPENPGP_PKALGO_DSA)
				{
					if (!tmcg_mpz_set_gcry_mpi(sig->dsa_r, dsa_r))
					{
						std::cerr << "WARNING: bad signature (cannot convert" <<
							" dsa_r)" << std::endl << "\t";
					}
					else
					{
						ret = sig_check_dsa(dsa_p, dsa_q, dsa_g, dsa_y, dsa_r);
						sigs.push_back(sig);
					}
				}
				else
					std::cerr << "WARNING: inconsistent public-key algorithm" <<
						std::endl << "\t";
			}
		}
		for (size_t j = 0; j < primary->userattributes.size(); j++)
		{
			TMCG_OpenPGP_UserAttribute *uat = primary->userattributes[j];
			for (size_t i = 0; i < uat->selfsigs.size();
				i++)
			{
				TMCG_OpenPGP_Signature *sig = uat->selfsigs[i];
				if (sig->pkalgo == TMCG_OPENPGP_PKALGO_DSA)
				{
					if (!tmcg_mpz_set_gcry_mpi(sig->dsa_r, dsa_r))
					{
						std::cerr << "WARNING: bad signature (cannot convert" <<
							" dsa_r)" << std::endl << "\t";
					}
					else
					{
						ret = sig_check_dsa(dsa_p, dsa_q, dsa_g, dsa_y, dsa_r);
						sigs.push_back(sig);
					}
				}
				else
					std::cerr << "WARNING: inconsistent public-key algorithm" <<
						std::endl << "\t";
			}
			for (size_t i = 0; i < uat->revsigs.size(); i++)
			{
				TMCG_OpenPGP_Signature *sig = uat->revsigs[i];
				if (sig->pkalgo == TMCG_OPENPGP_PKALGO_DSA)
				{
					if (!tmcg_mpz_set_gcry_mpi(sig->dsa_r, dsa_r))
					{
						std::cerr << "WARNING: bad signature (cannot convert" <<
							" dsa_r)" << std::endl << "\t";
					}
					else
					{
						ret = sig_check_dsa(dsa_p, dsa_q, dsa_g, dsa_y, dsa_r);
						sigs.push_back(sig);
					}
				}
				else
					std::cerr << "WARNING: inconsistent public-key algorithm" <<
						std::endl << "\t";
			}
		}
		mpz_clear(dsa_p), mpz_clear(dsa_q), mpz_clear(dsa_g);
		mpz_clear(dsa_y), mpz_clear(dsa_r);
	}
	else if (primary->pkalgo == TMCG_OPENPGP_PKALGO_ECDSA)
	{
		unsigned int curvebits = 0;
		const char *curvename = gcry_pk_get_curve(primary->key, 0, &curvebits);
		if (curvename == NULL)
			curvename = "unknown";
		std::cout << "Public-key algorithm: " << std::endl <<
			"\tECDSA with curve \"" << curvename << "\" with " <<
			curvebits << " bits" << std::endl;
	}
	else if (primary->pkalgo == TMCG_OPENPGP_PKALGO_EDDSA)
	{
		unsigned int curvebits = 0;
		const char *curvename = gcry_pk_get_curve(primary->key, 0, &curvebits);
		if (curvename == NULL)
			curvename = "unknown";
		std::cout << "Public-key algorithm: " << std::endl <<
			"\tEdDSA with curve \"" << curvename << "\" with " <<
			curvebits << " bits" << std::endl;
	}
	else
	{
		std::cerr << "ERROR: public-key algorithm not supported" << std::endl;
		if (opt_p)
			delete prv;
		else
			delete primary;
		delete ring;
		return -1;
	}
	if (opt_p)
	{
		if (prv->Weak(opt_verbose) && opt_verbose)
		{
			std::cerr << "WARNING: weak private primary key detected" <<
				std::endl;
		}
		switch (prv->pkalgo)
		{
			case TMCG_OPENPGP_PKALGO_RSA:
			case TMCG_OPENPGP_PKALGO_RSA_ENCRYPT_ONLY:
			case TMCG_OPENPGP_PKALGO_RSA_SIGN_ONLY:
				{
					mpz_t rsa_p, rsa_q, rsa_d, rsa_n, rsa_e;
					mpz_init(rsa_p), mpz_init(rsa_q), mpz_init(rsa_d);
					mpz_init(rsa_n), mpz_init(rsa_e);
					if (!tmcg_mpz_set_gcry_mpi(prv->rsa_p, rsa_p) ||
						!tmcg_mpz_set_gcry_mpi(prv->rsa_q, rsa_q) ||
						!tmcg_mpz_set_gcry_mpi(prv->rsa_d, rsa_d) ||
						!tmcg_mpz_set_gcry_mpi(primary->rsa_n, rsa_n) ||
						!tmcg_mpz_set_gcry_mpi(primary->rsa_e, rsa_e))
					{
						std::cerr << "ERROR: cannot convert RSA key material" <<
							std::endl;
						mpz_clear(rsa_p), mpz_clear(rsa_q), mpz_clear(rsa_d);
						mpz_clear(rsa_n), mpz_clear(rsa_e);
						delete prv;
						delete ring;
						return -1;
					}
					ret = rsa_check(rsa_p, rsa_q, rsa_d, rsa_n, rsa_e);
					mpz_clear(rsa_p), mpz_clear(rsa_q), mpz_clear(rsa_d);
					mpz_clear(rsa_n), mpz_clear(rsa_e);
				}
				break;
			case TMCG_OPENPGP_PKALGO_DSA:
			case TMCG_OPENPGP_PKALGO_ECDSA:
			case TMCG_OPENPGP_PKALGO_EDDSA:
				break;
			default:
				break;
		}
	}
	// show information w.r.t. (valid) user IDs
	for (size_t j = 0; j < primary->userids.size(); j++)
	{
		std::cout << "OpenPGP User ID: " << std::endl << "\t";
		std::cout << primary->userids[j]->userid_sanitized << std::endl;
	}
	// show information w.r.t. (valid) subkeys
	for (size_t j = 0; j < primary->subkeys.size(); j++)
	{
		TMCG_OpenPGP_Subkey *sub = primary->subkeys[j];
		if (sub->Weak(opt_verbose) && opt_verbose)
			std::cerr << "WARNING: weak subkey detected" << std::endl;
		CallasDonnerhackeFinneyShawThayerRFC4880::
			KeyidCompute(sub->sub_hashing, kid);
		CallasDonnerhackeFinneyShawThayerRFC4880::
			FingerprintComputePretty(sub->sub_hashing, fpr);
		std::cout << "OpenPGP V4 Key ID of subkey: " << std::endl << "\t";
		std::cout << kid << std::endl;
		std::cout << "OpenPGP V4 fingerprint of subkey: " << std::endl << "\t";
		std::cout << fpr << std::endl;
		std::cout << "OpenPGP Subkey Creation Time: " << std::endl << "\t" <<
			ctime(&sub->creationtime);
		std::cout << "OpenPGP Subkey Expiration Time: " << std::endl << "\t";
		if (sub->expirationtime == 0)
			std::cout << "undefined" << std::endl;
		else
		{
			// compute validity period of the subkey after key creation
			time_t ekeytime = sub->creationtime + sub->expirationtime;
			if (ekeytime < time(NULL))
				std::cout << "[EXPIRED] ";
			std::cout << ctime(&ekeytime);
		}
		std::cout << "OpenPGP Revocation Keys: " << std::endl;
		for (size_t i = 0; i < sub->revkeys.size(); i++)
		{
			tmcg_openpgp_revkey_t rk = sub->revkeys[i];
			tmcg_openpgp_octets_t f(rk.key_fingerprint,
				 rk.key_fingerprint+sizeof(rk.key_fingerprint));
			CallasDonnerhackeFinneyShawThayerRFC4880::
				FingerprintConvertPretty(f, fpr);
			std::cout << "\t" << fpr << std::endl;
		}
		if (sub->revkeys.size() == 0)
			std::cout << "\t" << "none" << std::endl;
		size_t allflags = sub->AccumulateFlags();
		std::cout << "OpenPGP Key Flags: " << std::endl << "\t";
		// The key may be used to certify other keys.
		if ((allflags & 0x01) == 0x01)
			std::cout << "C";
		// The key may be used to sign data.
		if ((allflags & 0x02) == 0x02)
			std::cout << "S";
		// The key may be used encrypt communications.
		if ((allflags & 0x04) == 0x04)
			std::cout << "E";
		// The key may be used encrypt storage.
		if ((allflags & 0x08) == 0x08)
			std::cout << "e";
		// The private component of this key may have
		// been split by a secret-sharing mechanism.
		if ((allflags & 0x10) == 0x10)
			std::cout << "D";
		// The key may be used for authentication.
		if ((allflags & 0x20) == 0x20)
			std::cout << "A";
		// The private component of this key may be
		// in the possession of more than one person.
		if ((allflags & 0x80) == 0x80)
			std::cout << "G";
		if (allflags == 0x00)
			std::cout << "undefined";
		std::cout << std::endl;
		if ((sub->pkalgo == TMCG_OPENPGP_PKALGO_RSA) ||
		    (sub->pkalgo == TMCG_OPENPGP_PKALGO_RSA_ENCRYPT_ONLY) ||
		    (sub->pkalgo == TMCG_OPENPGP_PKALGO_RSA_SIGN_ONLY))
		{
			mpz_t rsa_n, rsa_e;
			mpz_init(rsa_n), mpz_init(rsa_e);
			if (!tmcg_mpz_set_gcry_mpi(sub->rsa_n, rsa_n) ||
				!tmcg_mpz_set_gcry_mpi(sub->rsa_e, rsa_e))
			{
				std::cerr << "ERROR: cannot convert RSA key material" <<
					std::endl;
				mpz_clear(rsa_n), mpz_clear(rsa_e);
				if (opt_p)
					delete prv;
				else
					delete primary;
				delete ring;
				return -1;
			}
			ret = rsa_check(rsa_n, rsa_e);
			mpz_clear(rsa_n), mpz_clear(rsa_e);
		}
		else if (sub->pkalgo == TMCG_OPENPGP_PKALGO_ELGAMAL)
		{
			mpz_t elg_p, elg_g, elg_y, dsa_q;
			mpz_init(elg_p), mpz_init(elg_g), mpz_init(elg_y);
			mpz_init(dsa_q);
			if (!tmcg_mpz_set_gcry_mpi(sub->elg_p, elg_p) ||
				!tmcg_mpz_set_gcry_mpi(sub->elg_g, elg_g) ||
			    !tmcg_mpz_set_gcry_mpi(sub->elg_y, elg_y))
			{
				std::cerr << "ERROR: cannot convert ElGamal key material" <<
					std::endl;
				mpz_clear(elg_p), mpz_clear(elg_g), mpz_clear(elg_y);
				mpz_clear(dsa_q);
				if (opt_p)
					delete prv;
				else
					delete primary;
				delete ring;
				return -1;
			}
			if (primary->pkalgo == TMCG_OPENPGP_PKALGO_DSA)
			{
				if (!tmcg_mpz_set_gcry_mpi(primary->dsa_q, dsa_q))
				{
					std::cerr << "ERROR: cannot convert DSA key material" <<
						std::endl;
					mpz_clear(elg_p), mpz_clear(elg_g), mpz_clear(elg_y);
					mpz_clear(dsa_q);
					if (opt_p)
						delete prv;
					else
						delete primary;
					delete ring;
					return -1;
				}
			}
			else
				mpz_set_ui(dsa_q, 0L);
			ret = elg_check(elg_p, elg_g, elg_y, dsa_q);
			mpz_clear(elg_p), mpz_clear(elg_g), mpz_clear(elg_y);
			mpz_clear(dsa_q);
		}
		else if (sub->pkalgo == TMCG_OPENPGP_PKALGO_DSA)
		{
			mpz_t dsa_p, dsa_q, dsa_g, dsa_y;
			mpz_init(dsa_p), mpz_init(dsa_q), mpz_init(dsa_g);
			mpz_init(dsa_y);
			if (!tmcg_mpz_set_gcry_mpi(sub->dsa_p, dsa_p) ||
				!tmcg_mpz_set_gcry_mpi(sub->dsa_q, dsa_q) ||
			    !tmcg_mpz_set_gcry_mpi(sub->dsa_g, dsa_g) ||
				!tmcg_mpz_set_gcry_mpi(sub->dsa_y, dsa_y))
			{
				std::cerr << "ERROR: cannot convert DSA key material" <<
					std::endl;
				mpz_clear(dsa_p), mpz_clear(dsa_q), mpz_clear(dsa_g);
				mpz_clear(dsa_y);
				if (opt_p)
					delete prv;
				else
					delete primary;
				delete ring;
				return -1;
			}
			ret = dsa_check(dsa_p, dsa_q, dsa_g, dsa_y);
			mpz_clear(dsa_p), mpz_clear(dsa_q), mpz_clear(dsa_g);
			mpz_clear(dsa_y);
		}
		else if (sub->pkalgo == TMCG_OPENPGP_PKALGO_ECDH)
		{
			unsigned int curvebits = 0;
			const char *curvename = gcry_pk_get_curve(sub->key, 0, &curvebits);
			if (curvename == NULL)
				curvename = "unknown";
			std::cout << "Public-key algorithm: " << std::endl <<
				"\tECDH with curve \"" << curvename << "\" with " <<
				curvebits << " bits" << std::endl;
		}
		else if (sub->pkalgo == TMCG_OPENPGP_PKALGO_ECDSA)
		{
			unsigned int curvebits = 0;
			const char *curvename = gcry_pk_get_curve(sub->key, 0, &curvebits);
			if (curvename == NULL)
				curvename = "unknown";
			std::cout << "Public-key algorithm: " << std::endl <<
				"\tECDSA with curve \"" << curvename << "\" with " <<
				curvebits << " bits" << std::endl;
		}
		else if (sub->pkalgo == TMCG_OPENPGP_PKALGO_EDDSA)
		{
			unsigned int curvebits = 0;
			const char *curvename = gcry_pk_get_curve(sub->key, 0, &curvebits);
			if (curvename == NULL)
				curvename = "unknown";
			std::cout << "Public-key algorithm: " << std::endl <<
				"\tEdDSA with curve \"" << curvename << "\" with " <<
				curvebits << " bits" << std::endl;
		}
		else
		{
			std::cerr << "ERROR: public-key algorithm not supported" <<
				std::endl;
			if (opt_p)
				delete prv;
			else
				delete primary;
			delete ring;
			return -1;
		}
		// additional part for checking DSA signatures
		if (primary->pkalgo == TMCG_OPENPGP_PKALGO_DSA)
		{
			mpz_t dsa_p, dsa_q, dsa_g, dsa_y, dsa_r;
			mpz_init(dsa_p), mpz_init(dsa_q), mpz_init(dsa_g);
			mpz_init(dsa_y), mpz_init(dsa_r);
			if (!tmcg_mpz_set_gcry_mpi(primary->dsa_p, dsa_p) ||
				!tmcg_mpz_set_gcry_mpi(primary->dsa_q, dsa_q) ||
			    !tmcg_mpz_set_gcry_mpi(primary->dsa_g, dsa_g) ||
				!tmcg_mpz_set_gcry_mpi(primary->dsa_y, dsa_y))
			{
				std::cerr << "ERROR: cannot convert DSA primary key material" <<
					std::endl;
				mpz_clear(dsa_p), mpz_clear(dsa_q), mpz_clear(dsa_g);
				mpz_clear(dsa_y), mpz_clear(dsa_r);
				if (opt_p)
					delete prv;
				else
					delete primary;
				delete ring;
				return -1;
			}
			for (size_t i = 0; i < sub->selfsigs.size(); i++)
			{
				if (sub->selfsigs[i]->pkalgo == TMCG_OPENPGP_PKALGO_DSA)
				{
					if (!tmcg_mpz_set_gcry_mpi(sub->selfsigs[i]->dsa_r, dsa_r))
					{
						std::cerr << "WARNING: bad signature (cannot convert" <<
							" dsa_r)" << std::endl << "\t";
					}
					else
					{
						ret = sig_check_dsa(dsa_p, dsa_q, dsa_g, dsa_y, dsa_r);
						sigs.push_back(sub->selfsigs[i]);
					}
				}
				else
					std::cerr << "WARNING: inconsistent public-key algorithm" <<
						std::endl << "\t";
			}
			for (size_t i = 0; i < sub->bindsigs.size(); i++)
			{
				if (sub->bindsigs[i]->pkalgo == TMCG_OPENPGP_PKALGO_DSA)
				{
					if (!tmcg_mpz_set_gcry_mpi(sub->bindsigs[i]->dsa_r, dsa_r))
					{
						std::cerr << "WARNING: bad signature (cannot convert" <<
							" dsa_r)" << std::endl << "\t";
					}
					else
					{
						ret = sig_check_dsa(dsa_p, dsa_q, dsa_g, dsa_y, dsa_r);
						sigs.push_back(sub->bindsigs[i]);
					}
				}
				else
					std::cerr << "WARNING: inconsistent public-key algorithm" <<
						std::endl << "\t";
			}
			for (size_t i = 0; i < sub->keyrevsigs.size(); i++)
			{
				if (sub->keyrevsigs[i]->pkalgo == TMCG_OPENPGP_PKALGO_DSA)
				{
					if (!tmcg_mpz_set_gcry_mpi(sub->keyrevsigs[i]->dsa_r, dsa_r))
					{
						std::cerr << "WARNING: bad signature (cannot convert" <<
							" dsa_r)" << std::endl << "\t";
					}
					else
					{
						ret = sig_check_dsa(dsa_p, dsa_q, dsa_g, dsa_y, dsa_r);
						sigs.push_back(sub->keyrevsigs[i]);
					}
				}
				else
					std::cerr << "WARNING: inconsistent public-key algorithm" <<
						std::endl << "\t";
			}
			for (size_t i = 0; i < sub->certrevsigs.size(); i++)
			{
				if (sub->certrevsigs[i]->pkalgo == TMCG_OPENPGP_PKALGO_DSA)
				{
					if (!tmcg_mpz_set_gcry_mpi(sub->certrevsigs[i]->dsa_r, dsa_r))
					{
						std::cerr << "WARNING: bad signature (cannot convert" <<
							" dsa_r)" << std::endl << "\t";
					}
					else
					{
						ret = sig_check_dsa(dsa_p, dsa_q, dsa_g, dsa_y, dsa_r);
						sigs.push_back(sub->certrevsigs[i]);
					}
				}
				else
					std::cerr << "WARNING: inconsistent public-key algorithm" <<
						std::endl << "\t";
			}
			mpz_clear(dsa_p), mpz_clear(dsa_q), mpz_clear(dsa_g);
			mpz_clear(dsa_y), mpz_clear(dsa_r);
		}
	}
	if (opt_p)
	{
		prv->RelinkPrivateSubkeys(); // undo the relinking
		for (size_t j = 0; j < prv->private_subkeys.size(); j++)
		{
			TMCG_OpenPGP_PrivateSubkey *ssb = prv->private_subkeys[j];
			if (ssb->Weak(opt_verbose) && opt_verbose)
				std::cerr << "WARNING: weak private subkey #" << j <<
					" detected" << std::endl;
			switch (ssb->pkalgo)
			{
				case TMCG_OPENPGP_PKALGO_RSA:
				case TMCG_OPENPGP_PKALGO_RSA_ENCRYPT_ONLY:
				case TMCG_OPENPGP_PKALGO_RSA_SIGN_ONLY:
					{
						mpz_t rsa_p, rsa_q, rsa_d, rsa_n, rsa_e;
						mpz_init(rsa_p), mpz_init(rsa_q), mpz_init(rsa_d);
						mpz_init(rsa_n), mpz_init(rsa_e);
						if (!tmcg_mpz_set_gcry_mpi(ssb->rsa_p, rsa_p) ||
							!tmcg_mpz_set_gcry_mpi(ssb->rsa_q, rsa_q) ||
							!tmcg_mpz_set_gcry_mpi(ssb->rsa_d, rsa_d) ||
							!tmcg_mpz_set_gcry_mpi(ssb->pub->rsa_n, rsa_n) ||
							!tmcg_mpz_set_gcry_mpi(ssb->pub->rsa_e, rsa_e))
						{
							std::cerr << "ERROR: cannot convert RSA key" <<
								" material" << std::endl;
							mpz_clear(rsa_p), mpz_clear(rsa_q), mpz_clear(rsa_d);
							mpz_clear(rsa_n), mpz_clear(rsa_e);
							delete prv;
							delete ring;
							return -1;
						}
						ret = rsa_check(rsa_p, rsa_q, rsa_d, rsa_n, rsa_e);
						mpz_clear(rsa_p), mpz_clear(rsa_q), mpz_clear(rsa_d);
						mpz_clear(rsa_n), mpz_clear(rsa_e);
					}
					break;
				case TMCG_OPENPGP_PKALGO_ELGAMAL:
				case TMCG_OPENPGP_PKALGO_DSA:
				case TMCG_OPENPGP_PKALGO_ECDSA:
				case TMCG_OPENPGP_PKALGO_EDDSA:
				case TMCG_OPENPGP_PKALGO_ECDH:
					break;
				default:
					break;
			}
		}
	}

	// cross-check DSA signatures w.r.t same k
	std::cout << std::endl;
	for (size_t i = 0; i < sigs.size(); i++)
	{
		for (size_t ii = 0; ii < sigs.size(); ii++)
		{
			if (i >= ii)
				continue;
			if (!gcry_mpi_cmp(sigs[i]->dsa_r, sigs[ii]->dsa_r) &&
				gcry_mpi_cmp(sigs[i]->dsa_s, sigs[ii]->dsa_s))
			{
				std::cout << "WEAKNESS: DSA value r is EQUAL for both" <<
					" signatures (e.g. same k used)" << std::endl;
				ret = -2; // return with non-null status code
			}
		}
	}

	// release primary key and keyring structures
	if (opt_p)
		delete prv;
	else
		delete primary;
	delete ring;
	
	return ret;
}

