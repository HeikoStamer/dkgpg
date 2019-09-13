/*******************************************************************************
   This file is part of Distributed Privacy Guard (DKGPG).

 Copyright (C) 2017, 2018, 2019  Heiko Stamer <HeikoStamer@gmx.net>

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

int main
	(int argc, char **argv)
{
	static const char *usage = "dkg-gencrs [OPTIONS] [ARGS]; "
		"security level is defined by number of dummy ARGS";
	static const char *about = PACKAGE_STRING " " PACKAGE_URL;
	static const char *version = PACKAGE_VERSION " (" PACKAGE_NAME ")";
	size_t factor = 0;
	std::string fips, prefix;
	int opt_verbose = 0;
	bool opt_r = false;

	for (size_t i = 0; i < (size_t)(argc - 1); i++)
	{
		std::string arg = argv[i+1];
		// ignore options
		if ((arg.find("-f") == 0))
		{
			size_t idx = ++i;
			if ((idx < (size_t)(argc - 1)) && (!fips.length()))
			{
				fips = argv[i+1];
			}
			else
			{
				std::cerr << "ERROR: bad option \"" << arg << "\" found" <<
					std::endl;
				return -1;
			}
			continue;
		}
		else if ((arg.find("-k") == 0))
		{
			size_t idx = ++i;
			if ((idx < (size_t)(argc - 1)) && (!prefix.length()))
			{
				prefix = argv[i+1];
			}
			else
			{
				std::cerr << "ERROR: bad option \"" << arg << "\" found" <<
					std::endl;
				return -1;
			}
			continue;
		}
		else if ((arg.find("--") == 0) || (arg.find("-v") == 0) ||
			(arg.find("-h") == 0) || (arg.find("-V") == 0) ||
			(arg.find("-r") == 0))
		{
			if ((arg.find("-h") == 0) || (arg.find("--help") == 0))
			{
				std::cout << usage << std::endl;
				std::cout << about << std::endl;
				std::cout << "Arguments mandatory for long options are also" <<
					" mandatory for short options." << std::endl;
				std::cout << "  -h, --help     print this help" << std::endl;
				std::cout << "  -f SEED        generate domain parameters" <<
					" according to FIPS 186-4 with SEED" << std::endl;
				std::cout << "  -k PREFIX      generate value k with given" <<
					" PREFIX (not in FIPS and RFC mode)" << std::endl;
				std::cout << "  -r, --rfc7919  use fixed domain parameters" <<
					" from RFC 7919" << std::endl;
				std::cout << "  -v, --version  print the version number" <<
					std::endl;
				std::cout << "  -V, --verbose  turn on verbose output" <<
					std::endl;
				return 0; // not continue
			}
			if ((arg.find("-v") == 0) || (arg.find("--version") == 0))
			{
				std::cout << "dkg-gencrs v" << version << std::endl;
				return 0; // not continue
			}
			if ((arg.find("-V") == 0) || (arg.find("--verbose") == 0))
				opt_verbose++; // increase verbosity
			if ((arg.find("-r") == 0) || (arg.find("--rfc7919") == 0))
				opt_r = true;
			continue;
		}
		else if (arg.find("-") == 0)
		{
			std::cerr << "ERROR: unknown option \"" << arg << "\"" << std::endl;
			return -1;
		}
		factor++;
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

#ifdef DKGPG_TESTSUITE
	factor = 1;
	if (tmcg_mpz_wrandom_ui() % 2)
		fips = "DKGPGTESTSUITEDKGPGTESTSUITEDKGPGTESTSUITEDKGPGTESTSUITEDKGPG";
	else if (tmcg_mpz_wrandom_ui() % 2)
		opt_r = true;
	opt_verbose = 2;
#endif

	// generate primes and generator according to FIPS 186-4
	if (fips.length())
	{
		// 1. Check that the $(L, N)$ pair is in the list of acceptable $(L, N)$
		//    pairs. If the pair is not in the list, the return INVALID.
		size_t L = 0, N = 0;
		if (factor > 0)
		{
			if (opt_verbose)
			{
				std::cerr << "INFO: Generating primes p and q according to" <<
					" FIPS 186-4 with factor = " << factor << std::endl;
			}
			L = TMCG_DDH_SIZE + (factor * 1024);
			N = TMCG_DLSE_SIZE + ((factor - 1) * 128);
		}
		else
		{
			if (opt_verbose)
				std::cerr << "INFO: Generating primes p and q according to" <<
					" FIPS 186-4 with default sizes" << std::endl;
			L = TMCG_DDH_SIZE, N = TMCG_DLSE_SIZE;
		}
		int hash_algo = 0, mr_iterations = 0;
		if (N == 256)
			hash_algo = GCRY_MD_SHA256, mr_iterations = 56;
		else if (N == 384)
			hash_algo = GCRY_MD_SHA384, mr_iterations = 64;
		else if (N == 512)
			hash_algo = GCRY_MD_SHA512, mr_iterations = 72;
		else
		{
			std::cerr << "ERROR: no FIPS approved hash function defined for" <<
				" N = " << N << std::endl;
			return -1;
		}
		// 5. Get an arbitrary sequence of $seedlen$ bits as the
		//    $domain\_parameter\_seed$.
		mpz_t domain_parameter_seed;
		mpz_init(domain_parameter_seed);
		if (mpz_set_str(domain_parameter_seed, fips.c_str(),
			TMCG_MPZ_IO_BASE) < 0)
		{
			std::cerr << "ERROR: FIPS domain parameter SEED is not a valid" <<
				" integer of base " << TMCG_MPZ_IO_BASE << std::endl;
			mpz_clear(domain_parameter_seed);
			return -1;
		}
		// 2. If $(seedlen < N)$, then return INVALID.
		size_t seedlen = mpz_sizeinbase(domain_parameter_seed, 2L);
		if (seedlen < N)
		{
			std::cerr << "ERROR: FIPS domain parameter SEED (seedlen = " <<
				seedlen << ") too short for N = " << N << std::endl;
			mpz_clear(domain_parameter_seed);
			return -1;
		}
		// 3. $n = \lceil L / outlen \rceil - 1$.
		size_t outlen = tmcg_mpz_fhash_len(hash_algo) * 8;
		size_t n = (L / outlen) - 1;
		// 4. $b = L - 1 - (n * outlen)$.
		size_t b = L - 1 - (n * outlen);
		// 5.
		size_t counter = 0;
		mpz_t U, q, q2, W, X, c, p;
		mpz_init(U), mpz_init(q), mpz_init(q2), mpz_init(W), mpz_init(X);
		mpz_init(c), mpz_init(p);
		std::vector<mpz_ptr> V_j;
		for (size_t j = 0; j <= n; j++)
		{
			mpz_ptr tmp = new mpz_t();
			mpz_init(tmp);
			V_j.push_back(tmp);
		}
		while (1)
		{
			while (1)
			{
				// 6. $U = \mathbf{Hash}(domain\_parameter\_seed)\bmod 2^{N-1}$.
				tmcg_mpz_fhash(U, hash_algo, domain_parameter_seed);
				mpz_tdiv_r_2exp(U, U, N - 1);
				if (opt_verbose)
					std::cerr << "INFO: U = " << U << std::endl;
				// 7. $q = 2^{N-1} + U + 1 - (U \bmod 2)$.
				mpz_set_ui(q, 1L);
				mpz_mul_2exp(q, q, N - 1);
				mpz_add(q, q, U);
				mpz_add_ui(q, q, 1L);
				if (mpz_odd_p(U))
					mpz_sub_ui(q, q, 1L);
				if (opt_verbose)
					std::cerr << "INFO: q = " << q << std::endl;
				// 8. Test whether or not $q$ is prime as specified in
				//    Appendix C.3.
				// 9. If $q$ is not a prime, then go to step 5.
				if (!mpz_probab_prime_p(q, mr_iterations))
					mpz_add_ui(domain_parameter_seed, domain_parameter_seed,
						1L);
				else
					break;
			}
			mpz_mul_2exp(q2, q, 1L);
			// 10. $offset = 1$.
			size_t offset = 1;
			// 11. For $counter = 0$ to $(4L - 1)$ do
			for (counter = 0; counter < (4 * L); counter++)
			{
				// 11.1 For $j = 0$ to $n$ do
				for (size_t j = 0; j <= n; j++)
				{
					// $V_j = \mathbf{Hash}((domain_parameter_seed + offset + j)
					//        \bmod 2^{seedlen})$.
					mpz_t tmp;
					mpz_init_set(tmp, domain_parameter_seed);
					mpz_add_ui(tmp, tmp, offset);
					mpz_add_ui(tmp, tmp, j);
					mpz_tdiv_r_2exp(tmp, tmp, seedlen);
					tmcg_mpz_fhash(V_j[j], hash_algo, tmp);
					if (opt_verbose > 1)
						std::cerr << "INFO: V_j[" << j << "] = " << V_j[j] <<
							std::endl;
					mpz_clear(tmp);
				}
				// 11.2 $W = V_0 + (V_1 * 2^{outlen}) + \cdots +
				//           (V_{n-1} * 2^{(n-1)*outlen}) + ((V_n \bmod 2^b) *
				//           2^{n*outlen})$.
				mpz_set_ui(W, 0L);
				for (size_t j = 0; j <= n; j++)
				{
					mpz_t tmp;
					mpz_init_set(tmp, V_j[j]);
					if (j == n)
						mpz_tdiv_r_2exp(tmp, tmp, b);
					mpz_mul_2exp(tmp, tmp, (j * outlen));
					mpz_add(W, W, tmp);
					mpz_clear(tmp);
				}
				if (opt_verbose)
					std::cerr << "INFO: W = " << W << std::endl;
				// 11.3 $X = W + 2^{L-1}$.
				mpz_set_ui(X, 1L);
				mpz_mul_2exp(X, X, L - 1);
				mpz_add(X, X, W);
				// 11.4 $c = X \bmod 2q$.
				mpz_mod(c, X, q2);
				// 11.5 $p = X - (c - 1)$.
				mpz_sub(p, X, c);
				mpz_add_ui(p, p, 1L);
				// 11.6 If $(p < 2^{L-1})$, then go to step 11.9.
				if (mpz_sizeinbase(p, 2L) < L)
				{
					offset += (n + 1);
					continue;
				}
				// 11.7 Test whether or not $p$ is prime as specified in
				//      Appendix C.3.
				// 11.8 If $p$ is determined to be prime, then return VALID and
				//      the values of $p$, $q$ and (optionally) the values of
				//      $domain\_parameter\_seed$ and $counter$. 
				if (mpz_probab_prime_p(p, mr_iterations))
					break;
				// 11.9 $offset = offset + n + 1$.
				offset += (n + 1);
			}
			if (mpz_probab_prime_p(p, mr_iterations))
				break;
		}
		if (opt_verbose)
		{
			std::cerr << "INFO: p = " << p << std::endl;
			std::cerr << "INFO: counter = " << counter << std::endl;
			std::cerr << "INFO: Computing generator g according to" <<
				" FIPS 186-4" << std::endl;
		}
		// 1. If ($index$ is incorrect), then return INVALID.
		mpz_t index;
		mpz_init_set_ui(index, 108L); // fixed index value for DKG-tools
		// 2. $N = \mathbf{len}(q)$.
		N = mpz_sizeinbase(q, 2L);
		if (opt_verbose)
			std::cerr << "INFO: N = " << N << std::endl;
		// 3. $e = (p - 1)/q$.
		mpz_t e;
		mpz_init_set(e, p);
		mpz_sub_ui(e, e, 1L);
		mpz_div(e, e, q);
		// 4. $count = 0$.
		mpz_t count, g;
		mpz_init_set_ui(count, 0L);
		mpz_init(g);
		while (1)
		{
			// 5. $count = count + 1$.
			mpz_add_ui(count, count, 1L);
			// 6. If $(count = 0)$, then return INVALID.
			if (!mpz_cmp_ui(count, 0L))
			{
				std::cerr << "ERROR: invalid value count = 0" << std::endl;
				mpz_clear(domain_parameter_seed);
				mpz_clear(U), mpz_clear(q), mpz_clear(q2), mpz_clear(W);
				mpz_clear(X), mpz_clear(c), mpz_clear(p);
				for (size_t j = 0; j <= n; j++)
				{
					mpz_clear(V_j[j]);
					delete [] V_j[j];
				}
				V_j.clear();
				mpz_clear(index), mpz_clear(e);
				mpz_clear(count), mpz_clear(g);
				return -1;
			}
			// 7. $U = domain_parameter_seed || "ggen" || index || count$.
			// 8. $W = \mathbf{Hash}(U)$.
			tmcg_mpz_fhash_ggen(W, hash_algo, domain_parameter_seed, "ggen",
				index, count);
			// 9. $g = W^e \bmod p$.
			mpz_powm(g, W, e, p);
			// 10. If $(g < 2)$, the go to step 5.
			if (mpz_cmp_ui(g, 2L) < 0)
				continue;
			// 11. Return VALID and the value of $g$.
			break;
		}
		if (opt_verbose)
			std::cerr << "INFO: g = " << p << std::endl;

		// export group parameters to stdout
		mpz_t hash_algo_mpz, counter_mpz;
		mpz_init_set_ui(hash_algo_mpz, hash_algo), mpz_init_set_ui(counter_mpz,
			counter);
		std::cout << "// setup CRS (common reference string) aka set of" <<
			" domain parameters" << std::endl;
		std::cout << "//           ";
		std::cout << "|p| = " << mpz_sizeinbase(p, 2L) << " bit, ";
		std::cout << "|q| = " << mpz_sizeinbase(q, 2L) << " bit, ";
		std::cout << "|g| = " << mpz_sizeinbase(g, 2L) << " bit";
		std::cout << std::endl;
		std::cout << "// FIPS 186-4 A.1.1.2 generation of parameters using" <<
			" an approved hash function" << std::endl;
		std::cout << "//      hash_algo = " << gcry_md_algo_name(hash_algo) <<
			std::endl; 
		std::cout << "//      domain_parameter_seed = " <<
			domain_parameter_seed << std::endl;
		std::cout << "//      counter = " << counter << std::endl;
		std::cout << "//      index = " << index << std::endl;
		std::cout << "crs = \"fips-crs|" << p << "|" << q << "|" << g << "|" <<
			e << "|" << hash_algo_mpz << "|" << domain_parameter_seed << "|" <<
			counter_mpz << "|" << index << "|\"" << std::endl;

		// release
		mpz_clear(domain_parameter_seed);
		mpz_clear(U), mpz_clear(q), mpz_clear(q2), mpz_clear(W), mpz_clear(X);
		mpz_clear(c), mpz_clear(p);
		for (size_t j = 0; j <= n; j++)
		{
			mpz_clear(V_j[j]);
			delete [] V_j[j];
		}
		V_j.clear();
		mpz_clear(index), mpz_clear(e);
		mpz_clear(count), mpz_clear(g);
		mpz_clear(hash_algo_mpz), mpz_clear(counter_mpz);
	}
	else if (opt_r)
	{
		// use fixed domain parameters from RFC 7919
		mpz_t p, q, g, k;
		if (opt_verbose)
			std::cerr << "INFO: Use fixed domain parameters from RFC 7919" <<
				" with factor = " << factor << std::endl;
		mpz_init(p), mpz_init(q), mpz_init(g), mpz_init(k);
		if (factor == 0)
		{
			mpz_set_str(p, "FFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1"\
"D8B9C583CE2D3695A9E13641146433FBCC939DCE249B3EF9"\
"7D2FE363630C75D8F681B202AEC4617AD3DF1ED5D5FD6561"\
"2433F51F5F066ED0856365553DED1AF3B557135E7F57C935"\
"984F0C70E0E68B77E2A689DAF3EFE8721DF158A136ADE735"\
"30ACCA4F483A797ABC0AB182B324FB61D108A94BB2C8E3FB"\
"B96ADAB760D7F4681D4F42A3DE394DF4AE56EDE76372BB19"\
"0B07A7C8EE0A6D709E02FCE1CDF7E2ECC03404CD28342F61"\
"9172FE9CE98583FF8E4F1232EEF28183C3FE3B1B4C6FAD73"\
"3BB5FCBC2EC22005C58EF1837D1683B2C6F34A26C1B2EFFA"\
"886B423861285C97FFFFFFFFFFFFFFFF", 16);
			mpz_set_str(q, "7FFFFFFFFFFFFFFFD6FC2A2C515DA54D57EE2B10139E9E78"\
"EC5CE2C1E7169B4AD4F09B208A3219FDE649CEE7124D9F7C"\
"BE97F1B1B1863AEC7B40D901576230BD69EF8F6AEAFEB2B0"\
"9219FA8FAF83376842B1B2AA9EF68D79DAAB89AF3FABE49A"\
"CC278638707345BBF15344ED79F7F4390EF8AC509B56F39A"\
"98566527A41D3CBD5E0558C159927DB0E88454A5D96471FD"\
"DCB56D5BB06BFA340EA7A151EF1CA6FA572B76F3B1B95D8C"\
"8583D3E4770536B84F017E70E6FBF176601A0266941A17B0"\
"C8B97F4E74C2C1FFC7278919777940C1E1FF1D8DA637D6B9"\
"9DDAFE5E17611002E2C778C1BE8B41D96379A51360D977FD"\
"4435A11C30942E4BFFFFFFFFFFFFFFFF", 16);
			mpz_set_ui(g, 2UL);
			mpz_set_ui(k, 1UL);
		}
		else if (factor == 1)
		{
			mpz_set_str(p, "FFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1"\
"D8B9C583CE2D3695A9E13641146433FBCC939DCE249B3EF9"\
"7D2FE363630C75D8F681B202AEC4617AD3DF1ED5D5FD6561"\
"2433F51F5F066ED0856365553DED1AF3B557135E7F57C935"\
"984F0C70E0E68B77E2A689DAF3EFE8721DF158A136ADE735"\
"30ACCA4F483A797ABC0AB182B324FB61D108A94BB2C8E3FB"\
"B96ADAB760D7F4681D4F42A3DE394DF4AE56EDE76372BB19"\
"0B07A7C8EE0A6D709E02FCE1CDF7E2ECC03404CD28342F61"\
"9172FE9CE98583FF8E4F1232EEF28183C3FE3B1B4C6FAD73"\
"3BB5FCBC2EC22005C58EF1837D1683B2C6F34A26C1B2EFFA"\
"886B4238611FCFDCDE355B3B6519035BBC34F4DEF99C0238"\
"61B46FC9D6E6C9077AD91D2691F7F7EE598CB0FAC186D91C"\
"AEFE130985139270B4130C93BC437944F4FD4452E2D74DD3"\
"64F2E21E71F54BFF5CAE82AB9C9DF69EE86D2BC522363A0D"\
"ABC521979B0DEADA1DBF9A42D5C4484E0ABCD06BFA53DDEF"\
"3C1B20EE3FD59D7C25E41D2B66C62E37FFFFFFFFFFFFFFFF", 16);
			mpz_set_str(q, "7FFFFFFFFFFFFFFFD6FC2A2C515DA54D57EE2B10139E9E78"\
"EC5CE2C1E7169B4AD4F09B208A3219FDE649CEE7124D9F7C"\
"BE97F1B1B1863AEC7B40D901576230BD69EF8F6AEAFEB2B0"\
"9219FA8FAF83376842B1B2AA9EF68D79DAAB89AF3FABE49A"\
"CC278638707345BBF15344ED79F7F4390EF8AC509B56F39A"\
"98566527A41D3CBD5E0558C159927DB0E88454A5D96471FD"\
"DCB56D5BB06BFA340EA7A151EF1CA6FA572B76F3B1B95D8C"\
"8583D3E4770536B84F017E70E6FBF176601A0266941A17B0"\
"C8B97F4E74C2C1FFC7278919777940C1E1FF1D8DA637D6B9"\
"9DDAFE5E17611002E2C778C1BE8B41D96379A51360D977FD"\
"4435A11C308FE7EE6F1AAD9DB28C81ADDE1A7A6F7CCE011C"\
"30DA37E4EB736483BD6C8E9348FBFBF72CC6587D60C36C8E"\
"577F0984C289C9385A098649DE21BCA27A7EA229716BA6E9"\
"B279710F38FAA5FFAE574155CE4EFB4F743695E2911B1D06"\
"D5E290CBCD86F56D0EDFCD216AE22427055E6835FD29EEF7"\
"9E0D90771FEACEBE12F20E95B363171BFFFFFFFFFFFFFFFF", 16);
			mpz_set_ui(g, 2UL);
			mpz_set_ui(k, 1UL);
		}
		else if (factor == 2)
		{
			mpz_set_str(p, "FFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1"\
"D8B9C583CE2D3695A9E13641146433FBCC939DCE249B3EF9"\
"7D2FE363630C75D8F681B202AEC4617AD3DF1ED5D5FD6561"\
"2433F51F5F066ED0856365553DED1AF3B557135E7F57C935"\
"984F0C70E0E68B77E2A689DAF3EFE8721DF158A136ADE735"\
"30ACCA4F483A797ABC0AB182B324FB61D108A94BB2C8E3FB"\
"B96ADAB760D7F4681D4F42A3DE394DF4AE56EDE76372BB19"\
"0B07A7C8EE0A6D709E02FCE1CDF7E2ECC03404CD28342F61"\
"9172FE9CE98583FF8E4F1232EEF28183C3FE3B1B4C6FAD73"\
"3BB5FCBC2EC22005C58EF1837D1683B2C6F34A26C1B2EFFA"\
"886B4238611FCFDCDE355B3B6519035BBC34F4DEF99C0238"\
"61B46FC9D6E6C9077AD91D2691F7F7EE598CB0FAC186D91C"\
"AEFE130985139270B4130C93BC437944F4FD4452E2D74DD3"\
"64F2E21E71F54BFF5CAE82AB9C9DF69EE86D2BC522363A0D"\
"ABC521979B0DEADA1DBF9A42D5C4484E0ABCD06BFA53DDEF"\
"3C1B20EE3FD59D7C25E41D2B669E1EF16E6F52C3164DF4FB"\
"7930E9E4E58857B6AC7D5F42D69F6D187763CF1D55034004"\
"87F55BA57E31CC7A7135C886EFB4318AED6A1E012D9E6832"\
"A907600A918130C46DC778F971AD0038092999A333CB8B7A"\
"1A1DB93D7140003C2A4ECEA9F98D0ACC0A8291CDCEC97DCF"\
"8EC9B55A7F88A46B4DB5A851F44182E1C68A007E5E655F6A"\
"FFFFFFFFFFFFFFFF", 16);
			mpz_set_str(q, "7FFFFFFFFFFFFFFFD6FC2A2C515DA54D57EE2B10139E9E78"\
"EC5CE2C1E7169B4AD4F09B208A3219FDE649CEE7124D9F7C"\
"BE97F1B1B1863AEC7B40D901576230BD69EF8F6AEAFEB2B0"\
"9219FA8FAF83376842B1B2AA9EF68D79DAAB89AF3FABE49A"\
"CC278638707345BBF15344ED79F7F4390EF8AC509B56F39A"\
"98566527A41D3CBD5E0558C159927DB0E88454A5D96471FD"\
"DCB56D5BB06BFA340EA7A151EF1CA6FA572B76F3B1B95D8C"\
"8583D3E4770536B84F017E70E6FBF176601A0266941A17B0"\
"C8B97F4E74C2C1FFC7278919777940C1E1FF1D8DA637D6B9"\
"9DDAFE5E17611002E2C778C1BE8B41D96379A51360D977FD"\
"4435A11C308FE7EE6F1AAD9DB28C81ADDE1A7A6F7CCE011C"\
"30DA37E4EB736483BD6C8E9348FBFBF72CC6587D60C36C8E"\
"577F0984C289C9385A098649DE21BCA27A7EA229716BA6E9"\
"B279710F38FAA5FFAE574155CE4EFB4F743695E2911B1D06"\
"D5E290CBCD86F56D0EDFCD216AE22427055E6835FD29EEF7"\
"9E0D90771FEACEBE12F20E95B34F0F78B737A9618B26FA7D"\
"BC9874F272C42BDB563EAFA16B4FB68C3BB1E78EAA81A002"\
"43FAADD2BF18E63D389AE44377DA18C576B50F0096CF3419"\
"5483B00548C0986236E3BC7CB8D6801C0494CCD199E5C5BD"\
"0D0EDC9EB8A0001E15276754FCC68566054148E6E764BEE7"\
"C764DAAD3FC45235A6DAD428FA20C170E345003F2F32AFB5"\
"7FFFFFFFFFFFFFFF", 16);
			mpz_set_ui(g, 2UL);
			mpz_set_ui(k, 1UL);
		}
		else if (factor == 3)
		{
			mpz_set_str(p, "FFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1"\
"D8B9C583CE2D3695A9E13641146433FBCC939DCE249B3EF9"\
"7D2FE363630C75D8F681B202AEC4617AD3DF1ED5D5FD6561"\
"2433F51F5F066ED0856365553DED1AF3B557135E7F57C935"\
"984F0C70E0E68B77E2A689DAF3EFE8721DF158A136ADE735"\
"30ACCA4F483A797ABC0AB182B324FB61D108A94BB2C8E3FB"\
"B96ADAB760D7F4681D4F42A3DE394DF4AE56EDE76372BB19"\
"0B07A7C8EE0A6D709E02FCE1CDF7E2ECC03404CD28342F61"\
"9172FE9CE98583FF8E4F1232EEF28183C3FE3B1B4C6FAD73"\
"3BB5FCBC2EC22005C58EF1837D1683B2C6F34A26C1B2EFFA"\
"886B4238611FCFDCDE355B3B6519035BBC34F4DEF99C0238"\
"61B46FC9D6E6C9077AD91D2691F7F7EE598CB0FAC186D91C"\
"AEFE130985139270B4130C93BC437944F4FD4452E2D74DD3"\
"64F2E21E71F54BFF5CAE82AB9C9DF69EE86D2BC522363A0D"\
"ABC521979B0DEADA1DBF9A42D5C4484E0ABCD06BFA53DDEF"\
"3C1B20EE3FD59D7C25E41D2B669E1EF16E6F52C3164DF4FB"\
"7930E9E4E58857B6AC7D5F42D69F6D187763CF1D55034004"\
"87F55BA57E31CC7A7135C886EFB4318AED6A1E012D9E6832"\
"A907600A918130C46DC778F971AD0038092999A333CB8B7A"\
"1A1DB93D7140003C2A4ECEA9F98D0ACC0A8291CDCEC97DCF"\
"8EC9B55A7F88A46B4DB5A851F44182E1C68A007E5E0DD902"\
"0BFD64B645036C7A4E677D2C38532A3A23BA4442CAF53EA6"\
"3BB454329B7624C8917BDD64B1C0FD4CB38E8C334C701C3A"\
"CDAD0657FCCFEC719B1F5C3E4E46041F388147FB4CFDB477"\
"A52471F7A9A96910B855322EDB6340D8A00EF092350511E3"\
"0ABEC1FFF9E3A26E7FB29F8C183023C3587E38DA0077D9B4"\
"763E4E4B94B2BBC194C6651E77CAF992EEAAC0232A281BF6"\
"B3A739C1226116820AE8DB5847A67CBEF9C9091B462D538C"\
"D72B03746AE77F5E62292C311562A846505DC82DB854338A"\
"E49F5235C95B91178CCF2DD5CACEF403EC9D1810C6272B04"\
"5B3B71F9DC6B80D63FDD4A8E9ADB1E6962A69526D43161C1"\
"A41D570D7938DAD4A40E329CD0E40E65FFFFFFFFFFFFFFFF", 16);
			mpz_set_str(q, "7FFFFFFFFFFFFFFFD6FC2A2C515DA54D57EE2B10139E9E78"\
"EC5CE2C1E7169B4AD4F09B208A3219FDE649CEE7124D9F7C"\
"BE97F1B1B1863AEC7B40D901576230BD69EF8F6AEAFEB2B0"\
"9219FA8FAF83376842B1B2AA9EF68D79DAAB89AF3FABE49A"\
"CC278638707345BBF15344ED79F7F4390EF8AC509B56F39A"\
"98566527A41D3CBD5E0558C159927DB0E88454A5D96471FD"\
"DCB56D5BB06BFA340EA7A151EF1CA6FA572B76F3B1B95D8C"\
"8583D3E4770536B84F017E70E6FBF176601A0266941A17B0"\
"C8B97F4E74C2C1FFC7278919777940C1E1FF1D8DA637D6B9"\
"9DDAFE5E17611002E2C778C1BE8B41D96379A51360D977FD"\
"4435A11C308FE7EE6F1AAD9DB28C81ADDE1A7A6F7CCE011C"\
"30DA37E4EB736483BD6C8E9348FBFBF72CC6587D60C36C8E"\
"577F0984C289C9385A098649DE21BCA27A7EA229716BA6E9"\
"B279710F38FAA5FFAE574155CE4EFB4F743695E2911B1D06"\
"D5E290CBCD86F56D0EDFCD216AE22427055E6835FD29EEF7"\
"9E0D90771FEACEBE12F20E95B34F0F78B737A9618B26FA7D"\
"BC9874F272C42BDB563EAFA16B4FB68C3BB1E78EAA81A002"\
"43FAADD2BF18E63D389AE44377DA18C576B50F0096CF3419"\
"5483B00548C0986236E3BC7CB8D6801C0494CCD199E5C5BD"\
"0D0EDC9EB8A0001E15276754FCC68566054148E6E764BEE7"\
"C764DAAD3FC45235A6DAD428FA20C170E345003F2F06EC81"\
"05FEB25B2281B63D2733BE961C29951D11DD2221657A9F53"\
"1DDA2A194DBB126448BDEEB258E07EA659C74619A6380E1D"\
"66D6832BFE67F638CD8FAE1F2723020F9C40A3FDA67EDA3B"\
"D29238FBD4D4B4885C2A99176DB1A06C500778491A8288F1"\
"855F60FFFCF1D1373FD94FC60C1811E1AC3F1C6D003BECDA"\
"3B1F2725CA595DE0CA63328F3BE57CC97755601195140DFB"\
"59D39CE091308B4105746DAC23D33E5F7CE4848DA316A9C6"\
"6B9581BA3573BFAF311496188AB15423282EE416DC2A19C5"\
"724FA91AE4ADC88BC66796EAE5677A01F64E8C0863139582"\
"2D9DB8FCEE35C06B1FEEA5474D6D8F34B1534A936A18B0E0"\
"D20EAB86BC9C6D6A5207194E68720732FFFFFFFFFFFFFFFF", 16);
			mpz_set_ui(g, 2UL);
			mpz_set_ui(k, 1UL);
		}
		else if (factor == 4)
		{
			mpz_set_str(p, "FFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1"\
"D8B9C583CE2D3695A9E13641146433FBCC939DCE249B3EF9"\
"7D2FE363630C75D8F681B202AEC4617AD3DF1ED5D5FD6561"\
"2433F51F5F066ED0856365553DED1AF3B557135E7F57C935"\
"984F0C70E0E68B77E2A689DAF3EFE8721DF158A136ADE735"\
"30ACCA4F483A797ABC0AB182B324FB61D108A94BB2C8E3FB"\
"B96ADAB760D7F4681D4F42A3DE394DF4AE56EDE76372BB19"\
"0B07A7C8EE0A6D709E02FCE1CDF7E2ECC03404CD28342F61"\
"9172FE9CE98583FF8E4F1232EEF28183C3FE3B1B4C6FAD73"\
"3BB5FCBC2EC22005C58EF1837D1683B2C6F34A26C1B2EFFA"\
"886B4238611FCFDCDE355B3B6519035BBC34F4DEF99C0238"\
"61B46FC9D6E6C9077AD91D2691F7F7EE598CB0FAC186D91C"\
"AEFE130985139270B4130C93BC437944F4FD4452E2D74DD3"\
"64F2E21E71F54BFF5CAE82AB9C9DF69EE86D2BC522363A0D"\
"ABC521979B0DEADA1DBF9A42D5C4484E0ABCD06BFA53DDEF"\
"3C1B20EE3FD59D7C25E41D2B669E1EF16E6F52C3164DF4FB"\
"7930E9E4E58857B6AC7D5F42D69F6D187763CF1D55034004"\
"87F55BA57E31CC7A7135C886EFB4318AED6A1E012D9E6832"\
"A907600A918130C46DC778F971AD0038092999A333CB8B7A"\
"1A1DB93D7140003C2A4ECEA9F98D0ACC0A8291CDCEC97DCF"\
"8EC9B55A7F88A46B4DB5A851F44182E1C68A007E5E0DD902"\
"0BFD64B645036C7A4E677D2C38532A3A23BA4442CAF53EA6"\
"3BB454329B7624C8917BDD64B1C0FD4CB38E8C334C701C3A"\
"CDAD0657FCCFEC719B1F5C3E4E46041F388147FB4CFDB477"\
"A52471F7A9A96910B855322EDB6340D8A00EF092350511E3"\
"0ABEC1FFF9E3A26E7FB29F8C183023C3587E38DA0077D9B4"\
"763E4E4B94B2BBC194C6651E77CAF992EEAAC0232A281BF6"\
"B3A739C1226116820AE8DB5847A67CBEF9C9091B462D538C"\
"D72B03746AE77F5E62292C311562A846505DC82DB854338A"\
"E49F5235C95B91178CCF2DD5CACEF403EC9D1810C6272B04"\
"5B3B71F9DC6B80D63FDD4A8E9ADB1E6962A69526D43161C1"\
"A41D570D7938DAD4A40E329CCFF46AAA36AD004CF600C838"\
"1E425A31D951AE64FDB23FCEC9509D43687FEB69EDD1CC5E"\
"0B8CC3BDF64B10EF86B63142A3AB8829555B2F747C932665"\
"CB2C0F1CC01BD70229388839D2AF05E454504AC78B758282"\
"2846C0BA35C35F5C59160CC046FD8251541FC68C9C86B022"\
"BB7099876A460E7451A8A93109703FEE1C217E6C3826E52C"\
"51AA691E0E423CFC99E9E31650C1217B624816CDAD9A95F9"\
"D5B8019488D9C0A0A1FE3075A577E23183F81D4A3F2FA457"\
"1EFC8CE0BA8A4FE8B6855DFE72B0A66EDED2FBABFBE58A30"\
"FAFABE1C5D71A87E2F741EF8C1FE86FEA6BBFDE530677F0D"\
"97D11D49F7A8443D0822E506A9F4614E011E2A94838FF88C"\
"D68C8BB7C5C6424CFFFFFFFFFFFFFFFF", 16);
			mpz_set_str(q, "7FFFFFFFFFFFFFFFD6FC2A2C515DA54D57EE2B10139E9E78"\
"EC5CE2C1E7169B4AD4F09B208A3219FDE649CEE7124D9F7C"\
"BE97F1B1B1863AEC7B40D901576230BD69EF8F6AEAFEB2B0"\
"9219FA8FAF83376842B1B2AA9EF68D79DAAB89AF3FABE49A"\
"CC278638707345BBF15344ED79F7F4390EF8AC509B56F39A"\
"98566527A41D3CBD5E0558C159927DB0E88454A5D96471FD"\
"DCB56D5BB06BFA340EA7A151EF1CA6FA572B76F3B1B95D8C"\
"8583D3E4770536B84F017E70E6FBF176601A0266941A17B0"\
"C8B97F4E74C2C1FFC7278919777940C1E1FF1D8DA637D6B9"\
"9DDAFE5E17611002E2C778C1BE8B41D96379A51360D977FD"\
"4435A11C308FE7EE6F1AAD9DB28C81ADDE1A7A6F7CCE011C"\
"30DA37E4EB736483BD6C8E9348FBFBF72CC6587D60C36C8E"\
"577F0984C289C9385A098649DE21BCA27A7EA229716BA6E9"\
"B279710F38FAA5FFAE574155CE4EFB4F743695E2911B1D06"\
"D5E290CBCD86F56D0EDFCD216AE22427055E6835FD29EEF7"\
"9E0D90771FEACEBE12F20E95B34F0F78B737A9618B26FA7D"\
"BC9874F272C42BDB563EAFA16B4FB68C3BB1E78EAA81A002"\
"43FAADD2BF18E63D389AE44377DA18C576B50F0096CF3419"\
"5483B00548C0986236E3BC7CB8D6801C0494CCD199E5C5BD"\
"0D0EDC9EB8A0001E15276754FCC68566054148E6E764BEE7"\
"C764DAAD3FC45235A6DAD428FA20C170E345003F2F06EC81"\
"05FEB25B2281B63D2733BE961C29951D11DD2221657A9F53"\
"1DDA2A194DBB126448BDEEB258E07EA659C74619A6380E1D"\
"66D6832BFE67F638CD8FAE1F2723020F9C40A3FDA67EDA3B"\
"D29238FBD4D4B4885C2A99176DB1A06C500778491A8288F1"\
"855F60FFFCF1D1373FD94FC60C1811E1AC3F1C6D003BECDA"\
"3B1F2725CA595DE0CA63328F3BE57CC97755601195140DFB"\
"59D39CE091308B4105746DAC23D33E5F7CE4848DA316A9C6"\
"6B9581BA3573BFAF311496188AB15423282EE416DC2A19C5"\
"724FA91AE4ADC88BC66796EAE5677A01F64E8C0863139582"\
"2D9DB8FCEE35C06B1FEEA5474D6D8F34B1534A936A18B0E0"\
"D20EAB86BC9C6D6A5207194E67FA35551B5680267B00641C"\
"0F212D18ECA8D7327ED91FE764A84EA1B43FF5B4F6E8E62F"\
"05C661DEFB258877C35B18A151D5C414AAAD97BA3E499332"\
"E596078E600DEB81149C441CE95782F22A282563C5BAC141"\
"1423605D1AE1AFAE2C8B0660237EC128AA0FE3464E435811"\
"5DB84CC3B523073A28D4549884B81FF70E10BF361C137296"\
"28D5348F07211E7E4CF4F18B286090BDB1240B66D6CD4AFC"\
"EADC00CA446CE05050FF183AD2BBF118C1FC0EA51F97D22B"\
"8F7E46705D4527F45B42AEFF395853376F697DD5FDF2C518"\
"7D7D5F0E2EB8D43F17BA0F7C60FF437F535DFEF29833BF86"\
"CBE88EA4FBD4221E8411728354FA30A7008F154A41C7FC46"\
"6B4645DBE2E321267FFFFFFFFFFFFFFF", 16);
			mpz_set_ui(g, 2UL);
			mpz_set_ui(k, 1UL);
		}
		else
		{
			std::cerr << "ERROR: security factor = " << factor << " not" <<
				" supported by RFC 7919" << std::endl;
			mpz_clear(p), mpz_clear(q), mpz_clear(g), mpz_clear(k);	
			return -1;
		}

		// export group parameters to stdout
		std::cout << "// setup CRS (common reference string) aka set of" <<
			" domain parameters" << std::endl;
		std::cout << "//           ";
		std::cout << "|p| = " << mpz_sizeinbase(p, 2L) << " bit, ";
		std::cout << "|q| = " << mpz_sizeinbase(q, 2L) << " bit, ";
		std::cout << "|g| = " << mpz_sizeinbase(g, 2L) << " bit";
		std::cout << std::endl;
		std::cout << "crs = \"rfc-crs|" << p << "|" << q << "|" << g << "|" <<
			k << "|\"" << std::endl;

		// release
		mpz_clear(p), mpz_clear(q), mpz_clear(g), mpz_clear(k);	
	}
	else
	{
		// create VTMF instance as a CRS (common reference string)
		BarnettSmartVTMF_dlog *vtmf = NULL;
		if (prefix.length())
		{
			if (opt_verbose)
				std::cerr << "INFO: Generating primes p and q with" <<
					" k-prefix = " << prefix << ", factor = " << factor <<
					" and canonical generator g (by VTMF)" << std::endl;
			mpz_t p, q, g, k;
			mpz_init(p), mpz_init(q), mpz_init(g), mpz_init(k);
			if (mpz_set_str(k, prefix.c_str(), TMCG_MPZ_IO_BASE) < 0)
			{
				mpz_clear(p), mpz_clear(q), mpz_clear(g), mpz_clear(k);
				std::cerr << "ERROR: cannot convert given PREFIX to MPI" <<
					" value (wrong base)" << std::endl;
				return -1;
			}
			tmcg_mpz_lprime_prefix(p, q, k, TMCG_DDH_SIZE + (factor * 1024),
				TMCG_DLSE_SIZE + (factor * 128), TMCG_MR_ITERATIONS);
			mpz_t foo, bar;
			mpz_init(foo), mpz_init(bar);
			mpz_sub_ui(foo, p, 1L); // compute $p-1$
			// We use a procedure similar to FIPS 186-3 A.2.3;
			// it is supposed as verifiable generation of $g$.
			std::stringstream U;
			U << "LibTMCG|" << p << "|" << q << "|ggen|";
			do
			{
				tmcg_mpz_shash(bar, U.str());
				mpz_powm(g, bar, k, p); // $g := [bar]^k \bmod p$
				U << g << "|";
				mpz_powm(bar, g, q, p);
				// check $1 < g < p-1$ and $g^q \equiv 1 \pmod{p}$
			}
			while (!mpz_cmp_ui(g, 0L) || !mpz_cmp_ui(g, 1L) || 
				!mpz_cmp(g, foo) || mpz_cmp_ui(bar, 1L));
			mpz_clear(foo), mpz_clear(bar);
			std::stringstream input;
			input << p << std::endl << q << std::endl << g << std::endl <<
				k << std::endl;
			mpz_clear(p), mpz_clear(q), mpz_clear(g), mpz_clear(k);
			vtmf = new BarnettSmartVTMF_dlog(input, TMCG_DDH_SIZE,
				TMCG_DLSE_SIZE, true);
		}
		else
		{
			if (factor > 0)
			{
				if (opt_verbose)
					std::cerr << "INFO: Generating primes p and q with" <<
						" factor = " << factor <<
						" and canonical generator g (by VTMF)" << std::endl;
				// for each argument, sizes of underlying finite field and
				// subgroup are increased by 1024 bit resp. 128 bit
				vtmf = new BarnettSmartVTMF_dlog(TMCG_DDH_SIZE +
					(factor * 1024), TMCG_DLSE_SIZE + (factor * 128), true);
			}
			else
			{
				if (opt_verbose)
					std::cerr << "INFO: Generating primes p and q with" <<
						" default sizes and canonical generator g (by VTMF)" <<
						std::endl;
				// use default security parameter from LibTMCG and
				// verifiable generation of $g$
				vtmf = new BarnettSmartVTMF_dlog(TMCG_DDH_SIZE, TMCG_DLSE_SIZE,
					true);
			}
		}

		// check the instance for sanity
		if (!vtmf->CheckGroup())
		{
			std::cerr << "ERROR: Group G from CRS is incorrectly generated!" <<
				std::endl;
			return -1;
		}

		// export group parameters to stdout
		std::cout << "// setup CRS (common reference string) aka set of" <<
			" domain parameters" << std::endl;
		std::cout << "//           ";
		std::cout << "|p| = " << mpz_sizeinbase(vtmf->p, 2L) << " bit, ";
		std::cout << "|q| = " << mpz_sizeinbase(vtmf->q, 2L) << " bit, ";
		std::cout << "|g| = " << mpz_sizeinbase(vtmf->g, 2L) << " bit";
		std::cout << std::endl;
		std::cout << "crs = \"crs|" << vtmf->p << "|" << vtmf->q << "|" <<
			vtmf->g << "|" << vtmf->k << "|\"" << std::endl;

		// release
		delete vtmf;
	}
	
	return 0;
}

