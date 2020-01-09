/*******************************************************************************
   This file is part of Distributed Privacy Guard (DKGPG).

 Copyright (C) 2017, 2018, 2019, 2020  Heiko Stamer <HeikoStamer@gmx.net>

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
#include "dkg-common.hh"

bool fips_verify
	(mpz_srcptr fips_p, mpz_srcptr fips_q, mpz_srcptr fips_g,
	 mpz_srcptr fips_hashalgo, mpz_srcptr fips_dps, mpz_srcptr fips_counter,
	 mpz_srcptr fips_index, const int opt_verbose)
{
		// 1. $L = \mathbf{len}(p)$.
		size_t fips_L = mpz_sizeinbase(fips_p, 2L);
		// 2. $N = \mathbf{len}(q)$.
		size_t fips_N = mpz_sizeinbase(fips_q, 2L);
		// 3. Check that the $(L, N)$ pair is in the list of acceptable $(L, N)$
		//    pairs. If the pair is not in the list, the return INVALID.
		if (!((fips_L == 2048) && (fips_N == 256)) &&
			!((fips_L == 3072) && (fips_N == 256)))
		{
			return false;
		}
		// 4. If $counter > (4L - 1)$, the return INVALID.
		if (mpz_cmp_ui(fips_counter, (4L * fips_L) - 1L) > 0)
			return false;
		// 5. $seedlen = \mathbf{len}(domain_parameter_seed)$.
		size_t fips_seedlen = mpz_sizeinbase(fips_dps, 2L);
		// 6. If $(seedlen < N)$, then return INVALID.
		if (fips_seedlen < fips_N)
			return false;
		// 7. $U = \mathbf{Hash}(domain\_parameter\_seed) \bmod 2^{N-1}$.
		mpz_t U, computed_q;
		mpz_init(U), mpz_init(computed_q),
		tmcg_mpz_fhash(U, mpz_get_ui(fips_hashalgo), fips_dps);
		mpz_tdiv_r_2exp(U, U, fips_N - 1);
		// 8. $computed\_q = 2^{N-1} + U + 1 - (U \bmod 2)$.
		mpz_set_ui(computed_q, 1L);
		mpz_mul_2exp(computed_q, computed_q, fips_N - 1);
		mpz_add(computed_q, computed_q, U);
		mpz_add_ui(computed_q, computed_q, 1L);
		if (mpz_odd_p(U))
			mpz_sub_ui(computed_q, computed_q, 1L);
		// 9. Test whether or not $computed\_q$ is prime as specified in
		//    Appendix C.3. If $(computed\_q \neq q)$ or ($computed\_q$ is not
		//    prime), the return INVALID.
		if (mpz_cmp(computed_q, fips_q) || !mpz_probab_prime_p(computed_q, 56))
		{
			mpz_clear(U), mpz_clear(computed_q);
			return false;
		}
		// 10. $n = \lceil L / outlen \rceil - 1$.
		size_t outlen = tmcg_mpz_fhash_len((int)mpz_get_ui(fips_hashalgo)) * 8;
		size_t fips_n = (fips_L / outlen) - 1;
		// 11. $b = L - 1 - (n * outlen)$.
		size_t fips_b = fips_L - 1 - (fips_n * outlen);
		// 12. $offset = 1$.
		size_t fips_offset = 1;
		// 13. For $i = 0$ to $counter$ do
		mpz_t q2, W, X, c, computed_p;
		mpz_init(q2), mpz_init(W), mpz_init(X), mpz_init(c);
		mpz_init(computed_p);
		std::vector<mpz_ptr> V_j;
		for (size_t j = 0; j <= fips_n; j++)
		{
			mpz_ptr tmp = new mpz_t();
			mpz_init(tmp);
			V_j.push_back(tmp);
		}
		mpz_mul_2exp(q2, fips_q, 1L);
		size_t fips_i = 0;
		for (fips_i = 0; fips_i <= mpz_get_ui(fips_counter); fips_i++)
		{
			// 13.1 For $j = 0$ to $n$ do
			for (size_t j = 0; j <= fips_n; j++)
			{
				// $V_j = \mathbf{Hash}((domain_parameter_seed + offset + j)
				//        \bmod 2^{seedlen})$.
				mpz_t tmp;
				mpz_init_set(tmp, fips_dps);
				mpz_add_ui(tmp, tmp, fips_offset);
				mpz_add_ui(tmp, tmp, j);
				mpz_tdiv_r_2exp(tmp, tmp, fips_seedlen);
				tmcg_mpz_fhash(V_j[j], (int)mpz_get_ui(fips_hashalgo), tmp);
				mpz_clear(tmp);
			}
			// 13.2 $W = V_0 + (V_1 * 2^{outlen}) + \cdots +
			//           (V_{n-1} * 2^{(n-1)*outlen}) +
			//           ((V_n \bmod 2^b) * 2^{n*outlen})$.
			mpz_set_ui(W, 0L);
			for (size_t j = 0; j <= fips_n; j++)
			{
				mpz_t tmp;
				mpz_init_set(tmp, V_j[j]);
				if (j == fips_n)
					mpz_tdiv_r_2exp(tmp, tmp, fips_b);
				mpz_mul_2exp(tmp, tmp, (j * outlen));
				mpz_add(W, W, tmp);
				mpz_clear(tmp);
			}
			// 13.3 $X = W + 2^{L-1}$.
			mpz_set_ui(X, 1L);
			mpz_mul_2exp(X, X, fips_L - 1);
			mpz_add(X, X, W);
			// 13.4 $c = X \bmod 2q$.
			mpz_mod(c, X, q2);
			// 13.5 $computed\_p = X - (c - 1)$.
			mpz_sub(computed_p, X, c);
			mpz_add_ui(computed_p, computed_p, 1L);
			// 13.6 If $(computed\_p < 2^{L-1})$, then go to step 13.9.
			if (mpz_sizeinbase(computed_p, 2L) < fips_L)
			{
				fips_offset += (fips_n + 1);
				continue;
			}
			// 13.7 Test whether or not $computed\_p$ is prime as specified in
			//      Appendix C.3.
			// 13.8 If $computed\_p$ is determined to be prime, then go to
			//      step 14. 
			if (mpz_probab_prime_p(computed_p, 56))
				break;
			// 13.9 $offset = offset + n + 1$.
			fips_offset += (fips_n + 1);
		}
		// 14. If ($(i \neq counter)$ or $(computed\_p \neq p)$ or
		//     ($computed\_p$ is not a prime)), then return INVALID.
		if ((fips_i != mpz_get_ui(fips_counter)) ||
			mpz_cmp(computed_p, fips_p) || !mpz_probab_prime_p(computed_p, 56))
		{
			mpz_clear(U), mpz_clear(computed_q), mpz_clear(q2), mpz_clear(W);
			mpz_clear(X), mpz_clear(c), mpz_clear(computed_p);
			for (size_t j = 0; j <= fips_n; j++)
			{
				mpz_clear(V_j[j]);
				delete [] V_j[j];
			}
			V_j.clear();
			return false;
		}
		// 1. If ($index$ is incorrect), then return INVALID.
		if (mpz_cmp_ui(fips_index, 108L))
		{		
			mpz_clear(U), mpz_clear(computed_q), mpz_clear(q2), mpz_clear(W);
			mpz_clear(X), mpz_clear(c), mpz_clear(computed_p);
			for (size_t j = 0; j <= fips_n; j++)
			{
				mpz_clear(V_j[j]);
				delete [] V_j[j];
			}
			V_j.clear();
			return false;
		}
		// 2. Verify that $2 \le g \le (p - 1)$. If not true, return INVALID.
		mpz_set(q2, fips_p);
		mpz_sub_ui(q2, q2, 1L);
		if ((mpz_cmp_ui(fips_g, 2L) < 0) || (mpz_cmp(fips_g, q2) > 0))
		{
			mpz_clear(U), mpz_clear(computed_q), mpz_clear(q2), mpz_clear(W);
			mpz_clear(X), mpz_clear(c), mpz_clear(computed_p);
			for (size_t j = 0; j <= fips_n; j++)
			{
				mpz_clear(V_j[j]);
				delete [] V_j[j];
			}
			V_j.clear();
			return false;
		}
		// 3. If $(g^q \neq 1 \bmod p)$, then return INVALID.
		mpz_powm(q2, fips_g, fips_q, fips_p);
		if (mpz_cmp_ui(q2, 1L))
		{
			mpz_clear(U), mpz_clear(computed_q), mpz_clear(q2), mpz_clear(W);
			mpz_clear(X), mpz_clear(c), mpz_clear(computed_p);
			for (size_t j = 0; j <= fips_n; j++)
			{
				mpz_clear(V_j[j]);
				delete [] V_j[j];
			}
			V_j.clear();
			return false;
		}
		// 4. $N = \mathbf{len}(q)$.
		fips_N = mpz_sizeinbase(fips_q, 2L);
		if (opt_verbose)
			std::cerr << "INFO: fips_N = " << fips_N << std::endl;
		// 5. $e = (p - 1)/q$.
		mpz_t e;
		mpz_init_set(e, fips_p);
		mpz_sub_ui(e, e, 1L);
		mpz_div(e, e, fips_q);
		// 6. $count = 0$.
		mpz_t count, computed_g;
		mpz_init_set_ui(count, 0L);
		mpz_init(computed_g);
		while (1)
		{
			// 7. $count = count + 1$.
			mpz_add_ui(count, count, 1L);
			// 8. If $(count = 0)$, then return INVALID.
			if (!mpz_cmp_ui(count, 0L))
			{
				mpz_clear(U), mpz_clear(computed_q), mpz_clear(q2);
				mpz_clear(W), mpz_clear(X), mpz_clear(c), mpz_clear(computed_p);
				for (size_t j = 0; j <= fips_n; j++)
				{
					mpz_clear(V_j[j]);
					delete [] V_j[j];
				}
				V_j.clear();
				mpz_clear(e), mpz_clear(count), mpz_clear(computed_g);
				return false;
			}
			// 9. $U = domain_parameter_seed || "ggen" || index || count$.
			// 10. $W = \mathbf{Hash}(U)$.
			tmcg_mpz_fhash_ggen(W, (int)mpz_get_ui(fips_hashalgo), fips_dps,
				"ggen", fips_index, count);
			// 11. $computed\_g = W^e \bmod p$.
			mpz_powm(computed_g, W, e, fips_p);
			// 12. If $(computed\_g < 2)$, the go to step 7.
			if (mpz_cmp_ui(computed_g, 2L) < 0)
				continue;
			// 13. If $(computed\_g = g)$, then return VALID, else return
			//     INVALID.
			if (mpz_cmp(computed_g, fips_g))
			{
				mpz_clear(U), mpz_clear(computed_q), mpz_clear(q2);
				mpz_clear(W), mpz_clear(X), mpz_clear(c), mpz_clear(computed_p);
				for (size_t j = 0; j <= fips_n; j++)
				{
					mpz_clear(V_j[j]);
					delete [] V_j[j];
				}
				V_j.clear();
				mpz_clear(e), mpz_clear(count), mpz_clear(computed_g);
				return false;
			}
			break;
		}
		// release
		mpz_clear(U), mpz_clear(computed_q), mpz_clear(q2), mpz_clear(W);
		mpz_clear(X), mpz_clear(c), mpz_clear(computed_p);
		for (size_t j = 0; j <= fips_n; j++)
		{
			mpz_clear(V_j[j]);
			delete [] V_j[j];
		}
		V_j.clear();
		mpz_clear(e), mpz_clear(count), mpz_clear(computed_g);
		// verification of domain parameters successful
		return true;
}

bool pqg_extract
	(std::string ecrs, const bool fips, const int opt_verbose,
	 mpz_ptr fips_p, mpz_ptr fips_q, mpz_ptr fips_g,
	 std::stringstream &crss)
{
	std::string mpz_str;
	mpz_t crsmpz;
	mpz_init(crsmpz);
	for (size_t i = 0; i < 4; i++)
	{
		if (!TMCG_ParseHelper::gs(ecrs, '|', mpz_str))
		{
			std::cerr << "ERROR: common reference string (CRS) is corrupted" <<
				std::endl;
			mpz_clear(crsmpz);
			return false;
		}
		else if ((mpz_set_str(crsmpz, mpz_str.c_str(), TMCG_MPZ_IO_BASE) < 0) ||
			!TMCG_ParseHelper::nx(ecrs, '|'))
		{
			std::cerr << "ERROR: common reference string (CRS) is corrupted" <<
				std::endl;
			mpz_clear(crsmpz);
			return false;
		}
		crss << crsmpz << std::endl;
		if (i == 0)
		{
			mpz_set(fips_p, crsmpz);
			if (opt_verbose > 1)
				std::cerr << "INFO: p";
		}
		else if (i == 1)
		{
			mpz_set(fips_q, crsmpz);
			if (opt_verbose > 1)
				std::cerr << "INFO: q";
		}
		else if (i == 2)
		{
			mpz_set(fips_g, crsmpz);
			if (opt_verbose > 1)
				std::cerr << "INFO: g";
		}
		if ((opt_verbose > 1) && (i < 3))
		{
			std::cerr << " (" << mpz_sizeinbase(crsmpz, 2L) << " bits) = " <<
				crsmpz << std::endl;
		}
	}
	mpz_clear(crsmpz);
	if (fips)
	{
		mpz_t fips_hashalgo, fips_dps, fips_counter, fips_index;
		mpz_init_set_ui(fips_hashalgo, 0L), mpz_init_set_ui(fips_dps, 0L);
		mpz_init_set_ui(fips_counter, 0L), mpz_init_set_ui(fips_index, 0L);
		if (!TMCG_ParseHelper::gs(ecrs, '|', mpz_str))
		{
			std::cerr << "ERROR: common reference string (CRS) is corrupted" <<
				std::endl;
			mpz_clear(fips_hashalgo), mpz_clear(fips_dps);
			mpz_clear(fips_counter), mpz_clear(fips_index);
			return false;
		}
		if ((mpz_set_str(fips_hashalgo, mpz_str.c_str(),
			TMCG_MPZ_IO_BASE) < 0) || !TMCG_ParseHelper::nx(ecrs, '|'))
		{
			std::cerr << "ERROR: common reference string (CRS) is corrupted" <<
				std::endl;
			mpz_clear(fips_hashalgo), mpz_clear(fips_dps);
			mpz_clear(fips_counter), mpz_clear(fips_index);
			return false;
		}
		if (!TMCG_ParseHelper::gs(ecrs, '|', mpz_str))
		{
			std::cerr << "ERROR: common reference string (CRS) is corrupted" <<
				std::endl;
			mpz_clear(fips_hashalgo), mpz_clear(fips_dps);
			mpz_clear(fips_counter), mpz_clear(fips_index);
			return false;
		}
		if ((mpz_set_str(fips_dps, mpz_str.c_str(), TMCG_MPZ_IO_BASE) < 0) ||
			(!TMCG_ParseHelper::nx(ecrs, '|')))
		{
			std::cerr << "ERROR: common reference string (CRS) is corrupted" <<
				std::endl;
			mpz_clear(fips_hashalgo), mpz_clear(fips_dps);
			mpz_clear(fips_counter), mpz_clear(fips_index);
			return false;
		}
		if (!TMCG_ParseHelper::gs(ecrs, '|', mpz_str))
		{
			std::cerr << "ERROR: common reference string (CRS) is corrupted" <<
				std::endl;
			mpz_clear(fips_hashalgo), mpz_clear(fips_dps);
			mpz_clear(fips_counter), mpz_clear(fips_index);
			return false;
		}
		if ((mpz_set_str(fips_counter, mpz_str.c_str(),
			TMCG_MPZ_IO_BASE) < 0) || (!TMCG_ParseHelper::nx(ecrs, '|')))
		{
			std::cerr << "ERROR: common reference string (CRS) is corrupted" <<
				std::endl;
			mpz_clear(fips_hashalgo), mpz_clear(fips_dps);
			mpz_clear(fips_counter), mpz_clear(fips_index);
			return false;
		}
		if (!TMCG_ParseHelper::gs(ecrs, '|', mpz_str))
		{
			std::cerr << "ERROR: common reference string (CRS) is corrupted" <<
				std::endl;
			mpz_clear(fips_hashalgo), mpz_clear(fips_dps);
			mpz_clear(fips_counter), mpz_clear(fips_index);
			return false;
		}
		if ((mpz_set_str(fips_index, mpz_str.c_str(), TMCG_MPZ_IO_BASE) < 0) ||
			(!TMCG_ParseHelper::nx(ecrs, '|')))
		{
			std::cerr << "ERROR: common reference string (CRS) is corrupted" <<
				std::endl;
			mpz_clear(fips_hashalgo), mpz_clear(fips_dps);
			mpz_clear(fips_counter), mpz_clear(fips_index);
			return false;
		}
		if (mpz_get_ui(fips_hashalgo) != GCRY_MD_SHA256) 
		{
			std::cerr << "ERROR: hash function is not approved according to" <<
				" FIPS 186-4" << std::endl;
			mpz_clear(fips_hashalgo), mpz_clear(fips_dps);
			mpz_clear(fips_counter), mpz_clear(fips_index);
			return false;
		}
		// check the domain parameters according to FIPS 186-4 sections
		// A.1.1.3 and A.2.4
		if (!fips_verify(fips_p, fips_q, fips_g, fips_hashalgo, fips_dps,
			fips_counter, fips_index, opt_verbose))
		{
			std::cerr << "ERROR: domain parameters are not set according to" <<
				" FIPS 186-4" << std::endl;
			mpz_clear(fips_hashalgo), mpz_clear(fips_dps);
			mpz_clear(fips_counter), mpz_clear(fips_index);
			return false;
		}
		// release
		mpz_clear(fips_hashalgo), mpz_clear(fips_dps);
		mpz_clear(fips_counter), mpz_clear(fips_index);
	}
	return true;
}

bool init_tDSS
	(const TMCG_OpenPGP_Prvkey *prv, const int opt_verbose,
	 CanettiGennaroJareckiKrawczykRabinDSS* &dss)
{
//	tmcg_openpgp_secure_stringstream_t dss_in; // TODO
	std::stringstream dss_in;
	dss_in << prv->pub->dsa_p << std::endl << prv->pub->dsa_q << std::endl <<
		prv->pub->dsa_g << std::endl << prv->tdss_h << std::endl;
	dss_in << prv->tdss_n << std::endl << prv->tdss_t << std::endl <<
		prv->tdss_i << std::endl;
	dss_in << prv->tdss_x_i << std::endl << prv->tdss_xprime_i << std::endl <<
		prv->pub->dsa_y << std::endl;
	dss_in << prv->tdss_qual.size() << std::endl;
	for (size_t i = 0; i < prv->tdss_qual.size(); i++)
		dss_in << prv->tdss_qual[i] << std::endl;
	// tdss->dkg
	dss_in << prv->pub->dsa_p << std::endl << prv->pub->dsa_q << std::endl <<
		prv->pub->dsa_g << std::endl << prv->tdss_h << std::endl;
	dss_in << prv->tdss_n << std::endl << prv->tdss_t << std::endl <<
		prv->tdss_i << std::endl;
	dss_in << prv->tdss_x_i << std::endl << prv->tdss_xprime_i << std::endl <<
		prv->pub->dsa_y << std::endl;
	dss_in << prv->tdss_qual.size() << std::endl;
	for (size_t i = 0; i < prv->tdss_qual.size(); i++)
		dss_in << prv->tdss_qual[i] << std::endl;
	// tdss->dkg->x_rvss
	dss_in << prv->pub->dsa_p << std::endl << prv->pub->dsa_q << std::endl <<
		prv->pub->dsa_g << std::endl << prv->tdss_h << std::endl;
	dss_in << prv->tdss_n << std::endl << prv->tdss_t << std::endl <<
		prv->tdss_i << std::endl << prv->tdss_t << std::endl;
	dss_in << prv->tdss_x_i << std::endl << prv->tdss_xprime_i << std::endl;
	dss_in << "0" << std::endl << "0" << std::endl;
	dss_in << prv->tdss_x_rvss_qual.size() << std::endl;
	for (size_t i = 0; i < prv->tdss_x_rvss_qual.size(); i++)
		dss_in << prv->tdss_x_rvss_qual[i] << std::endl;
	assert((prv->tdss_c_ik.size() == prv->tdss_n));
	for (size_t i = 0; i < prv->tdss_c_ik.size(); i++)
	{
		for (size_t j = 0; j < prv->tdss_c_ik.size(); j++)
			dss_in << "0" << std::endl << "0" << std::endl;
		assert((prv->tdss_c_ik[i].size() == (prv->tdss_t + 1)));
		for (size_t k = 0; k < prv->tdss_c_ik[i].size(); k++)
			dss_in << prv->tdss_c_ik[i][k] << std::endl;
	}
	if (prv->tdss_n > 0)
	{
		if (opt_verbose)
		{
			std::cerr << "INFO: CanettiGennaroJareckiKrawczykRabinDSS(in," <<
				" ...)" << std::endl;
		}
		dss = new CanettiGennaroJareckiKrawczykRabinDSS(dss_in);
	}
	else
	{
		if (opt_verbose)
		{
			std::cerr << "INFO: CanettiGennaroJareckiKrawczykRabinDSS" <<
				"(1, 0, 0, ...) dummy instance" << std::endl;
		}
		// check magic bytes of CRS (common reference string)
		bool fips = false;
		if (TMCG_ParseHelper::cm(crs, "crs", '|'))
		{
			if (opt_verbose)
			{
				std::cerr << "INFO: verifying domain parameters (according" <<
					" to LibTMCG::VTMF constructor)" << std::endl;
			}
		}
		else if (TMCG_ParseHelper::cm(crs, "fips-crs", '|'))
		{
			if (opt_verbose)
			{
				std::cerr << "INFO: verifying domain parameters (according" <<
					" to FIPS 186-4 section A.1.1.2)" << std::endl;
			}
			fips = true;
		}
		else
		{
			std::cerr << "ERROR: common reference string (CRS) is not valid" <<
				std::endl;
			return false;
		}
		std::stringstream crss;
		mpz_t fips_p, fips_q, fips_g;	
		mpz_init(fips_p), mpz_init(fips_q), mpz_init(fips_g);
		if (!pqg_extract(crs, fips, opt_verbose, fips_p, fips_q, fips_g, crss))
		{
			mpz_clear(fips_p), mpz_clear(fips_q), mpz_clear(fips_g);
			return false;
		}
		mpz_t gen_h;
		mpz_init(gen_h);
		mpz_powm_ui(gen_h, fips_g, 42UL, fips_p);
		dss = new CanettiGennaroJareckiKrawczykRabinDSS(1, 0, 0,
			fips_p, fips_q, fips_g, gen_h);
		mpz_clear(gen_h);
		mpz_clear(fips_p), mpz_clear(fips_q), mpz_clear(fips_g);
	}
 	if (!dss->CheckGroup())
	{
		std::cerr << "ERROR: bad tDSS domain parameters" << std::endl;
		return false;
	}
	return true;
}

bool init_tElG
	(const TMCG_OpenPGP_PrivateSubkey *sub, const int opt_verbose,
	 GennaroJareckiKrawczykRabinDKG* &dkg)
{
//	tmcg_openpgp_secure_stringstream_t dkg_in; // TODO
	std::stringstream dkg_in;
	dkg_in << sub->pub->elg_p << std::endl << sub->telg_q << std::endl <<
		sub->pub->elg_g << std::endl << sub->telg_h << std::endl;
	dkg_in << sub->telg_n << std::endl << sub->telg_t << std::endl <<
		sub->telg_i << std::endl;
	dkg_in << sub->telg_x_i << std::endl << sub->telg_xprime_i <<
		std::endl << sub->pub->elg_y << std::endl;
	dkg_in << sub->telg_qual.size() << std::endl;
	for (size_t i = 0; i < sub->telg_qual.size(); i++)
		dkg_in << sub->telg_qual[i] << std::endl;
	for (size_t i = 0; i < sub->telg_n; i++)
		dkg_in << "1" << std::endl; // y_i not yet stored
	for (size_t i = 0; i < sub->telg_n; i++)
		dkg_in << "0" << std::endl; // z_i not yet stored
	assert((sub->telg_v_i.size() == sub->telg_n));
	for (size_t i = 0; i < sub->telg_v_i.size(); i++)
		dkg_in << sub->telg_v_i[i] << std::endl;
	assert((sub->telg_c_ik.size() == sub->telg_n));
	for (size_t i = 0; i < sub->telg_n; i++)
	{
		// s_ij and sprime_ij not yet stored
		for (size_t j = 0; j < sub->telg_n; j++)
			dkg_in << "0" << std::endl << "0" << std::endl;
		assert((sub->telg_c_ik[i].size() == (sub->telg_t + 1)));
		for (size_t k = 0; k < sub->telg_c_ik[i].size(); k++)
			dkg_in << sub->telg_c_ik[i][k] << std::endl;
	}
	if (opt_verbose)
		std::cerr << "INFO: GennaroJareckiKrawczykRabinDKG(in, ...)" <<
			std::endl;
	dkg = new GennaroJareckiKrawczykRabinDKG(dkg_in);
	if (!dkg->CheckGroup())
	{
		std::cerr << "ERROR: bad tElG domain parameters" << std::endl;
		return false;
	}
	if (!dkg->CheckKey())
	{
		std::cerr << "ERROR: bad tElG key" << std::endl;
		return false;
	}
	return true;
}

bool verify_signature
	(const tmcg_openpgp_octets_t &data,
	 const std::string &armored_pubkey,
	 const TMCG_OpenPGP_Signature *signature,
	 const TMCG_OpenPGP_Keyring *ring,
	 const int opt_verbose,
	 const bool opt_weak,
	 const bool opt_broken)
{
	TMCG_OpenPGP_Pubkey *primary = NULL;
	bool parse_ok = CallasDonnerhackeFinneyShawThayerRFC4880::
		PublicKeyBlockParse(armored_pubkey, opt_verbose, primary);
	if (parse_ok)
	{
		primary->CheckSelfSignatures(ring, opt_verbose);
		if (!primary->valid && !opt_weak)
		{
			std::cerr << "ERROR: primary key is not valid" << std::endl;
			delete primary;
			return false;
		}
		primary->CheckSubkeys(ring, opt_verbose);
		if (!opt_weak)
			primary->Reduce(); // keep only valid subkeys
		if (primary->Weak(opt_verbose) && !opt_weak)
		{
			std::cerr << "ERROR: weak primary key is not allowed" << std::endl;
			delete primary;
			return false;
		}
	}
	else
	{
		std::cerr << "ERROR: cannot use the provided public key" << std::endl;
		return false;
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
			delete primary;
			return false;
		}
		if (!CallasDonnerhackeFinneyShawThayerRFC4880::
			OctetsCompare(signature->issuer, primary->id))
		{
			std::cerr << "ERROR: no admissible public key found" << std::endl;
			delete primary;
			return false;
		}
		keyusage = primary->AccumulateFlags();
		ckeytime = primary->creationtime;
		ekeytime = primary->expirationtime;
	}
	else
	{
		if (primary->subkeys[subkey_idx]->Weak(opt_verbose) && !opt_weak)
		{
			std::cerr << "ERROR: weak subkey is not allowed" << std::endl;
			delete primary;
			return false;
		}
	}

	// additional validity checks on key and signature
	time_t current_time = time(NULL);
	// 1. key validity time (signatures made before key creation or
	//    after key expiry are not valid)
	if (signature->creationtime < ckeytime)
	{
		std::cerr << "ERROR: signature was made before key creation" <<
			std::endl;
		delete primary;
		return false;
	}
	if (ekeytime && (signature->creationtime > (ckeytime + ekeytime)))
	{
		std::cerr << "ERROR: signature was made after key expiry" << std::endl;
		delete primary;
		return false;
	}
	// 2. signature validity time (expired signatures are not valid)
	if (signature->expirationtime &&
		(current_time > (signature->creationtime + signature->expirationtime)))
	{
		std::cerr << "ERROR: signature is expired" << std::endl;
		delete primary;
		return false;
	}
	// 3. key usage flags (signatures made by keys not with the "signing"
	//    capability are not valid)
	if (!opt_weak && ((keyusage & 0x02) != 0x02))
	{
		std::cerr << "ERROR: corresponding key was not intented for signing" <<
			std::endl;
		delete primary;
		return false;
	}
	// 4. key validity time (expired keys are not valid)
	if (!opt_weak && ekeytime && (current_time > (ckeytime + ekeytime)))
	{
		std::cerr << "ERROR: corresponding key is expired" << std::endl;
		delete primary;
		return false;
	}
	// 5. hash algorithm (reject broken hash algorithms)
	if ((signature->hashalgo == TMCG_OPENPGP_HASHALGO_MD5) ||
	    (signature->hashalgo == TMCG_OPENPGP_HASHALGO_SHA1) ||
		(signature->hashalgo == TMCG_OPENPGP_HASHALGO_RMD160))
	{
		if (opt_broken)
		{
			std::cerr << "WARNING: broken hash algorithm " << 
				(int)signature->hashalgo << " used for signature" << std::endl;
		}
		else
		{
			std::cerr << "ERROR: broken hash algorithm " << 
				(int)signature->hashalgo << " used for signature" << std::endl;
			delete primary;
			return false;
		}
	}

	// verify signature cryptographically
	bool verify_ok = false;
	if (subkey_selected)
	{
		verify_ok = signature->VerifyData(primary->subkeys[subkey_idx]->key,
			data, opt_verbose);
	}
	else
		verify_ok = signature->VerifyData(primary->key, data, opt_verbose);
	std::string fpr;
	CallasDonnerhackeFinneyShawThayerRFC4880::
		FingerprintConvertPlain(primary->fingerprint, fpr);
	if (!verify_ok)
	{
		if (opt_verbose)
		{
			std::cerr << "INFO: Bad signature by key " << fpr <<
				" included" << std::endl;
		}
	}
	else
	{
		if (opt_verbose)
		{
			std::cerr << "INFO: Good signature by key " << fpr <<
				" included" << std::endl;
		}
	}

	// release primary key
	delete primary;

	return verify_ok;
}

void xtest
	(const size_t num_xtests,
	 const size_t whoami,
	 const size_t peers,
	 CachinKursawePetzoldShoupRBC *rbc)
{
	for (size_t i = 0; i < num_xtests; i++)
	{
		mpz_t x;
		mpz_init_set_ui(x, i);
		std::cerr << "INFO: p_" << whoami << ": x = " << x << " <-> ";
		rbc->Broadcast(x);
		for (size_t ii = 0; ii < peers; ii++)
		{
			if (!rbc->DeliverFrom(x, ii))
				std::cerr << "<X> ";
			else
				std::cerr << x << " ";
		}
		std::cerr << std::endl;
		mpz_clear(x);
	}
}

time_t agree_time
	(const time_t mytime,
	 const size_t whoami,
	 const size_t peers,
	 const int opt_verbose,
	 CachinKursawePetzoldShoupRBC *rbc)
{
	if (opt_verbose)
		std::cerr << "INFO: agree on a creation time for OpenPGP" << std::endl;
	std::vector<time_t> tvs;
	mpz_t mtv;
	mpz_init_set_ui(mtv, mytime);
	rbc->Broadcast(mtv);
	tvs.push_back(mytime);
	for (size_t i = 0; i < peers; i++)
	{
		if (rbc->DeliverFrom(mtv, i))
		{
			time_t utv;
			utv = (time_t)mpz_get_ui(mtv);
			if (i != whoami)
				tvs.push_back(utv);
		}
		else
		{
			std::cerr << "WARNING: p_" << whoami << ": no creation" <<
				" timestamp received from p_" << i << std::endl;
		}
	}
	mpz_clear(mtv);
	std::sort(tvs.begin(), tvs.end()); // sort the received values
	if (tvs.size() < peers)
	{
		std::cerr << "WARNING: p_" << whoami << ": not enough timestamps" <<
			" received" << std::endl;
	}
	if (tvs.size() == 0)
	{
		std::cerr << "ERROR: p_" << whoami << ": no timestamps received" <<
			std::endl;
		tvs.push_back(0); // add at least one dummy return value
	}
	// use a median value as some kind of gentle agreement
	time_t coctime = tvs[tvs.size()/2];
	if (opt_verbose)
	{
		std::cerr << "INFO: p_" << whoami << ": canonicalized OpenPGP" <<
			" creation time = " << coctime << std::endl;
	}
	return coctime;
}

bool select_hashalgo
	(CanettiGennaroJareckiKrawczykRabinDSS *dss,
	 tmcg_openpgp_hashalgo_t &hashalgo)
{
	if (dss == NULL)
		return false;
	// select hash algorithm for OpenPGP based on |q| (size in bit)
	if (mpz_sizeinbase(dss->q, 2L) == 256)
		hashalgo = TMCG_OPENPGP_HASHALGO_SHA256; // SHA256 (alg 8)
	else if (mpz_sizeinbase(dss->q, 2L) == 384)
		hashalgo = TMCG_OPENPGP_HASHALGO_SHA384; // SHA384 (alg 9)
	else if (mpz_sizeinbase(dss->q, 2L) == 512)
		hashalgo = TMCG_OPENPGP_HASHALGO_SHA512; // SHA512 (alg 10)
	else
		return false;
	return true;
}

bool sign_hash
	(const tmcg_openpgp_octets_t &hash,
	 const tmcg_openpgp_octets_t &trailer,
	 const tmcg_openpgp_octets_t &left,
	 const size_t whoami,
	 const size_t peers,
	 TMCG_OpenPGP_Prvkey *prv,
	 const tmcg_openpgp_hashalgo_t hashalgo,
	 tmcg_openpgp_octets_t &sig,
	 const int opt_verbose,
	 const bool opt_y,
	 CanettiGennaroJareckiKrawczykRabinDSS *dss,
	 aiounicast_select *aiou,
	 CachinKursawePetzoldShoupRBC *rbc)
{
	// prepare the hash value
	tmcg_openpgp_byte_t buffer[1024];
	size_t buflen = 0;
	memset(buffer, 0, sizeof(buffer));
	if (opt_verbose > 1)
		std::cerr << std::hex << "INFO: hash = ";
	for (size_t i = 0; i < hash.size(); i++, buflen++)
	{
		if (i < sizeof(buffer))
			buffer[i] = hash[i];
		if (opt_verbose > 1)
			std::cerr << (int)hash[i] << " ";
	}
	if (opt_verbose > 1)
		std::cerr << std::dec << std::endl;

	// sign the hash value
	gcry_error_t ret;
	gcry_mpi_t r, s;
	r = gcry_mpi_new(2048);
	s = gcry_mpi_new(2048);
	if (opt_y == false)
	{
		gcry_mpi_t h;
		ret = gcry_mpi_scan(&h, GCRYMPI_FMT_USG, buffer, buflen, NULL);
		if (ret)
		{
			std::cerr << "ERROR: p_" << whoami << ": gcry_mpi_scan() failed" <<
				" for h" << std::endl;
			return false;
		}
		if (opt_verbose > 1)
			std::cerr << "INFO: p_" << whoami << ": h = " << h << std::endl;
		mpz_t dsa_m, dsa_r, dsa_s;
		mpz_init(dsa_m), mpz_init(dsa_r), mpz_init(dsa_s);
		if (!tmcg_mpz_set_gcry_mpi(h, dsa_m))
		{
			std::cerr << "ERROR: p_" << whoami << ": tmcg_mpz_set_gcry_mpi()" <<
				" failed for dsa_m" << std::endl;
			gcry_mpi_release(r), gcry_mpi_release(s), gcry_mpi_release(h);
			mpz_clear(dsa_m), mpz_clear(dsa_r), mpz_clear(dsa_s);
			return false;
		}
		gcry_mpi_release(h);
		std::stringstream err_log_sign;
		if (opt_verbose)
			std::cerr << "INFO: p_" << whoami << ": dss.Sign()" << std::endl;
		if (dss == NULL)
			return false; // should never happen: only to make scan-build happy
		if (!dss->Sign(peers, whoami, dsa_m, dsa_r, dsa_s,
			prv->tdss_idx2dkg, prv->tdss_dkg2idx, aiou, rbc, err_log_sign))
		{
			std::cerr << "ERROR: p_" << whoami << ": " <<
				"tDSS Sign() failed" << std::endl;
			std::cerr << "ERROR: p_" << whoami << ": log follows " <<
				std::endl << err_log_sign.str();
			gcry_mpi_release(r), gcry_mpi_release(s);
			mpz_clear(dsa_m), mpz_clear(dsa_r), mpz_clear(dsa_s);
			return false;
		}
		if (opt_verbose > 1)
			std::cerr << "INFO: p_" << whoami << ": log follows " <<
				std::endl << err_log_sign.str();
		if (!tmcg_mpz_get_gcry_mpi(r, dsa_r))
		{
			std::cerr << "ERROR: p_" << whoami << ": tmcg_mpz_get_gcry_mpi()" <<
				" failed for dsa_r" << std::endl;
			gcry_mpi_release(r), gcry_mpi_release(s);
			mpz_clear(dsa_m), mpz_clear(dsa_r), mpz_clear(dsa_s);
			return false;
		}
		if (!tmcg_mpz_get_gcry_mpi(s, dsa_s))
		{
			std::cerr << "ERROR: p_" << whoami << ": tmcg_mpz_get_gcry_mpi()" <<
				" failed for dsa_s" << std::endl;
			gcry_mpi_release(r), gcry_mpi_release(s);
			mpz_clear(dsa_m), mpz_clear(dsa_r), mpz_clear(dsa_s);
			return false;
		}
		mpz_clear(dsa_m), mpz_clear(dsa_r), mpz_clear(dsa_s);
	}
	else
	{
		switch (prv->pkalgo)
		{
			case TMCG_OPENPGP_PKALGO_RSA:
			case TMCG_OPENPGP_PKALGO_RSA_SIGN_ONLY:
				ret = CallasDonnerhackeFinneyShawThayerRFC4880::
					AsymmetricSignRSA(hash, prv->private_key, hashalgo, s);
				break;
			case TMCG_OPENPGP_PKALGO_DSA:
				ret = CallasDonnerhackeFinneyShawThayerRFC4880::
					AsymmetricSignDSA(hash, prv->private_key, r, s);
				break;
			case TMCG_OPENPGP_PKALGO_ECDSA:
				ret = CallasDonnerhackeFinneyShawThayerRFC4880::
					AsymmetricSignECDSA(hash, prv->private_key, r, s);
				break;
			case TMCG_OPENPGP_PKALGO_EDDSA:
				ret = CallasDonnerhackeFinneyShawThayerRFC4880::
					AsymmetricSignEdDSA(hash, prv->private_key, r, s);
				break;
			default:
				std::cerr << "ERROR: public-key algorithm " <<
					(int)prv->pkalgo << " not supported" << std::endl;
				gcry_mpi_release(r), gcry_mpi_release(s);
				return false;
		}
		if (ret)
		{
			std::cerr << "ERROR: signing of hash value failed " <<
				"(rc = " << gcry_err_code(ret) << ", str = " <<
				gcry_strerror(ret) << ")" << std::endl;
			gcry_mpi_release(r), gcry_mpi_release(s);
			return false;
		}
	}
	switch (prv->pkalgo)
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
			std::cerr << "ERROR: public-key algorithm " << (int)prv->pkalgo <<
				" not supported" << std::endl;
			gcry_mpi_release(r), gcry_mpi_release(s);
			return false;
	}
	gcry_mpi_release(r), gcry_mpi_release(s);
	return true;
}

void canonicalize
	(std::vector<std::string> &p)
{
	std::sort(p.begin(), p.end());
	std::vector<std::string>::iterator it = std::unique(p.begin(), p.end());
	p.resize(std::distance(p.begin(), it));
}

int wait_instance
	(const size_t whoami,
	 const int opt_verbose,
	 pid_t pid[DKGPG_MAX_N])
{
	int wstatus = 0;
	if (opt_verbose)
		std::cerr << "INFO: waitpid(" << pid[whoami] << ")" << std::endl;
	if (waitpid(pid[whoami], &wstatus, 0) != pid[whoami])
	{
		perror("ERROR: dkg-common:wait_instance (waitpid)");
		return -1; // waitpid failed
	}
	if (!WIFEXITED(wstatus))
	{
		std::cerr << "ERROR: protocol instance ";
		if (WIFSIGNALED(wstatus))
		{
			std::cerr << pid[whoami] << " terminated by signal " <<
				WTERMSIG(wstatus) << std::endl;
		}
		if (WCOREDUMP(wstatus))
			std::cerr << pid[whoami] << " dumped core" << std::endl;
		return -1; // fatal error
	}
	else if (WIFEXITED(wstatus))
	{
		if (opt_verbose)
		{
			std::cerr << "INFO: protocol instance " << pid[whoami] <<
				" terminated with exit status " << WEXITSTATUS(wstatus) <<
				std::endl;
		}
		if (WEXITSTATUS(wstatus))
			return -2; // error
	}
	return 0;
}

int run_localtest
	(const size_t peers,
	 const int opt_verbose,
	 pid_t pid[DKGPG_MAX_N],
	 int pipefd[DKGPG_MAX_N][DKGPG_MAX_N][2],
	 int self_pipefd[2],
	 int bpipefd[DKGPG_MAX_N][DKGPG_MAX_N][2],
	 int bself_pipefd[2],
	 void (*fork_instance)(const size_t))
{
	assert(peers <= DKGPG_MAX_N);
	int ret = 0;
	std::cerr << "WARNING: running only a local test with " << peers <<
		" participants" << std::endl;
	// open pipes
	for (size_t i = 0; i < peers; i++)
	{
		for (size_t j = 0; j < peers; j++)
		{
			if (pipe(pipefd[i][j]) < 0)
				perror("ERROR: dkg-common:run_localtest (pipe)");
			if (pipe(bpipefd[i][j]) < 0)
				perror("ERROR: dkg-common:run_localtest (pipe)");
		}
	}

	// initialize self-pipes
	self_pipefd[0] = -1, self_pipefd[1] = -1;
	bself_pipefd[0] = -1, bself_pipefd[1] = -1;

	// start childs
	for (size_t i = 0; i < peers; i++)
		fork_instance(i);

	// sleep for five seconds
	sleep(5);
	
	// wait for childs and close pipes
	for (size_t i = 0; i < peers; i++)
	{
		int iret = wait_instance(i, opt_verbose, pid);
		if (iret != 0)
			ret = iret; // return error, if any instance failed
		for (size_t j = 0; j < peers; j++)
		{
			if ((close(pipefd[i][j][0]) < 0) || (close(pipefd[i][j][1]) < 0))
				perror("WARNING: dkg-common:run_localtest (close)");
			if ((close(bpipefd[i][j][0]) < 0) || (close(bpipefd[i][j][1]) < 0))
				perror("WARNING: dkg-common:run_localtest (close)");
		}
	}
	return ret;
}

