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
#ifdef DKGPG_TESTSUITE
	#undef GNUNET
#else
#ifdef DKGPG_TESTSUITE_Y
	#undef GNUNET
#endif
#endif

// copy infos from DKGPG package before overwritten by GNUnet headers
static const char *version = PACKAGE_VERSION " (" PACKAGE_NAME ")";
static const char *about = PACKAGE_STRING " " PACKAGE_URL;
static const char *protocol = "DKGPG-decrypt-1.0";

#include <sstream>
#include <fstream>
#include <vector>
#include <map>
#include <string>
#include <algorithm>
#include <cstdio>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <signal.h>

#include <zlib.h>
#ifdef LIBBZ
#include <bzlib.h>
#endif

#include <libTMCG.hh>
#include <aiounicast_select.hh>

#include "dkg-tcpip-common.hh"
#include "dkg-gnunet-common.hh"
#include "dkg-io.hh"
#include "dkg-common.hh"

int 							pipefd[DKGPG_MAX_N][DKGPG_MAX_N][2];
int								broadcast_pipefd[DKGPG_MAX_N][DKGPG_MAX_N][2];
pid_t 							pid[DKGPG_MAX_N];
std::vector<std::string>		peers;
bool							instance_forked = false;

tmcg_openpgp_secure_string_t	passphrase;
std::string						ifilename, ofilename, kfilename;
std::string						passwords, hostname, port, yfilename;

int 							opt_verbose = 0;
bool							opt_binary = false, opt_E = false;
bool							opt_weak = false;
char							*opt_ifilename = NULL;
char							*opt_ofilename = NULL;
char							*opt_passwords = NULL;
char							*opt_hostname = NULL;
char							*opt_k = NULL;
char							*opt_y = NULL;
unsigned long int				opt_p = 55000, opt_W = 5;

std::string						armored_message;


void print_message
	(const tmcg_openpgp_octets_t &msg)
{
	// print out the decrypted message
	if (opt_verbose)
		std::cerr << "INFO: decrypted message:" << std::endl;
	for (size_t i = 0; i < msg.size(); i++)
		std::cout << msg[i];
}

void compute_decryption_share
	(const gcry_mpi_t gk, const GennaroJareckiKrawczykRabinDKG *dkg,
		std::string &result)
{
	// [CGS97] Ronald Cramer, Rosario Gennaro, and Berry Schoenmakers:
	//  'A Secure and Optimally Efficient Multi-Authority Election Scheme'
	// Advances in Cryptology - EUROCRYPT '97, LNCS 1233, pp. 103--118, 1997.

	// compute the decryption share
	mpz_t nizk_gk, r_i, R, foo;
	mpz_init(nizk_gk), mpz_init(r_i), mpz_init(R), mpz_init(foo);
	tmcg_mpz_spowm(R, dkg->g, dkg->x_i, dkg->p);
	if (mpz_cmp(R, dkg->v_i[dkg->i]))
	{
		std::cerr << "ERROR: check of DKG public verification key failed" <<
			std::endl;
		mpz_clear(nizk_gk), mpz_clear(r_i), mpz_clear(R), mpz_clear(foo);
		exit(-1);
	}
	if (!tmcg_mpz_set_gcry_mpi(gk, nizk_gk))
	{
		std::cerr << "ERROR: converting message component failed" << std::endl;
		mpz_clear(nizk_gk), mpz_clear(r_i), mpz_clear(R), mpz_clear(foo);
		exit(-1);
	}
	mpz_powm(foo, nizk_gk, dkg->q, dkg->p); // check for subgroup property
	if (mpz_cmp_ui(foo, 1L))
	{
		std::cerr << "ERROR: (g^k)^q equiv 1 mod p not satisfied" << std::endl;
		mpz_clear(nizk_gk), mpz_clear(r_i), mpz_clear(R), mpz_clear(foo);
		exit(-1);
	}
	tmcg_mpz_spowm(r_i, nizk_gk, dkg->x_i, dkg->p);
	// compute NIZK argument for decryption share, e.g. see [CGS97]
	// proof of knowledge (equality of discrete logarithms)
	mpz_t a, b, omega, c, r, c2;
	mpz_init(c), mpz_init(r), mpz_init(c2), mpz_init(a), mpz_init(b);
	mpz_init(omega);
	// commitment
	tmcg_mpz_srandomm(omega, dkg->q);
	tmcg_mpz_spowm(a, nizk_gk, omega, dkg->p);
	tmcg_mpz_spowm(b, dkg->g, omega, dkg->p);
	// challenge
	// Here we use the well-known "Fiat-Shamir heuristic" to make
	// the PoK non-interactive, i.e. we turn it into a statistically
	// zero-knowledge (Schnorr signature scheme style) proof of
	// knowledge (SPK) in the random oracle model.
	tmcg_mpz_shash(c, 6, a, b, r_i, dkg->v_i[dkg->i], nizk_gk, dkg->g);
	// response
	mpz_mul(r, c, dkg->x_i);
	mpz_neg(r, r);
	mpz_add(r, r, omega);
	mpz_mod(r, r, dkg->q);
	// construct dds
	std::ostringstream dds;
	dds << "dds|" << dkg->i << "|" << r_i << "|" << c << "|" << r << "|";
	mpz_clear(c), mpz_clear(r), mpz_clear(c2), mpz_clear(a), mpz_clear(b);
	mpz_clear(omega);
	mpz_clear(nizk_gk), mpz_clear(r_i), mpz_clear(R), mpz_clear(foo);
	result = dds.str();
}

void prove_decryption_share_interactive_publiccoin
	(const gcry_mpi_t gk, const GennaroJareckiKrawczykRabinDKG *dkg,
	 mpz_srcptr r_i, aiounicast *aiou, CachinKursawePetzoldShoupRBC *rbc,
	 JareckiLysyanskayaEDCF *edcf, std::ostream &err)
{
	mpz_t nizk_gk, foo;
	mpz_init(nizk_gk), mpz_init(foo);
	if (!tmcg_mpz_set_gcry_mpi(gk, nizk_gk))
	{
		std::cerr << "ERROR: converting message component failed" << std::endl;
		mpz_clear(nizk_gk), mpz_clear(foo);
		exit(-1);
	}
	mpz_powm(foo, nizk_gk, dkg->q, dkg->p); // check for subgroup property
	if (mpz_cmp_ui(foo, 1L))
	{
		std::cerr << "ERROR: (g^k)^q equiv 1 mod p not satisfied" << std::endl;
		mpz_clear(nizk_gk), mpz_clear(foo);
		exit(-1);
	}
	// set ID for RBC
	std::stringstream myID;
	myID << "dkg-decrypt::*_decryption_share_interactive_publiccoin" <<
		dkg->p << dkg->q << dkg->g << dkg->h << 
		edcf->h << r_i << "|" << rbc->j << "|" << dkg->i;
	rbc->setID(myID.str());
	// proof of knowledge (equality of discrete logarithms) [CGS97]
	mpz_t a, b, omega, c, r, c2;
	mpz_init(c), mpz_init(r), mpz_init(c2), mpz_init(a), mpz_init(b);
	mpz_init(omega);
	// 1. commitment
	tmcg_mpz_srandomm(omega, dkg->q);
	tmcg_mpz_spowm(a, dkg->g, omega, dkg->p);
	tmcg_mpz_spowm(b, nizk_gk, omega, dkg->p);
	rbc->Broadcast(a);
	rbc->Broadcast(b);
	// 2. challenge
	if (edcf->Flip(rbc->j, c, aiou, rbc, err))
	{
		// 3. response
		mpz_mul(r, c, dkg->x_i);
		mpz_mod(r, r, dkg->q);
		mpz_add(r, r, omega);
		mpz_mod(r, r, dkg->q);
		rbc->Broadcast(r);
	}
	// release
	mpz_clear(c), mpz_clear(r), mpz_clear(c2), mpz_clear(a), mpz_clear(b);
	mpz_clear(omega);
	mpz_clear(nizk_gk), mpz_clear(foo);
	// unset ID for RBC
	rbc->unsetID();
}

bool verify_decryption_share
	(const gcry_mpi_t gk, const GennaroJareckiKrawczykRabinDKG *dkg,
	 std::string in, size_t &idx_dkg, mpz_ptr r_i_out, mpz_ptr c_out,
	 mpz_ptr r_out)
{
	// initialize
	mpz_t c2, a, b, nizk_gk;
	mpz_init(c2), mpz_init(a), mpz_init(b), mpz_init(nizk_gk);

	try
	{
		// convert message component
		if (!tmcg_mpz_set_gcry_mpi(gk, nizk_gk))
		{
			std::cerr << "ERROR: converting message component failed" <<
				std::endl;
			throw false;
		}
		// check magic
		if (!TMCG_ParseHelper::cm(in, "dds", '|'))
			throw false;
		// parse index
		std::string idxstr, mpzstr;
		if (!TMCG_ParseHelper::gs(in, '|', idxstr))
			throw false;
		if ((sscanf(idxstr.c_str(), "%zu", &idx_dkg) < 1) ||
			!TMCG_ParseHelper::nx(in, '|'))
			throw false;
		// r_i
		if (!TMCG_ParseHelper::gs(in, '|', mpzstr))
			throw false;
		if ((mpz_set_str(r_i_out, mpzstr.c_str(), TMCG_MPZ_IO_BASE) < 0) ||
			!TMCG_ParseHelper::nx(in, '|'))
			throw false;
		// c
		if (!TMCG_ParseHelper::gs(in, '|', mpzstr))
			throw false;
		if ((mpz_set_str(c_out, mpzstr.c_str(), TMCG_MPZ_IO_BASE) < 0) ||
			!TMCG_ParseHelper::nx(in, '|'))
			throw false;
		// r
		if (!TMCG_ParseHelper::gs(in, '|', mpzstr))
			throw false;
		if ((mpz_set_str(r_out, mpzstr.c_str(), TMCG_MPZ_IO_BASE) < 0) ||
			!TMCG_ParseHelper::nx(in, '|'))
			throw false;
		// check index for sanity
		if (idx_dkg >= (dkg->v_i).size())
			throw false;
		// check r_i for sanity
		if (!dkg->CheckElement(r_i_out))
			throw false;
		// check the NIZK argument for sanity
		if (mpz_cmpabs(r_out, dkg->q) >= 0)  // check the size of r
			throw false;
		size_t c_len = tmcg_mpz_shash_len() * 8;
		if (mpz_sizeinbase(c_out, 2L) > c_len) // check the size of c
			throw false;
		// verify proof of knowledge (equality of discrete logarithms), [CGS97]
		mpz_powm(a, nizk_gk, r_out, dkg->p);
		mpz_powm(b, r_i_out, c_out, dkg->p);
		mpz_mul(a, a, b);
		mpz_mod(a, a, dkg->p);
		mpz_powm(b, dkg->g, r_out, dkg->p);
		mpz_powm(c2, dkg->v_i[idx_dkg], c_out, dkg->p);
		mpz_mul(b, b, c2);
		mpz_mod(b, b, dkg->p);
		tmcg_mpz_shash(c2, 6, a, b, r_i_out, dkg->v_i[idx_dkg], nizk_gk,
			dkg->g);
		if (mpz_cmp(c2, c_out))
			throw false;		

		// finish
		throw true;
	}
	catch (bool return_value)
	{
		// release
		mpz_clear(c2), mpz_clear(a), mpz_clear(b), mpz_clear(nizk_gk);
		// return
		return return_value;
	}
}

bool verify_decryption_share_interactive_publiccoin
	(const gcry_mpi_t gk, const GennaroJareckiKrawczykRabinDKG *dkg,
	 const size_t idx_rbc, const size_t idx_dkg, mpz_srcptr r_i,
	 aiounicast *aiou, CachinKursawePetzoldShoupRBC *rbc,
	 JareckiLysyanskayaEDCF *edcf, std::ostream &err)
{
	// initialize
	mpz_t a, b, c, r, foo, bar, nizk_gk;
	mpz_init(a), mpz_init(b), mpz_init(c), mpz_init(r);
	mpz_init(foo), mpz_init(bar), mpz_init(nizk_gk);

	// set ID for RBC
	std::stringstream myID;
	myID << "dkg-decrypt::*_decryption_share_interactive_publiccoin" <<
		dkg->p << dkg->q << dkg->g << dkg->h <<
		edcf->h << r_i << "|" << idx_rbc << "|" << idx_dkg;
	rbc->setID(myID.str());

	try
	{
		// convert message component
		if (!tmcg_mpz_set_gcry_mpi(gk, nizk_gk))
		{
			std::cerr << "ERROR: converting message component failed" <<
				std::endl;
			throw false;
		}
		// check index for sanity
		if (idx_dkg >= (dkg->v_i).size())
		{
			err << "verify PoK: bad idx_dkg for p_" << idx_rbc << std::endl;
			throw false;
		}
		// check r_i for sanity
		if (!dkg->CheckElement(r_i))
		{
			err << "verify PoK: r_i not in G for p_" << idx_rbc << std::endl;
			throw false;
		}
		// verify proof of knowledge (equality of discrete logarithms) [CGS97]
		// 1. receive and check the commitment, i.e., $a, b \in G$
		if (!rbc->DeliverFrom(a, idx_rbc))
		{
			err << "verify PoK: DeliverFrom(a, idx_rbc) failed for p_" <<
				idx_rbc << std::endl;
			throw false;
		}
		if (!rbc->DeliverFrom(b, idx_rbc))
		{
			err << "verify PoK: DeliverFrom(b, idx_rbc) failed for p_" <<
				idx_rbc << std::endl;
			throw false;
		}
		if (!dkg->CheckElement(a) || !dkg->CheckElement(b))
		{
			err << "verify PoK: check commitment failed for p_" <<
				idx_rbc << std::endl;
			throw false;
		}
		// 2. challenge: $c\in\mathbb{Z}_q$ is computed by a distributed
		//               coin-flip protocol [JL00]
		if (!edcf->Flip(rbc->j, c, aiou, rbc, err))
			throw false;
		// 3. receive, check and verify the response
		if (!rbc->DeliverFrom(r, idx_rbc))
		{
			err << "verify PoK: DeliverFrom(r, idx_rbc) failed for p_" <<
				idx_rbc << std::endl;
			throw false;
		}
		if (mpz_cmpabs(r, dkg->q) >= 0)
		{
			err << "verify PoK: check response failed for p_" <<
				idx_rbc << std::endl;
			throw false;
		}
		// verify PoK equations [CGS97]
		mpz_powm(foo, dkg->g, r, dkg->p);
		mpz_powm(bar, dkg->v_i[idx_dkg], c, dkg->p);
		mpz_mul(bar, bar, a);
		mpz_mod(bar, bar, dkg->p);
		if (mpz_cmp(foo, bar))
		{
			err << "verify PoK: verify first equation failed for p_" <<
				idx_rbc << std::endl;
			throw false;
		}
		mpz_powm(foo, nizk_gk, r, dkg->p);
		mpz_powm(bar, r_i, c, dkg->p);
		mpz_mul(bar, bar, b);
		mpz_mod(bar, bar, dkg->p);
		if (mpz_cmp(foo, bar))
		{
			err << "verify PoK: verify second equation failed for p_" <<
				idx_rbc << std::endl;
			throw false;
		}
	
		// finish
		throw true;
	}
	catch (bool return_value)
	{
		// unset ID for RBC
		rbc->unsetID();
		// release
		mpz_clear(a), mpz_clear(b), mpz_clear(c), mpz_clear(r);
		mpz_clear(foo), mpz_clear(bar), mpz_clear(nizk_gk);
		// return
		return return_value;
	}
}

bool combine_decryption_shares
	(const gcry_mpi_t gk, const GennaroJareckiKrawczykRabinDKG *dkg,
	 std::vector<size_t> &parties, std::vector<mpz_ptr> &shares)
{
	// initialize
	mpz_t a, b, c, lambda, R;
	mpz_init(a), mpz_init(b), mpz_init(c), mpz_init(lambda);
	mpz_init_set_ui(R, 1L);

	try
	{
		std::vector<size_t> parties_sorted = parties;
		std::sort(parties_sorted.begin(), parties_sorted.end());
		std::vector<size_t>::iterator ut =
			std::unique(parties_sorted.begin(), parties_sorted.end());
		parties_sorted.resize(std::distance(parties_sorted.begin(), ut));
		if ((parties.size() <= dkg->t) || (shares.size() <= dkg->t) ||
			(parties.size() != shares.size()) ||
			(parties_sorted.size() <= dkg->t))
		{
			std::cerr << "ERROR: not enough decryption shares collected" <<
				std::endl;
			throw false;
		}
		if (parties.size() > (dkg->t + 1))
			parties.resize(dkg->t + 1); // exactly $t + 1$ shares required
		if (opt_verbose)
		{
			std::cerr << "INFO: combine_decryption_shares():" <<
				" Lagrange interpolation with ";
			for (std::vector<size_t>::iterator jt = parties.begin();
				jt != parties.end(); ++jt)
			{
				std::cerr << "P_" << *jt << " ";
			}
			std::cerr << std::endl;
		}

		// compute $R = \prod_{i\in\Lambda} r_i^\lambda_{i,\Lambda} \bmod p$
		// where $\lambda_{i, \Lambda} = \prod_{l\in\Lambda\setminus\{i\}
		//                                      \frac{l}{l-i}}$
		size_t j = 0;
		for (std::vector<size_t>::iterator jt = parties.begin();
			jt != parties.end(); ++jt, ++j)
		{
			mpz_set_ui(a, 1L); // compute optimized Lagrange coefficients
			for (std::vector<size_t>::iterator lt = parties.begin();
				lt != parties.end(); ++lt)
			{
				if (*lt != *jt)
					mpz_mul_ui(a, a, (*lt + 1)); // adjust index in computation
			}
			mpz_set_ui(b, 1L);
			for (std::vector<size_t>::iterator lt = parties.begin();
				lt != parties.end(); ++lt)
			{
				if (*lt != *jt)
				{
					mpz_set_ui(c, (*lt + 1)); // adjust index in computation
					mpz_sub_ui(c, c, (*jt + 1)); // adjust index in computation
					mpz_mul(b, b, c);
				}
			}
			if (!mpz_invert(b, b, dkg->q))
			{
				std::cerr << "ERROR: cannot invert during interpolation" <<
					std::endl;
				throw false;
			}
			mpz_mul(lambda, a, b);
			mpz_mod(lambda, lambda, dkg->q);
			// computation of Lagrange coefficients finished
			// now interpolate and accumulate correct decryption shares
			mpz_powm(a, shares[j], lambda, dkg->p);
			mpz_mul(R, R, a);
			mpz_mod(R, R, dkg->p);
		}

		// copy the result from R to gk
		gcry_mpi_t gk_tmp;
		gk_tmp = gcry_mpi_new(2048);
		if (!tmcg_mpz_get_gcry_mpi(gk_tmp, R))
		{
			std::cerr << "ERROR: converting interpolated result failed" <<
				std::endl;
			gcry_mpi_release(gk_tmp);
			throw false;
		}
		gcry_mpi_set(gk, gk_tmp);
		gcry_mpi_release(gk_tmp);

		// finish
		throw true;
	}
	catch (bool return_value)
	{
		// release
		mpz_clear(a), mpz_clear(b), mpz_clear(c), mpz_clear(lambda);
		mpz_clear(R);
		// return
		return return_value;
	}
}

bool decrypt_session_key
	(const gcry_mpi_t p, const gcry_mpi_t g, const gcry_mpi_t y,
	 const gcry_mpi_t gk, const gcry_mpi_t myk,
	 tmcg_openpgp_secure_octets_t &out)
{
	gcry_mpi_t elg_x;
	gcry_sexp_t elgkey;
	size_t erroff;
	// cheat libgcrypt (decryption key shares have been already applied to gk)
	elg_x = gcry_mpi_new(2048);
	gcry_mpi_set_ui(elg_x, 1);
	gcry_error_t ret = gcry_sexp_build(&elgkey, &erroff,
		"(private-key (elg (p %M) (g %M) (y %M) (x %M)))", p, g, y, elg_x);
	gcry_mpi_release(elg_x);
	if (ret)
	{
		std::cerr << "ERROR: processing ElGamal key material failed" <<
			std::endl;
		return false;
	}
	ret = CallasDonnerhackeFinneyShawThayerRFC4880::
		AsymmetricDecryptElgamal(gk, myk, elgkey, out);
	gcry_sexp_release(elgkey);
	if (ret)
	{
		std::cerr << "ERROR: AsymmetricDecryptElgamal() failed" <<
			" with rc = " << gcry_err_code(ret) << std::endl;
		return false;
	}
	return true;
}

bool check_esk
	(const TMCG_OpenPGP_PKESK* esk, const TMCG_OpenPGP_PrivateSubkey* ssb)
{
	if ((esk->pkalgo == TMCG_OPENPGP_PKALGO_ELGAMAL) &&
		(ssb->pkalgo == TMCG_OPENPGP_PKALGO_EXPERIMENTAL9))
	{
		// check whether $0 < g^k < p$.
		if ((gcry_mpi_cmp_ui(esk->gk, 0L) <= 0) ||
			(gcry_mpi_cmp(esk->gk, ssb->pub->elg_p) >= 0))
		{
			if (opt_verbose > 1)
				std::cerr << "ERROR: 0 < g^k < p not satisfied" << std::endl;
			return false;
		}
		// check whether $0 < my^k < p$.
		if ((gcry_mpi_cmp_ui(esk->myk, 0L) <= 0) ||
			(gcry_mpi_cmp(esk->myk, ssb->pub->elg_p) >= 0))
		{
			if (opt_verbose > 1)
				std::cerr << "ERROR: 0 < my^k < p not satisfied" << std::endl;
			return false;
		}
		// check whether $(g^k)^q \equiv 1 \pmod{p}$.
		gcry_mpi_t tmp;
		tmp = gcry_mpi_new(2048);
		gcry_mpi_powm(tmp, esk->gk, ssb->telg_q, ssb->pub->elg_p);
		if (gcry_mpi_cmp_ui(tmp, 1L))
		{
			if (opt_verbose > 1)
				std::cerr << "ERROR: (g^k)^q equiv 1 mod p not satisfied" <<
					std::endl;
			gcry_mpi_release(tmp);
			return false;
		}
		gcry_mpi_release(tmp);
	}
	else if ((esk->pkalgo == TMCG_OPENPGP_PKALGO_ELGAMAL) &&
		(ssb->pkalgo == TMCG_OPENPGP_PKALGO_ELGAMAL))
	{
		// check whether $0 < g^k < p$.
		if ((gcry_mpi_cmp_ui(esk->gk, 0L) <= 0) ||
			(gcry_mpi_cmp(esk->gk, ssb->pub->elg_p) >= 0))
		{
			if (opt_verbose > 1)
				std::cerr << "ERROR: 0 < g^k < p not satisfied" << std::endl;
			return false;
		}
		// check whether $0 < my^k < p$.
		if ((gcry_mpi_cmp_ui(esk->myk, 0L) <= 0) ||
			(gcry_mpi_cmp(esk->myk, ssb->pub->elg_p) >= 0))
		{
			if (opt_verbose > 1)
				std::cerr << "ERROR: 0 < my^k < p not satisfied" << std::endl;
			return false;
		}
	}
	else if ((esk->pkalgo == TMCG_OPENPGP_PKALGO_RSA) &&
		(ssb->pkalgo == TMCG_OPENPGP_PKALGO_RSA))
	{
		// check whether $0 < m^e < n$.
		if ((gcry_mpi_cmp_ui(esk->me, 0L) <= 0) ||
			(gcry_mpi_cmp(esk->me, ssb->pub->rsa_n) >= 0))
		{
			if (opt_verbose > 1)
				std::cerr << "ERROR: 0 < m^e < n not satisfied" << std::endl;
			return false;
		}
	}
	return true;
}

bool decompress_libz
	(const TMCG_OpenPGP_Message* msg, tmcg_openpgp_octets_t &infmsg)
{
	int rc = 0;
	z_stream zs;
	unsigned char zin[4096];
	unsigned char zout[4096];
	zs.zalloc = Z_NULL;
	zs.zfree = Z_NULL;
	zs.opaque = Z_NULL;
	zs.avail_in = 0;
	zs.next_in = Z_NULL;
	static const char* myZlibVersion = ZLIB_VERSION;
	if (zlibVersion()[0] != myZlibVersion[0])
	{
		if (opt_verbose > 1)
			std::cerr << "ERROR: incompatible zlib version" << std::endl;
		return false;
	}
	else if (std::strcmp(zlibVersion(), ZLIB_VERSION) != 0)
	{
		if (opt_verbose > 1)
			std::cerr << "WARNING: different zlib version" << std::endl;
	}
	switch (msg->compalgo)
	{
		case TMCG_OPENPGP_COMPALGO_ZIP:
			rc = inflateInit2(&zs, -15);
			break;
		case TMCG_OPENPGP_COMPALGO_ZLIB:
			rc = inflateInit(&zs);
			break;
		default:
			if (opt_verbose > 1)
				std::cerr << "ERROR: compression algorithm " <<
					(int)msg->compalgo << " is not supported" << std::endl;
			return false;
	}
	if (rc != Z_OK)
	{
		if (opt_verbose)
		{
			std::cerr << "ZLIB ERROR: " << (int)rc;
			if (zs.msg != NULL)
				std::cerr << " " << zs.msg;
			std::cerr << std::endl;
		}
		return false;
	}
	size_t cnt = 0;
	memset(zin, 0, sizeof(zin));
	do
	{
		if (zs.avail_in == 0)
		{
			size_t zlen = 0;
			for (size_t i = 0; i < sizeof(zin); i++)
			{
				if (cnt >= (msg->compressed_data).size())
					break;
				zin[i] = (msg->compressed_data)[cnt];
				zlen++, cnt++;
			}
			zs.avail_in = zlen;
			zs.next_in = zin;
		}
		if ((zs.avail_in < sizeof(zin)) &&
			(msg->compalgo == TMCG_OPENPGP_COMPALGO_ZIP))
		{
			zin[zs.avail_in] = 0xFF; // dummy character to fake zlib structure
			zs.avail_in++;
		}
		memset(zout, 0, sizeof(zout));
		zs.avail_out = sizeof(zout);
		zs.next_out = zout;
		rc = inflate(&zs, Z_SYNC_FLUSH);
		switch (rc)
		{
			case Z_NEED_DICT:
			case Z_DATA_ERROR:
			case Z_MEM_ERROR:
			case Z_STREAM_ERROR:
				if (opt_verbose)
				{
					std::cerr << "ZLIB ERROR: " << (int)rc;
					if (zs.msg != NULL)
						std::cerr << " " << zs.msg;
					std::cerr << std::endl;
				}
				(void)inflateEnd(&zs);
				return false;
				break;
		}
		for (size_t i = 0; i < (sizeof(zout) - zs.avail_out); i++)
			infmsg.push_back(zout[i]);
	}
	while ((rc != Z_STREAM_END) && (rc != Z_BUF_ERROR));
	(void)inflateEnd(&zs);
	return (rc == Z_STREAM_END);
}

#ifdef LIBBZ
bool decompress_libbz
	(const TMCG_OpenPGP_Message* msg, tmcg_openpgp_octets_t &infmsg)
{
	int rc = 0;
	bz_stream zs;
	char zin[4096];
	char zout[4096];
	zs.bzalloc = NULL;
	zs.bzfree = NULL;
	zs.opaque = NULL;
	zs.avail_in = 0;
	zs.next_in = NULL;
	rc = BZ2_bzDecompressInit(&zs, 0, 0);
	if (rc != BZ_OK)
	{
		if (opt_verbose)
			std::cerr << "BZLIB ERROR: " << (int)rc << std::endl;
		return false;
	}
	size_t cnt = 0;
	memset(zin, 0, sizeof(zin));
	do
	{
		if (zs.avail_in == 0)
		{
			size_t zlen = 0;
			for (size_t i = 0; i < sizeof(zin); i++)
			{
				if (cnt >= (msg->compressed_data).size())
					break;
				zin[i] = (msg->compressed_data)[cnt];
				zlen++, cnt++;
			}
			zs.avail_in = zlen;
			zs.next_in = zin;
		}
		memset(zout, 0, sizeof(zout));
		zs.avail_out = sizeof(zout);
		zs.next_out = zout;
		rc = BZ2_bzDecompress(&zs);
		switch (rc)
		{
			case BZ_DATA_ERROR:
			case BZ_DATA_ERROR_MAGIC:
			case BZ_MEM_ERROR:
				if (opt_verbose)
				{
					std::cerr << "BZLIB ERROR: " << (int)rc << std::endl;
				}
				BZ2_bzDecompressEnd(&zs);
				return false;
				break;
		}
		for (size_t i = 0; i < (sizeof(zout) - zs.avail_out); i++)
			infmsg.push_back(zout[i]);
	}
	while ((rc != BZ_STREAM_END) && (rc != BZ_PARAM_ERROR));
	BZ2_bzDecompressEnd(&zs);
	return (rc == BZ_STREAM_END);
}
#endif

bool decrypt_message
	(const tmcg_openpgp_secure_octets_t seskey, const TMCG_OpenPGP_Keyring *ring,
	 TMCG_OpenPGP_Message *msg, tmcg_openpgp_octets_t &content)
{
	tmcg_openpgp_octets_t decmsg, infmsg;
	if (!msg->Decrypt(seskey, opt_verbose, decmsg))
	{
		std::cerr << "ERROR: message decryption failed" << std::endl;
		return false;
	}
	if (!CallasDonnerhackeFinneyShawThayerRFC4880::MessageParse(decmsg,
		opt_verbose, msg))
	{
		std::cerr << "ERROR: message parsing failed" << std::endl;
		return false;
	}
	else
	{
		// handle compressed message
		if ((msg->compressed_data).size() != 0)
		{
			bool decompress_ok = false;
			switch (msg->compalgo)
			{
				case TMCG_OPENPGP_COMPALGO_UNCOMPRESSED:
					for (size_t i = 0; i < (msg->compressed_data).size(); i++)
						infmsg.push_back(msg->compressed_data[i]);
					decompress_ok = true; // no compression
					break;
				case TMCG_OPENPGP_COMPALGO_ZIP:
				case TMCG_OPENPGP_COMPALGO_ZLIB:
					decompress_ok = decompress_libz(msg, infmsg);
					break;
#ifdef LIBBZ
				case TMCG_OPENPGP_COMPALGO_BZIP2:
					decompress_ok = decompress_libbz(msg, infmsg);
					break;
#endif
				default:
					if (opt_verbose > 1)
					{
						std::cerr << "WARNING: compression algorithm " <<
							(int)msg->compalgo << " is not supported" <<
							std::endl;
					}
			}
			if (!decompress_ok)
			{
				std::cerr << "ERROR: decompression failed" << std::endl;
				return false;
			}
			if (!CallasDonnerhackeFinneyShawThayerRFC4880::MessageParse(infmsg,
				opt_verbose, msg))
			{
				std::cerr << "ERROR: message parsing failed" << std::endl;
				return false;
			}
		}
		// handle decompressed message
		if ((msg->literal_data).size() == 0)
		{
			std::cerr << "ERROR: no literal data in decrypted message" <<
				std::endl;
			return false;
		}
		else
		{
			// verify included signatures based on keys from keyring
			if ((opt_k != NULL) && ((msg->signatures).size() > 0))
			{
				bool vf = true;
				for (size_t i = 0; i < (msg->signatures).size(); i++)
				{
					const TMCG_OpenPGP_Signature *sig = msg->signatures[i];
					std::string ak;
					if (get_key_by_signature(ring, sig, opt_verbose, ak))
					{
						if (!verify_signature(msg->literal_data, ak, sig,
							ring, opt_verbose, opt_weak))
						{
							vf = false;
							std::cerr << "WARNING: verification of" <<
							" signature #" << i << " failed" << std::endl;
						}	
					}
					else
					{
						std::cerr << "WARNING: cannot verify" <<
							" signature #" << i << " due to missing" <<
							" public key" << std::endl;
					}
				}
				if (!vf)
				{
					std::cerr << "ERROR: verification of included" <<
						" signature(s) failed" << std::endl;
					return false;
				}
			}
			// copy the content of literal data packet
			content.insert(content.end(), (msg->literal_data).begin(),
				(msg->literal_data).end());
		}
		if (msg->filename == "_CONSOLE")
			std::cerr << "INFO: sender requested \"for-your-eyes-only\"" <<
				std::endl;
	}
	return true;
}

void run_instance
	(size_t whoami, const size_t num_xtests)
{
	// read the key file
	std::string armored_seckey, pkfname;
	if (opt_y == NULL)
		pkfname = peers[whoami] + "_dkg-sec.asc";
	else
		pkfname = opt_y;
	if (opt_verbose > 1)
		std::cerr << "INFO: private key expected in file \"" << pkfname <<
			"\"" << std::endl;
	if (!check_strict_permissions(pkfname))
	{
		std::cerr << "WARNING: weak permissions of private key file" <<
			" detected" << std::endl;
		if (!set_strict_permissions(pkfname))
			exit(-1);
	}
	if (!read_key_file(pkfname, armored_seckey))
		exit(-1);

	// read the keyring
	std::string armored_pubring;
	if (opt_k)
	{
		if (!read_key_file(opt_k, armored_pubring))
			exit(-1);
	}

	// parse the keyring, the private key and corresponding signatures
	TMCG_OpenPGP_Prvkey *prv = NULL;
	TMCG_OpenPGP_Keyring *ring = NULL;
	bool parse_ok;
	if (opt_k)
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
	parse_ok = CallasDonnerhackeFinneyShawThayerRFC4880::
		PrivateKeyBlockParse(armored_seckey, opt_verbose, passphrase, prv);
	if (!parse_ok)
	{
#ifdef DKGPG_TESTSUITE
		passphrase = "Test";
#else
#ifdef DKGPG_TESTSUITE_Y
		passphrase = "TestY";
#else
		if (!get_passphrase("Enter passphrase to unlock private key", opt_E,
			passphrase))
		{
			std::cerr << "ERROR: cannot read passphrase" << std::endl;
			delete ring;
			exit(-1);
		}
#endif
#endif
		parse_ok = CallasDonnerhackeFinneyShawThayerRFC4880::
			PrivateKeyBlockParse(armored_seckey, opt_verbose, passphrase, prv);
	}
	if (parse_ok)
	{
		prv->RelinkPublicSubkeys(); // relink the contained subkeys
		prv->pub->CheckSelfSignatures(ring, opt_verbose);
		prv->pub->CheckSubkeys(ring, opt_verbose);
		prv->RelinkPrivateSubkeys(); // undo the relinking
	}
	else
	{
		std::cerr << "ERROR: cannot use the provided private key" << std::endl;
		delete ring;
		exit(-1);
	}
	if (!prv->pub->valid || ((opt_y == NULL) && prv->Weak(opt_verbose)))
	{
		std::cerr << "ERROR: primary key is invalid or weak" << std::endl;
		delete ring;
		delete prv;
		exit(-1);
	}

	// select admissible private subkey for decryption
	// TODO: currently always the last valid non-weak subkey is selected
	GennaroJareckiKrawczykRabinDKG *dkg = NULL;
	TMCG_OpenPGP_PrivateSubkey *ssb = NULL;
	if (opt_y == NULL)
	{
		for (size_t i = 0; i < prv->private_subkeys.size(); i++)
		{
			TMCG_OpenPGP_PrivateSubkey *ssb2 = prv->private_subkeys[i];
			if (ssb2->pkalgo == TMCG_OPENPGP_PKALGO_EXPERIMENTAL9)
			{
				if (ssb2->pub->valid && !ssb2->Weak(opt_verbose))
				{
					if ((ssb != NULL) && (opt_verbose > 1))
						std::cerr << "WARNING: more than one valid subkey" <<
							" found; last subkey selected" << std::endl;
					ssb = ssb2;
				}
				else
				{
					if (opt_verbose > 1)
						std::cerr << "WARNING: invalid or weak subkey at" <<
							" position " << i << " found and ignored" <<
							std::endl;
				}
			}
			else
			{
				if (opt_verbose > 1)
					std::cerr << "WARNING: non-tElG subkey at position " <<
						i << " found and ignored" << std::endl;
			}
		}
		if (ssb == NULL)
		{
			std::cerr << "ERROR: no admissible subkey found" << std::endl;
			delete ring;
			delete prv;
			exit(-1);
		}
		// create an instance of tElG by stored parameters from private key
		if (!init_tElG(ssb, opt_verbose, dkg))
		{
			delete dkg;
			delete ring;
			delete prv;
			exit(-1);
		}
	}
	else
	{
		if (prv->private_subkeys.size() == 0)
		{
			if (prv->pkalgo == TMCG_OPENPGP_PKALGO_RSA)
			{
				ssb = new TMCG_OpenPGP_PrivateSubkey(prv->pkalgo,
					prv->pub->creationtime, prv->pub->expirationtime,
					prv->pub->rsa_n, prv->pub->rsa_e, prv->rsa_p, prv->rsa_q,
					prv->rsa_u, prv->rsa_d, prv->packet);
				prv->private_subkeys.push_back(ssb);
			}
		}
		else
		{
			for (size_t i = 0; i < prv->private_subkeys.size(); i++)
			{
				TMCG_OpenPGP_PrivateSubkey *ssb2 = prv->private_subkeys[i];
				if (ssb2->pkalgo == TMCG_OPENPGP_PKALGO_EXPERIMENTAL9)
				{
					if (opt_verbose > 1)
						std::cerr << "WARNING: tElG subkey at position " <<
							i << " found and ignored" << std::endl;
					continue;
				}
				if (ssb2->pkalgo == TMCG_OPENPGP_PKALGO_EXPERIMENTAL7)
				{
					if (opt_verbose > 1)
						std::cerr << "WARNING: tDSS subkey at position " <<
							i << " found and ignored" << std::endl;
					continue;
				}
				if (ssb2->pub->AccumulateFlags() &&
					((ssb2->pub->AccumulateFlags() & 0x04) != 0x04) &&
					((ssb2->pub->AccumulateFlags() & 0x08) != 0x08))
				{
					if (opt_verbose > 1)
						std::cerr << "WARNING: non encryption-capable subkey" <<
							" at position " << i << " found and ignored" <<
							std::endl;
					continue;
				}
				if ((ssb2->pkalgo == TMCG_OPENPGP_PKALGO_RSA) ||
					(ssb2->pkalgo == TMCG_OPENPGP_PKALGO_RSA_ENCRYPT_ONLY) ||
					(ssb2->pkalgo == TMCG_OPENPGP_PKALGO_ELGAMAL) ||
					(ssb2->pkalgo == TMCG_OPENPGP_PKALGO_ECDH))
				{
					if (ssb2->pub->valid && !ssb2->Weak(opt_verbose))
					{
						if ((ssb != NULL) && (opt_verbose > 1))
							std::cerr << "WARNING: more than one valid" <<
								" subkey found; last subkey selected" <<
								std::endl;
						ssb = ssb2;
					}
					else
					{
						if (opt_verbose > 1)
							std::cerr << "WARNING: invalid or weak subkey at" <<
								" position " << i << " found and ignored" <<
								std::endl;
					}
				}
			}
		}
		if (ssb == NULL)
		{
			std::cerr << "ERROR: no admissible primary key resp." <<
				" subkey found" << std::endl;
			delete ring;
			delete prv;
			exit(-1);
		}
		// create a dummy instance of DKG
		std::stringstream dkg_in;
		dkg_in << "0" << std::endl << "0" << std::endl << "0" << std::endl
			<< "0" << std::endl; // p, q, g, h
		dkg_in << "1" << std::endl << "0" << std::endl << "0" << std::endl;
		dkg_in << "0" << std::endl << "0" << std::endl << "0" << std::endl;
		dkg_in << "1" << std::endl << "0" << std::endl; // |QUAL|, P_0
		dkg_in << "a" << std::endl << "b" << std::endl << "c" << std::endl;
		dkg_in << "d" << std::endl << "e" << std::endl << "f" << std::endl;
		dkg = new GennaroJareckiKrawczykRabinDKG(dkg_in);
	}

	// parse OpenPGP message and extract admissible PKESK
	TMCG_OpenPGP_Message *msg = NULL;
	if (!CallasDonnerhackeFinneyShawThayerRFC4880::
		MessageParse(armored_message, opt_verbose, msg))
	{
		delete dkg;
		delete ring;
		delete prv;
		exit(-1);
	}
	if (msg->encrypted_message.size() == 0)
	{
		std::cerr << "ERROR: no encrypted data found" << std::endl;
		delete msg;
		delete dkg;
		delete ring;
		delete prv;
		exit(-1);
	}
	std::vector<const TMCG_OpenPGP_PKESK*> esks;
	if (opt_y == NULL)
	{
		for (size_t i = 0; i < (msg->PKESKs).size(); i++)
		{
			if ((msg->PKESKs[i])->pkalgo == TMCG_OPENPGP_PKALGO_ELGAMAL)
			{
				if (CallasDonnerhackeFinneyShawThayerRFC4880::
					OctetsCompareZero((msg->PKESKs[i])->keyid))
				{
					std::cerr << "WARNING: PKESK wildcard keyid found; " <<
							"try to decrypt message anyway" << std::endl;
					esks.push_back(msg->PKESKs[i]);
				}
				else if (CallasDonnerhackeFinneyShawThayerRFC4880::
					OctetsCompare((msg->PKESKs[i])->keyid, ssb->pub->id))
				{
					if (opt_verbose > 1)
						std::cerr << "INFO: PKESK found with matching " <<
							"subkey ID" << std::endl;
					esks.clear();
					esks.push_back(msg->PKESKs[i]);
					break; // admissible PKESK found
				}
			}
		}
	}
	else
	{
		for (size_t i = 0; i < (msg->PKESKs).size(); i++)
		{
			if (CallasDonnerhackeFinneyShawThayerRFC4880::
				OctetsCompareZero((msg->PKESKs[i])->keyid))
			{
				std::cerr << "WARNING: PKESK wildcard keyid found; " <<
						"try to decrypt message anyway" << std::endl;
				esks.push_back(msg->PKESKs[i]);
			}
			else if (CallasDonnerhackeFinneyShawThayerRFC4880::
				OctetsCompare((msg->PKESKs[i])->keyid, ssb->pub->id))
			{
				if (opt_verbose > 1)
					std::cerr << "INFO: PKESK found with matching " <<
						"subkey ID" << std::endl;
				esks.clear();
				esks.push_back(msg->PKESKs[i]);
				break; // admissible PKESK found
			}
		}
	}
	if ((esks.size() == 0) && (msg->SKESKs.size() == 0))
	{
		std::cerr << "ERROR: no admissible encrypted session key found" <<
			std::endl;
		delete msg;
		delete dkg;
		delete ring;
		delete prv;
		exit(-1);
	}

	// decrypt session key from PKESK
	bool seskey_decrypted = false;
	tmcg_openpgp_secure_octets_t seskey;
	if (opt_y == NULL)
	{
		// create communication handles between all players
		std::vector<int> uP_in, uP_out, bP_in, bP_out;
		std::vector<std::string> uP_key, bP_key;
		for (size_t i = 0; i < peers.size(); i++)
		{
			std::stringstream key;
			if (opt_passwords != NULL)
			{
				std::string pwd;
				if (!TMCG_ParseHelper::gs(passwords, '/', pwd))
				{
					std::cerr << "ERROR: p_" << whoami << ": " <<
						"cannot read password for protecting channel to p_" <<
						i << std::endl;
					delete msg;
					delete dkg;
					delete ring;
					delete prv;
					exit(-1);
				}
				key << pwd;
				if (((i + 1) < peers.size()) &&
					!TMCG_ParseHelper::nx(passwords, '/'))
				{
					std::cerr << "ERROR: p_" << whoami << ": " <<
						"cannot skip to next password for protecting channel" <<
						" to p_" << (i + 1) << std::endl;
					delete msg;
					delete dkg;
					delete ring;
					delete prv;
					exit(-1);
				}
			}
			else
			{
				// simple key -- we assume that GNUnet provides secure channels
				key << "dkg-decrypt::p_" << (i + whoami);
			}
			uP_in.push_back(pipefd[i][whoami][0]);
			uP_out.push_back(pipefd[whoami][i][1]);
			uP_key.push_back(key.str());
			bP_in.push_back(broadcast_pipefd[i][whoami][0]);
			bP_out.push_back(broadcast_pipefd[whoami][i][1]);
			bP_key.push_back(key.str());
		}
		// create asynchronous authenticated unicast channels
		aiounicast_select *aiou = new aiounicast_select(peers.size(), whoami,
			uP_in, uP_out, uP_key, aiounicast::aio_scheduler_roundrobin,
			(opt_W * 60));
		// create asynchronous authenticated unicast channels for broadcast
		aiounicast_select *aiou2 = new aiounicast_select(peers.size(), whoami,
			bP_in, bP_out, bP_key, aiounicast::aio_scheduler_roundrobin,
			(opt_W * 60));
		// create an instance of a reliable broadcast protocol (RBC)
		std::string myID = "dkg-decrypt|" + std::string(protocol) + "|";
		for (size_t i = 0; i < peers.size(); i++)
			myID += peers[i] + "|";
		// include parameterized t-resiliance of DKG in the ID of RBC protocol
		std::stringstream myss;
		myss << dkg->t << "|";
		myID += myss.str();
		if (opt_verbose)
			std::cerr << "RBC: myID = " << myID << std::endl;
		// assume maximum asynchronous t-resilience for RBC
		size_t T_RBC = (peers.size() - 1) / 3;
		CachinKursawePetzoldShoupRBC *rbc =
			new CachinKursawePetzoldShoupRBC(peers.size(), T_RBC, whoami, aiou2,
				aiounicast::aio_scheduler_roundrobin, (opt_W * 60));
		rbc->setID(myID);
		// perform a simple exchange test with debug output
		xtest(num_xtests, whoami, peers.size(), rbc);
		// initialize for interactive part
		mpz_t crs_p, crs_q, crs_g, crs_k;
		mpz_init(crs_p), mpz_init(crs_q), mpz_init(crs_g), mpz_init(crs_k);
		if (!tmcg_mpz_set_gcry_mpi(ssb->pub->elg_p, crs_p))
		{
			std::cerr << "ERROR: converting group parameters failed" <<
				std::endl;
			mpz_clear(crs_p), mpz_clear(crs_q), mpz_clear(crs_g);
			mpz_clear(crs_k);
			delete aiou, delete aiou2, delete rbc;
			delete msg;
			delete dkg;
			delete ring;
			delete prv;
			exit(-1);
		}
		if (!tmcg_mpz_set_gcry_mpi(ssb->telg_q, crs_q))
		{
			std::cerr << "ERROR: converting group parameters failed" <<
				std::endl;
			mpz_clear(crs_p), mpz_clear(crs_q), mpz_clear(crs_g);
			mpz_clear(crs_k);
			delete aiou, delete aiou2, delete rbc;
			delete msg;
			delete dkg;
			delete ring;
			delete prv;
			exit(-1);
		}
		if (!tmcg_mpz_set_gcry_mpi(ssb->pub->elg_g, crs_g))
		{
			std::cerr << "ERROR: converting group parameters failed" <<
				std::endl;
			mpz_clear(crs_p), mpz_clear(crs_q), mpz_clear(crs_g);
			mpz_clear(crs_k);
			delete aiou, delete aiou2, delete rbc;
			delete msg;
			delete dkg;
			delete ring;
			delete prv;
			exit(-1);
		}
		mpz_sub_ui(crs_k, crs_p, 1L);
		if (!mpz_cmp_ui(crs_q, 0L))
		{
			std::cerr << "ERROR: group parameter q must not be zero" <<
				std::endl;
			mpz_clear(crs_p), mpz_clear(crs_q), mpz_clear(crs_g);
			mpz_clear(crs_k);
			delete aiou, delete aiou2, delete rbc;
			delete msg;
			delete dkg;
			delete ring;
			delete prv;
			exit(-1);
		}
		mpz_div(crs_k, crs_k, crs_q);
		// create VTMF instance from original CRS (common reference string)
		std::stringstream crss;
		crss << crs_p << std::endl << crs_q << std::endl << crs_g <<
			std::endl << crs_k << std::endl;
		// without verifiable generation of $g$ due to possible FIPS-CRS
		BarnettSmartVTMF_dlog *vtmf = new BarnettSmartVTMF_dlog(crss,
			TMCG_DDH_SIZE, TMCG_DLSE_SIZE, false);
		if (!vtmf->CheckGroup())
		{
			std::cerr << "ERROR: p_" << whoami << ": " << "VTMF: Group G was" <<
				" not correctly generated!" << std::endl;
			delete vtmf;
			mpz_clear(crs_p), mpz_clear(crs_q), mpz_clear(crs_g);
			mpz_clear(crs_k);
			delete aiou, delete aiou2, delete rbc;
			delete msg;
			delete dkg;
			delete ring;
			delete prv;
			exit(-1);
		}
		// create/exchange keys to bootstrap the $h$-generation for EDCF [JL00]
		if (opt_verbose)
		{
			std::cerr << "INFO: generate h for EDCF by using VTMF key" <<
				" generation protocol" << std::endl;
		}
		mpz_t nizk_c, nizk_r, h_j;
		mpz_init(nizk_c), mpz_init(nizk_r), mpz_init(h_j);
		vtmf->KeyGenerationProtocol_GenerateKey();
		vtmf->KeyGenerationProtocol_ComputeNIZK(nizk_c, nizk_r);
		rbc->Broadcast(vtmf->h_i);
		rbc->Broadcast(nizk_c);
		rbc->Broadcast(nizk_r);
		for (size_t i = 0; i < peers.size(); i++)
		{
			if (i != whoami)
			{
				if (!rbc->DeliverFrom(h_j, i))
				{
					std::cerr << "WARNING: p_" << whoami << ": no VTMF key" <<
						" received from p_" << i << std::endl;
				}
				if (!rbc->DeliverFrom(nizk_c, i))
				{
					std::cerr << "WARNING: p_" << whoami << ": no NIZK c" <<
						" received from p_" << i << std::endl;
				}
				if (!rbc->DeliverFrom(nizk_r, i))
				{
					std::cerr << "WARNING: p_" << whoami << ": no NIZK r" <<
						" received from p_" << i << std::endl;
				}
				std::stringstream lej;
				lej << h_j << std::endl << nizk_c << std::endl << nizk_r <<
					std::endl;
				if (!vtmf->KeyGenerationProtocol_UpdateKey(lej))
				{
					std::cerr << "WARNING: p_" << whoami << ": VTMF public" <<
						" key of p_" << i << " was not correctly generated!" <<
						std::endl;
				}
			}
		}
		vtmf->KeyGenerationProtocol_Finalize();
		mpz_clear(nizk_c), mpz_clear(nizk_r), mpz_clear(h_j);
		// create an instance of the distributed coin-flip protocol (EDCF)
		// assume maximum synchronous t-resilience for EDCF
		size_t T_EDCF = (peers.size() - 1) / 2;
		if (opt_verbose)
			std::cerr << "INFO: JareckiLysyanskayaEDCF(" << peers.size() <<
				", " << T_EDCF << ", ...)" << std::endl;
		JareckiLysyanskayaEDCF *edcf = new JareckiLysyanskayaEDCF(peers.size(),
			T_EDCF, vtmf->p, vtmf->q, vtmf->g, vtmf->h);
		for (size_t j = 0; j < esks.size(); j++)
		{
			if (!check_esk(esks[j], ssb))
			{
				if (opt_verbose)
					std::cerr << "WARNING: bad PKESK detected and ignored" <<
						std::endl;
				continue; // try next PKESK
			}
			// initialize shares
			mpz_t idx, r_i, c, r;
			mpz_init(idx), mpz_init(r_i), mpz_init(c), mpz_init(r);
			std::vector<size_t> interpol_parties;
			std::vector<mpz_ptr> interpol_shares;
			// compute own decryption share and store it
			std::string dds;
			size_t idx_tmp;
			compute_decryption_share(esks[j]->gk, dkg, dds);
			if (verify_decryption_share(esks[j]->gk, dkg, dds, idx_tmp, r_i,
				c, r))
			{
				assert((idx_tmp == dkg->i));
				// use this share as first point for Lagrange interpolation
				mpz_ptr tmp1 = new mpz_t();
				mpz_init_set(tmp1, r_i);
				interpol_parties.push_back(dkg->i);
				interpol_shares.push_back(tmp1);
			}
			else
			{
				std::cerr << "WARNING: verification of own decryption share" <<
					" failed for p_" << whoami << std::endl;
			}
			// collect other decryption shares
			if (opt_verbose)
				std::cerr << "INFO: start collecting other decryption shares" <<
					std::endl;
			std::vector<size_t> complaints;
			for (size_t i = 0; i < peers.size(); i++)
			{
				if (i != whoami)
				{
					mpz_set_ui(idx, dkg->n), mpz_set_ui(r_i, 1L);
					// receive index
					if (!rbc->DeliverFrom(idx, i))
					{
						std::cerr << "WARNING: DeliverFrom(idx, i) failed" <<
							" for p_" << i << std::endl;
						complaints.push_back(i);
					}
					// receive a decryption share
					if (!rbc->DeliverFrom(r_i, i))
					{
						std::cerr << "WARNING: DeliverFrom(r_i, i) failed" <<
							" for p_" << i << std::endl;
						complaints.push_back(i);
					}
					// verify decryption share interactively
					std::stringstream err_log;
					size_t idx_dkg = mpz_get_ui(idx);
					if (!verify_decryption_share_interactive_publiccoin(
						esks[j]->gk, dkg, i, idx_dkg, r_i, aiou, rbc, edcf,
						err_log))
					{
						std::cerr << "WARNING: bad decryption share of P_" <<
							idx_dkg << " received from p_" << i << std::endl;
						if (opt_verbose)
							std::cerr << err_log.str() << std::endl;
						complaints.push_back(i);
					}
					if (std::find(complaints.begin(), complaints.end(), i) ==
						complaints.end())
					{
						if (opt_verbose)
							std::cerr << "INFO: p_" << whoami << ": good" <<
								" decryption share of P_" << idx_dkg <<
								" received from p_" << i << std::endl;
						if (opt_verbose > 1)
							std::cerr << err_log.str() << std::endl;
						// collect only verified decryption shares
						mpz_ptr tmp1 = new mpz_t();
						mpz_init_set(tmp1, r_i);
						interpol_parties.push_back(idx_dkg);
						interpol_shares.push_back(tmp1);
					}
				}
				else
				{
					if (verify_decryption_share(esks[j]->gk, dkg, dds, idx_tmp,
						r_i, c, r))
					{
						mpz_set_ui(idx, idx_tmp);
					}
					else
						mpz_set_ui(idx, dkg->n); // indicates an error
					// broadcast own index and decryption share
					rbc->Broadcast(idx);
					rbc->Broadcast(r_i);
					// prove own decryption share interactively
					std::stringstream err_log;
					prove_decryption_share_interactive_publiccoin(esks[j]->gk,
						dkg, r_i, aiou, rbc, edcf, err_log);
					if (opt_verbose)
						std::cerr << "INFO: prove_decryption_share_" <<
							"interactive_publiccoin() finished" << std::endl;
					if (opt_verbose > 1)
						std::cerr << "INFO: p_" << whoami << ": log follows" <<
							std::endl << err_log.str();
				}
			}
			// Lagrange interpolation
			bool res = combine_decryption_shares(esks[j]->gk, dkg,
				interpol_parties, interpol_shares);
			// release shares
			mpz_clear(idx), mpz_clear(r_i), mpz_clear(c), mpz_clear(r);
			mpz_clear(crs_p), mpz_clear(crs_q), mpz_clear(crs_g);
			mpz_clear(crs_k);
			for (size_t i = 0; i < interpol_shares.size(); i++)
			{
				mpz_clear(interpol_shares[i]);
				delete [] interpol_shares[i];
			}
			interpol_shares.clear(), interpol_parties.clear();
			if (!res)
			{
				if (opt_verbose)
					std::cerr << "WARNING: recombination of shares failed;" <<
						" PKESK ignored" << std::endl;
				continue; // try next PKESK
			}
			// decrypt the session key
			if (!decrypt_session_key(ssb->pub->elg_p, ssb->pub->elg_g,
				ssb->pub->elg_y, esks[j]->gk, esks[j]->myk, seskey))
			{
				continue; // try next PKESK
			}
			else
			{
				if (opt_verbose > 1)
					std::cerr << "INFO: PKESK decryption succeeded" <<
						std::endl;				
				seskey_decrypted = true;
				break;
			}
		}			
		// at the end: deliver some more rounds for waiting parties
		time_t synctime = (opt_W * 6);
		if (opt_verbose)
			std::cerr << "INFO: p_" << whoami << ": waiting approximately " <<
				(synctime * (T_RBC + 1)) << " seconds for stalled parties" <<
				std::endl;
		rbc->Sync(synctime);
		// release EDCF
		delete edcf;
		// release VTMF
		delete vtmf;
		// release RBC
		delete rbc;
		// release handles (unicast channel)
		uP_in.clear(), uP_out.clear(), uP_key.clear();
		if (opt_verbose)
		{
			std::cerr << "INFO: p_" << whoami << ": unicast channels";
			aiou->PrintStatistics(std::cerr);
			std::cerr << std::endl;
		}
		// release handles (broadcast channel)
		bP_in.clear(), bP_out.clear(), bP_key.clear();
		if (opt_verbose)
		{
			std::cerr << "INFO: p_" << whoami << ": broadcast channel";
			aiou2->PrintStatistics(std::cerr);
			std::cerr << std::endl;
		}
		// release asynchronous unicast and broadcast
		delete aiou, delete aiou2;
	}
	else
	{
		for (size_t j = 0; j < esks.size(); j++)
		{
			// try to decrypt the session key from this PKESK packet
			if (!ssb->Decrypt(esks[j], opt_verbose, seskey))
			{
				if (opt_verbose)
					std::cerr << "WARNING: PKESK decryption failed;" <<
						" PKESK ignored" << std::endl;
				continue; // try next PKESK
			}
			else
			{
				if (opt_verbose > 1)
					std::cerr << "INFO: PKESK decryption succeeded" <<
						std::endl;				
				seskey_decrypted = true;
				break;
			}
		}
	}

	// do remaining decryption work
	if (!seskey_decrypted)
	{
		if (msg->SKESKs.size() > 0)
		{
			if (opt_verbose > 1)
				std::cerr << "INFO: every PKESK decryption failed;" <<
					" now try each SKESK" << std::endl;
			tmcg_openpgp_secure_string_t esk_passphrase;
			if (!get_passphrase("Enter passphrase for this message", opt_E,
				esk_passphrase))
			{
				std::cerr << "ERROR: cannot read passphrase" << std::endl;
				delete msg;
				delete dkg;
				delete ring;
				delete prv;
				exit(-1);
			}
			for (size_t i = 0; i < msg->SKESKs.size(); i++)
			{
				const TMCG_OpenPGP_SKESK *esk = msg->SKESKs[i];
				tmcg_openpgp_secure_octets_t esk_seskey;
				switch (esk->s2k_type)
				{
					case TMCG_OPENPGP_STRINGTOKEY_SIMPLE:
					case TMCG_OPENPGP_STRINGTOKEY_SALTED:
						CallasDonnerhackeFinneyShawThayerRFC4880::S2KCompute(
								esk->s2k_hashalgo,
								CallasDonnerhackeFinneyShawThayerRFC4880::
									AlgorithmKeyLength(esk->skalgo),
								esk_passphrase, esk->s2k_salt, false,
								esk->s2k_count, esk_seskey);
						break;
					case TMCG_OPENPGP_STRINGTOKEY_ITERATED:
						CallasDonnerhackeFinneyShawThayerRFC4880::S2KCompute(
								esk->s2k_hashalgo,
								CallasDonnerhackeFinneyShawThayerRFC4880::
									AlgorithmKeyLength(esk->skalgo),
								esk_passphrase, esk->s2k_salt, true,
								esk->s2k_count, esk_seskey);
						break;
					default:
						if (opt_verbose)
							std::cerr << "WARNING: S2K specifier not" <<
								" supported; skip SKESK" << std::endl;
						break;
				}
				seskey.clear();
				if (esk->encrypted_key.size() != 0)
				{
					tmcg_openpgp_octets_t decrypted_key, prefix;
					gcry_error_t ret = 0;
					if (esk->aeadalgo == 0)
					{
						ret = CallasDonnerhackeFinneyShawThayerRFC4880::
							SymmetricDecrypt(esk->encrypted_key, esk_seskey,
								prefix, false, esk->skalgo, decrypted_key);
					}
					else
					{
						tmcg_openpgp_octets_t ad; // additional data
						ad.push_back(0xC3); // packet tag in new format
						ad.push_back(esk->version); // packet version number
						ad.push_back(esk->skalgo); // cipher algorithm octet
						ad.push_back(esk->aeadalgo); // AEAD algorithm octet
						ret = CallasDonnerhackeFinneyShawThayerRFC4880::
							SymmetricDecryptAEAD(esk->encrypted_key, esk_seskey,
								esk->skalgo, esk->aeadalgo, 0, esk->iv, ad,
								opt_verbose, decrypted_key);
					}
					if (ret)
					{
						std::cerr << "ERROR: SymmetricDecrypt[AEAD]() failed" <<
							" with rc = " << gcry_err_code(ret) <<
							" str = " << gcry_strerror(ret) << std::endl;
						delete msg;
						delete dkg;
						delete ring;
						delete prv;
						exit(-1);
					}
					for (size_t j = 0; j < decrypted_key.size(); j++)
						seskey.push_back(decrypted_key[j]);
				}
				else
				{
					seskey.push_back(esk->skalgo);
					for (size_t j = 0; j < esk_seskey.size(); j++)
						seskey.push_back(esk_seskey[j]);
				}
				// quick check, whether decryption of session key was successful
				tmcg_openpgp_octets_t tmpmsg;				
				if (msg->Decrypt(seskey, 0, tmpmsg))
				{
					seskey_decrypted = true;
					break;
				}
			}
			if (!seskey_decrypted)
			{
				std::cerr << "ERROR: every SKESK decryption failed" <<
					std::endl;
				delete msg;
				delete dkg;
				delete ring;
				delete prv;
				exit(-1);
			}
		}
		else
		{
			std::cerr << "ERROR: every PKESK decryption failed" << std::endl;
			delete msg;
			delete dkg;
			delete ring;
			delete prv;
			exit(-1);
		}
	}
	tmcg_openpgp_octets_t content;
	if (!decrypt_message(seskey, ring, msg, content))
	{
		delete msg;
		delete dkg;
		delete ring;
		delete prv;
		exit(-1);
	}

	// release
	delete msg;
	delete dkg;
	delete ring;
	delete prv;

	// output result
	if (opt_ofilename != NULL)
	{
		if (!write_message(opt_ofilename, content))
			exit(-1);
	}
	else
		print_message(content);

#ifdef DKGPG_TESTSUITE
	std::string test_msg = "This is just a simple test message.";
	tmcg_openpgp_octets_t tmsg;
	for (size_t i = 0; i < test_msg.length(); i++)
		tmsg.push_back(test_msg[i]);
	if (!CallasDonnerhackeFinneyShawThayerRFC4880::OctetsCompare(content, tmsg))
		exit(-2);
#else
#ifdef DKGPG_TESTSUITE_Y
	std::string test_msg = "This is just another simple test message.";
	tmcg_openpgp_octets_t tmsg;
	for (size_t i = 0; i < test_msg.length(); i++)
		tmsg.push_back(test_msg[i]);
	if (!CallasDonnerhackeFinneyShawThayerRFC4880::OctetsCompare(content, tmsg))
		exit(-2);
#endif
#endif
}

#ifdef GNUNET
char *gnunet_opt_hostname = NULL;
char *gnunet_opt_ifilename = NULL;
char *gnunet_opt_ofilename = NULL;
char *gnunet_opt_passwords = NULL;
char *gnunet_opt_port = NULL;
char *gnunet_opt_k = NULL;
char *gnunet_opt_y = NULL;
unsigned int gnunet_opt_xtests = 0;
unsigned int gnunet_opt_wait = 5;
unsigned int gnunet_opt_W = opt_W;
int gnunet_opt_nonint = 0;
int gnunet_opt_verbose = 0;
int gnunet_opt_weak = 0;
int gnunet_opt_binary = 0;
int gnunet_opt_E = 0;
#endif

void fork_instance
	(const size_t whoami)
{
	if ((pid[whoami] = fork()) < 0)
		perror("ERROR: dkg-decrypt (fork)");
	else
	{
		if (pid[whoami] == 0)
		{
			/* BEGIN child code: participant p_i */
#ifdef GNUNET
			run_instance(whoami, gnunet_opt_xtests);
#else
			run_instance(whoami, 0);
#endif
			if (opt_verbose)
				std::cerr << "INFO: p_" << whoami << ": exit(0)" << std::endl;
			exit(0);
			/* END child code: participant p_i */
		}
		else
		{
			if (opt_verbose)
				std::cerr << "INFO: fork() = " << pid[whoami] << std::endl;
			instance_forked = true;
		}
	}
}

int main
	(int argc, char *const *argv)
{
	static const char *usage = "dkg-decrypt [OPTIONS] PEERS";
#ifdef GNUNET
	char *loglev = NULL;
	char *logfile = NULL;
	char *cfg_fn = NULL;
	static const struct GNUNET_GETOPT_CommandLineOption options[] = {
		GNUNET_GETOPT_option_flag('b',
			"binary",
			"consider encrypted message from FILENAME as binary input",
			&gnunet_opt_binary
		),
		GNUNET_GETOPT_option_cfgfile(&cfg_fn),
		GNUNET_GETOPT_option_flag('E',
			"echo",
			"enable terminal echo when reading passphrase",
			&gnunet_opt_E
		),
		GNUNET_GETOPT_option_help(about),
		GNUNET_GETOPT_option_string('H',
			"hostname",
			"STRING",
			"hostname (e.g. onion address) of this peer within PEERS",
			&gnunet_opt_hostname
		),
		GNUNET_GETOPT_option_string('i',
			"input",
			"FILENAME",
			"read encrypted message from FILENAME",
			&gnunet_opt_ifilename
		),
		GNUNET_GETOPT_option_string('k',
			"keyring",
			"FILENAME",
			"verify included signatures using keyring FILENAME",
			&gnunet_opt_k
		),
		GNUNET_GETOPT_option_flag('K',
			"weak",
			"allow weak keys to verify included signatures",
			&gnunet_opt_weak
		),
		GNUNET_GETOPT_option_logfile(&logfile),
		GNUNET_GETOPT_option_loglevel(&loglev),
		GNUNET_GETOPT_option_flag('n',
			"non-interactive",
			"run in non-interactive mode",
			&gnunet_opt_nonint
		),
		GNUNET_GETOPT_option_string('o',
			"output",
			"FILENAME",
			"write decrypted message to FILENAME",
			&gnunet_opt_ofilename
		),
		GNUNET_GETOPT_option_string('p',
			"port",
			"STRING",
			"GNUnet CADET port to listen/connect",
			&gnunet_opt_port
		),
		GNUNET_GETOPT_option_string('P',
			"passwords",
			"STRING",
			"exchanged passwords to protect private and broadcast channels",
			&gnunet_opt_passwords
		),
		GNUNET_GETOPT_option_version(version),
		GNUNET_GETOPT_option_flag('V',
			"verbose",
			"turn on verbose output",
			&gnunet_opt_verbose
		),
		GNUNET_GETOPT_option_uint('w',
			"wait",
			"INTEGER",
			"minutes to wait until start of decryption",
			&gnunet_opt_wait
		),
		GNUNET_GETOPT_option_uint('W',
			"aiou-timeout",
			"INTEGER",
			"timeout for point-to-point messages in minutes",
			&gnunet_opt_W
		),
		GNUNET_GETOPT_option_string('y',
			"yaot",
			"FILNAME",
			"yet another OpenPGP tool with private key in FILENAME",
			&gnunet_opt_y
		),
		GNUNET_GETOPT_option_uint('x',
			"x-tests",
			NULL,
			"number of exchange tests",
			&gnunet_opt_xtests
		),
		GNUNET_GETOPT_OPTION_END
	};
//	if (GNUNET_STRINGS_get_utf8_args(argc, argv, &argc, &argv) != GNUNET_OK)
//	{
//		std::cerr << "ERROR: GNUNET_STRINGS_get_utf8_args() failed" <<
//			std::endl;
//		return -1;
//	}
	if (GNUNET_GETOPT_run(usage, options, argc, argv) == GNUNET_SYSERR)
	{
		std::cerr << "ERROR: GNUNET_GETOPT_run() failed" << std::endl;
		return -1;
	}
	if (gnunet_opt_ifilename != NULL)
		opt_ifilename = gnunet_opt_ifilename;
	if (gnunet_opt_ofilename != NULL)
		opt_ofilename = gnunet_opt_ofilename;
	if (gnunet_opt_hostname != NULL)
		opt_hostname = gnunet_opt_hostname;
	if (gnunet_opt_passwords != NULL)
		opt_passwords = gnunet_opt_passwords;
	if (gnunet_opt_passwords != NULL)
		passwords = gnunet_opt_passwords; // get passwords from GNUnet options
	if (gnunet_opt_hostname != NULL)
		hostname = gnunet_opt_hostname; // get hostname from GNUnet options
	if (gnunet_opt_k != NULL)
		opt_k = gnunet_opt_k;
	if (gnunet_opt_W != opt_W)
		opt_W = gnunet_opt_W; // get aiou message timeout from GNUnet options
	if (gnunet_opt_y != NULL)
		opt_y = gnunet_opt_y;
#endif

	bool nonint = false;
	// create peer list from remaining arguments
	for (size_t i = 0; i < (size_t)(argc - 1); i++)
	{
		std::string arg = argv[i+1];
		// ignore options
		if ((arg.find("-c") == 0) || (arg.find("-p") == 0) ||
			(arg.find("-w") == 0) || (arg.find("-L") == 0) ||
			(arg.find("-l") == 0) || (arg.find("-i") == 0) ||
			(arg.find("-o") == 0) || (arg.find("-x") == 0) ||
			(arg.find("-P") == 0) || (arg.find("-H") == 0) ||
			(arg.find("-W") == 0) || (arg.find("-k") == 0) ||
			(arg.find("-y") == 0))
		{
			size_t idx = ++i;
			if ((arg.find("-i") == 0) && (idx < (size_t)(argc - 1)) &&
				(opt_ifilename == NULL))
			{
				ifilename = argv[i+1];
				opt_ifilename = (char*)ifilename.c_str();
			}
			if ((arg.find("-o") == 0) && (idx < (size_t)(argc - 1)) &&
				(opt_ofilename == NULL))
			{
				ofilename = argv[i+1];
				opt_ofilename = (char*)ofilename.c_str();
			}
			if ((arg.find("-k") == 0) && (idx < (size_t)(argc - 1)) &&
				(opt_k == NULL))
			{
				kfilename = argv[i+1];
				opt_k = (char*)kfilename.c_str();
			}
			if ((arg.find("-H") == 0) && (idx < (size_t)(argc - 1)) &&
				(opt_hostname == NULL))
			{
				hostname = argv[i+1];
				opt_hostname = (char*)hostname.c_str();
			}
			if ((arg.find("-P") == 0) && (idx < (size_t)(argc - 1)) &&
				(opt_passwords == NULL))
			{
				passwords = argv[i+1];
				opt_passwords = (char*)passwords.c_str();
			}
			if ((arg.find("-p") == 0) && (idx < (size_t)(argc - 1)) &&
				(port.length() == 0))
			{
				port = argv[i+1];
			}
			if ((arg.find("-W") == 0) && (idx < (size_t)(argc - 1)) &&
				(opt_W == 5))
			{
				opt_W = strtoul(argv[i+1], NULL, 10);
			}
			if ((arg.find("-y") == 0) && (idx < (size_t)(argc - 1)) &&
				(opt_y == NULL))
			{
				yfilename = argv[i+1];
				opt_y = (char*)yfilename.c_str();
			}
			continue;
		}
		else if ((arg.find("--") == 0) || (arg.find("-b") == 0) ||
			(arg.find("-v") == 0) || (arg.find("-h") == 0) ||
			(arg.find("-n") == 0) || (arg.find("-V") == 0) ||
			(arg.find("-E") == 0) || (arg.find("-K") == 0))
		{
			if ((arg.find("-h") == 0) || (arg.find("--help") == 0))
			{
#ifndef GNUNET
				std::cout << usage << std::endl;
				std::cout << about << std::endl;
				std::cout << "Arguments mandatory for long options are also" <<
					" mandatory for short options." << std::endl;
				std::cout << "  -b, --binary           consider encrypted" <<
					" message from FILENAME as binary input" << std::endl;
				std::cout << "  -E, --echo             enable terminal echo" <<
					" when reading passphrase" << std::endl;
				std::cout << "  -h, --help             print this help" <<
					std::endl;
				std::cout << "  -H STRING              hostname (e.g. onion" <<
					" address) of this peer within PEERS" << std::endl;
				std::cout << "  -i FILENAME            read encrypted" <<
					" message rather from FILENAME than STDIN" << std::endl;
				std::cout << "  -k FILENAME            verify included" <<
					" signatures using keyring FILENAME" << std::endl;
				std::cout << "  -K, --weak             allow weak keys to" <<
					" verify included signatures" << std::endl;
				std::cout << "  -n, --non-interactive  run in" <<
					" non-interactive mode" << std::endl;
				std::cout << "  -o FILENAME            write decrypted" <<
					" message rather to FILENAME than STDOUT" << std::endl;
				std::cout << "  -p INTEGER             start port for" <<
					" built-in TCP/IP message exchange service" << std::endl;
				std::cout << "  -P STRING              exchanged passwords" <<
					" to protect private and broadcast channels" << std::endl;
				std::cout << "  -v, --version          print the version" <<
					" number" << std::endl;
				std::cout << "  -V, --verbose          turn on verbose" <<
					" output" << std::endl;
				std::cout << "  -W INTEGER             timeout for" <<
					" point-to-point messages in minutes" << std::endl;
				std::cout << "  -y FILENAME            yet another OpenPGP" <<
					" tool with private key in FILENAME" << std::endl;
#endif
				return 0; // not continue
			}
			if ((arg.find("-b") == 0) || (arg.find("--binary") == 0))
				opt_binary = true;
			if ((arg.find("-E") == 0) || (arg.find("--echo") == 0))
				opt_E = true;
			if ((arg.find("-K") == 0) || (arg.find("--weak") == 0))
				opt_weak = true;
			if ((arg.find("-v") == 0) || (arg.find("--version") == 0))
			{
#ifndef GNUNET
				std::cout << "dkg-decrypt v" << version <<
					" without GNUNET support" << std::endl;
#endif
				return 0; // not continue
			}
			if ((arg.find("-n") == 0) || (arg.find("--non-interactive") == 0))
				nonint = true; // non-interactive mode
			if ((arg.find("-V") == 0) || (arg.find("--verbose") == 0))
				opt_verbose++; // increade verbosity
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
			std::cerr << "ERROR: peer identity \"" << arg << "\" too long" <<
				std::endl;
			return -1;
		}
	}
#ifdef DKGPG_TESTSUITE
	peers.push_back("Test2");
	peers.push_back("Test3");
	peers.push_back("Test4");
	ifilename = "Test1_output.bin";
	opt_ifilename = (char*)ifilename.c_str();
	opt_verbose = 2;
	opt_binary = true;
#else
#ifdef DKGPG_TESTSUITE_Y
	yfilename = "TestY-sec.asc";
	opt_y = (char*)yfilename.c_str();
	ifilename = "TestY_output.asc";
	opt_ifilename = (char*)ifilename.c_str();
	opt_verbose = 2;
#endif
#endif

	// check command line arguments
	if ((opt_hostname != NULL) && (opt_passwords == NULL) && (opt_y == NULL))
	{
		std::cerr << "ERROR: option \"-P\" is necessary due to insecure" <<
			" network" << std::endl;
		return -1;
	}
	if ((peers.size() < 1) && (opt_y == NULL))
	{
		std::cerr << "ERROR: no peers given as argument; usage: " << usage <<
			std::endl;
		return -1;
	}
	canonicalize(peers);
	if (!nonint && (opt_y == NULL) && ((peers.size() < 3)  ||
		(peers.size() > DKGPG_MAX_N)))
	{
		std::cerr << "ERROR: too few or too many peers given" << std::endl;
		return -1;
	}
	else if (nonint && (peers.size() != 1))
	{
		std::cerr << "ERROR: too few or too many peers given" << std::endl;
		return -1;
	}
	if ((opt_verbose) && (opt_y == NULL))
	{
		std::cerr << "INFO: canonicalized peer list = " << std::endl;
		for (size_t i = 0; i < peers.size(); i++)
			std::cerr << peers[i] << std::endl;
	}

	// lock memory
	bool force_secmem = false;
	if (!lock_memory())
	{
		std::cerr << "WARNING: locking memory failed; CAP_IPC_LOCK required" <<
			" for full memory protection" << std::endl;
		// at least try to use libgcrypt's secure memory
		force_secmem = true;
	}

	// initialize LibTMCG
	if (!init_libTMCG(force_secmem))
	{
		std::cerr << "ERROR: initialization of LibTMCG failed" << std::endl;
		return -1;
	}
	if (opt_verbose)
		std::cerr << "INFO: using LibTMCG version " << version_libTMCG() <<
			std::endl;

	// read message
	if (opt_ifilename != NULL)
	{
		if (opt_binary)
		{
			if (!read_binary_message(opt_ifilename, armored_message))
				return -1;
		}
		else
		{
			if (!read_message(opt_ifilename, armored_message))
				return -1;
		}
	}
	else
	{
		std::cerr << "Please enter the encrypted message (in ASCII Armor;" <<
			" ^D for EOF): " << std::endl;
		std::string line;
		while (std::getline(std::cin, line))
			armored_message += line + "\r\n";
		std::cin.clear();
	}

	// start non-interactive variant
	if (nonint)
	{
		// read the key file
		std::string armored_seckey, thispeer = peers[0];
		if (!check_strict_permissions(thispeer + "_dkg-sec.asc"))
		{
			std::cerr << "WARNING: weak permissions of private key file" <<
				" detected" << std::endl;
			if (!set_strict_permissions(thispeer + "_dkg-sec.asc"))
				return -1;
		}
		if (!read_key_file(thispeer + "_dkg-sec.asc", armored_seckey))
			return -1;
		// read the keyring
		std::string armored_pubring;
		if (opt_k)
		{
			if (!read_key_file(opt_k, armored_pubring))
				return -1;
		}
		// parse the keyring, the private key and corresponding signatures
		TMCG_OpenPGP_Prvkey *prv = NULL;
		TMCG_OpenPGP_Keyring *ring = NULL;
		bool parse_ok;
		if (opt_k)
		{
			parse_ok = CallasDonnerhackeFinneyShawThayerRFC4880::
				PublicKeyringParse(armored_pubring, opt_verbose, ring);
			if (!parse_ok)
			{
				std::cerr << "WARNING: cannot use the given keyring" <<
					std::endl;
				ring = new TMCG_OpenPGP_Keyring(); // create an empty keyring
			}
		}
		else
			ring = new TMCG_OpenPGP_Keyring(); // create an empty keyring
		parse_ok = CallasDonnerhackeFinneyShawThayerRFC4880::
			PrivateKeyBlockParse(armored_seckey, opt_verbose, passphrase, prv);
		if (!parse_ok)
		{
			if (!get_passphrase("Enter passphrase to unlock private key", opt_E,
				passphrase))
			{
				std::cerr << "ERROR: cannot read passphrase" << std::endl;
				delete ring;
				return -1;
			}
			parse_ok = CallasDonnerhackeFinneyShawThayerRFC4880::
				PrivateKeyBlockParse(armored_seckey, opt_verbose, passphrase,
				prv);
		}
		if (parse_ok)
		{
			prv->RelinkPublicSubkeys(); // relink the contained subkeys
			prv->pub->CheckSelfSignatures(ring, opt_verbose);
			prv->pub->CheckSubkeys(ring, opt_verbose);
			prv->RelinkPrivateSubkeys(); // undo the relinking
		}
		else
		{
			std::cerr << "ERROR: cannot use the provided private key" <<
				std::endl;
			delete ring;
			return -1;
		}
		if (!prv->pub->valid || prv->Weak(opt_verbose))
		{
			std::cerr << "ERROR: primary key is invalid or weak" << std::endl;
			delete ring;
			delete prv;
			return -1;
		}
		GennaroJareckiKrawczykRabinDKG *dkg = NULL;
		TMCG_OpenPGP_PrivateSubkey *ssb = NULL;
		for (size_t i = 0; i < prv->private_subkeys.size(); i++)
		{
			TMCG_OpenPGP_PrivateSubkey *ssb2 = prv->private_subkeys[i];
			if (ssb2->pkalgo == TMCG_OPENPGP_PKALGO_EXPERIMENTAL9)
			{
				if (ssb2->pub->valid && !ssb2->Weak(opt_verbose))
				{
					if ((ssb != NULL) && (opt_verbose > 1))
						std::cerr << "WARNING: more than one valid subkey" <<
							" found; last subkey selected" << std::endl;
					ssb = ssb2;
				}
				else
				{
					if (opt_verbose > 1)
						std::cerr << "WARNING: invalid or weak subkey at" <<
							" position " << i << " found and ignored" <<
							std::endl;
				}
			}
			else
			{
				if (opt_verbose > 1)
					std::cerr << "WARNING: non-tElG subkey at position " <<
						i << " found and ignored" << std::endl;
			}
		}
		if (ssb == NULL)
		{
			std::cerr << "ERROR: no admissible subkey found" << std::endl;
			delete ring;
			delete prv;
			exit(-1);
		}
		// create an instance of tElG by stored parameters from private key
		if (!init_tElG(ssb, opt_verbose, dkg))
		{
			delete dkg;
			delete ring;
			delete prv;
			return -1;
		}
		// parse OpenPGP message
		TMCG_OpenPGP_Message *msg = NULL;
		if (!CallasDonnerhackeFinneyShawThayerRFC4880::
			MessageParse(armored_message, opt_verbose, msg))
		{
			delete dkg;
			delete ring;
			delete prv;
			return -1;
		}
		if (msg->encrypted_message.size() == 0)
		{
			std::cerr << "ERROR: no encrypted data found" << std::endl;
			delete msg;
			delete dkg;
			delete ring;
			delete prv;
			return -1;
		}
		const TMCG_OpenPGP_PKESK *esk = NULL;
		for (size_t i = 0; i < (msg->PKESKs).size(); i++)
		{
			if ((msg->PKESKs[i])->pkalgo == TMCG_OPENPGP_PKALGO_ELGAMAL)
			{
				if (CallasDonnerhackeFinneyShawThayerRFC4880::
					OctetsCompareZero((msg->PKESKs[i])->keyid) &&
					check_esk(msg->PKESKs[i], ssb))
				{
					std::cerr << "WARNING: PKESK wildcard keyid found; " <<
							"try to decrypt message anyway" << std::endl;
					esk = msg->PKESKs[i];
				}
				else if (CallasDonnerhackeFinneyShawThayerRFC4880::
					OctetsCompare((msg->PKESKs[i])->keyid, ssb->pub->id))
				{
					if (opt_verbose > 1)
						std::cerr << "INFO: PKESK found with matching " <<
							"subkey ID" << std::endl;
					esk = msg->PKESKs[i];
					break;
				}
			}
		}
		if (esk == NULL)
		{
			std::cerr << "ERROR: no admissible PKESK found" << std::endl;
			delete msg;
			delete dkg;
			delete ring;
			delete prv;
			return -1;
		}
		if (!check_esk(esk, ssb))
		{
			std::cerr << "ERROR: bad ESK detected" << std::endl;
			delete msg;
			delete dkg;
			delete ring;
			delete prv;
			return -1;
		}
		// compute and process decryption shares
		std::string dds;
		compute_decryption_share(esk->gk, dkg, dds);
		tmcg_openpgp_octets_t dds_input;
		// bluring the decryption share make NSA's mass spying a bit harder
		dds_input.push_back((tmcg_openpgp_byte_t)(tmcg_mpz_wrandom_ui() % 256));
		dds_input.push_back((tmcg_openpgp_byte_t)(tmcg_mpz_wrandom_ui() % 256));
		dds_input.push_back((tmcg_openpgp_byte_t)(tmcg_mpz_wrandom_ui() % 256));
		dds_input.push_back((tmcg_openpgp_byte_t)(tmcg_mpz_wrandom_ui() % 256));
		dds_input.push_back((tmcg_openpgp_byte_t)(tmcg_mpz_wrandom_ui() % 256));
		for (size_t i = 0; i < dds.length(); i++)
			dds_input.push_back(dds[i]);
		std::string dds_radix;
		CallasDonnerhackeFinneyShawThayerRFC4880::
			Radix64Encode(dds_input, dds_radix, false);
		std::cerr << "Your decryption share (keep confidential): " <<
			dds_radix << std::endl;
		size_t idx;
		mpz_t r_i, c, r;
		mpz_init(r_i), mpz_init(c), mpz_init(r);
		if (!verify_decryption_share(esk->gk, dkg, dds, idx, r_i, c, r))
		{
			std::cerr << "ERROR: self-verification of decryption share" <<
				" failed" << std::endl;
			mpz_clear(r_i), mpz_clear(c), mpz_clear(r);
			delete msg;
			delete dkg;
			delete ring;
			delete prv;
			return -1;
		}
		std::vector<size_t> interpol_parties;
		std::vector<mpz_ptr> interpol_shares;
		mpz_ptr tmp1 = new mpz_t();
		mpz_init_set(tmp1, r_i);
		interpol_parties.push_back(dkg->i), interpol_shares.push_back(tmp1);
		std::cerr << "Enter decryption shares (one per line; ^D for EOF)" <<
			" from other parties/devices:" << std::endl;
		while (std::getline(std::cin, dds_radix))
		{
			tmcg_openpgp_octets_t dds_output;
			dds = "", idx = 0;
			CallasDonnerhackeFinneyShawThayerRFC4880::
				Radix64Decode(dds_radix, dds_output);
			for (size_t i = 5; i < dds_output.size(); i++)
				dds += dds_output[i];
			mpz_set_ui(r_i, 1L), mpz_set_ui(c, 1L), mpz_set_ui(r, 1L);
			if (verify_decryption_share(esk->gk, dkg, dds, idx, r_i, c, r))
			{
				if (!std::count(interpol_parties.begin(),
					interpol_parties.end(), idx))
				{
					mpz_ptr tmp1 = new mpz_t();
					mpz_init_set(tmp1, r_i);
					interpol_parties.push_back(idx);
					interpol_shares.push_back(tmp1);
				}
				else
					std::cerr << "WARNING: decryption share of P_" << idx <<
						" already stored" << std::endl;
			}
			else
				std::cerr << "WARNING: verification of decryption share from" <<
					" P_" << idx << " failed" << std::endl;
		}
		bool res = combine_decryption_shares(esk->gk, dkg, interpol_parties,
			interpol_shares);
		mpz_clear(r_i), mpz_clear(c), mpz_clear(r);
		for (size_t i = 0; i < interpol_shares.size(); i++)
		{
			mpz_clear(interpol_shares[i]);
			delete [] interpol_shares[i];
		}
		interpol_shares.clear(), interpol_parties.clear();
		tmcg_openpgp_octets_t content;
		tmcg_openpgp_secure_octets_t seskey;
		if (res)
		{
			res = decrypt_session_key(ssb->pub->elg_p, ssb->pub->elg_g,
				ssb->pub->elg_y, esk->gk, esk->myk, seskey);
		}
		if (res)
			res = decrypt_message(seskey, ring, msg, content);

		// release
		delete msg;
		delete dkg;
		delete ring;
		delete prv;
		// output decrypted content
		if (res)
		{
			if (opt_ofilename != NULL)
			{
				if (!write_message(opt_ofilename, content))
					return -1;
			}
			else
				print_message(content);
		}
		else
			return -1; // error
		return 0; // no error
	}
	// initialize return code
	int ret = 0;
	// create underlying point-to-point channels, if built-in TCP/IP requested
	if ((opt_hostname != NULL) && (opt_y == NULL))
	{
		if (port.length())
			opt_p = strtoul(port.c_str(), NULL, 10); // set own TCP start port
		if ((opt_p < 1) || (opt_p > 65535))
		{
			std::cerr << "ERROR: no valid TCP start port given" << std::endl;
			return -1;
		}
		tcpip_init(hostname);
		tcpip_bindports((uint16_t)opt_p, false);
		tcpip_bindports((uint16_t)opt_p, true);
		while (tcpip_connect((uint16_t)opt_p, false) < peers.size())
			sleep(1);
		while (tcpip_connect((uint16_t)opt_p, true) < peers.size())
			sleep(1);
		tcpip_accept();
		tcpip_fork();
		ret = tcpip_io();
		tcpip_close();
		tcpip_done();
		return ret;
	}
	else if (opt_y != NULL)
	{
		// run as replacement for GnuPG et al. (yet-another-openpgp-tool)
		run_instance(0, 0);
		return ret;
	}

	// start interactive variant with GNUnet or otherwise a local test
#ifdef GNUNET
	static const struct GNUNET_GETOPT_CommandLineOption myoptions[] = {
		GNUNET_GETOPT_option_flag('b',
			"binary",
			"consider encrypted message from FILENAME as binary input",
			&gnunet_opt_binary
		),
		GNUNET_GETOPT_option_flag('E',
			"echo",
			"enable terminal echo when reading passphrase",
			&gnunet_opt_E
		),
		GNUNET_GETOPT_option_string('H',
			"hostname",
			"STRING",
			"hostname (e.g. onion address) of this peer within PEERS",
			&gnunet_opt_hostname
		),
		GNUNET_GETOPT_option_string('i',
			"input",
			"FILENAME",
			"read encrypted message from FILENAME",
			&gnunet_opt_ifilename
		),
		GNUNET_GETOPT_option_string('k',
			"keyring",
			"FILENAME",
			"verify included signatures using keyring FILENAME",
			&gnunet_opt_k
		),
		GNUNET_GETOPT_option_flag('K',
			"weak",
			"allow weak keys to verify included signatures",
			&gnunet_opt_weak
		),
		GNUNET_GETOPT_option_flag('n',
			"non-interactive",
			"run in non-interactive mode",
			&gnunet_opt_nonint
		),
		GNUNET_GETOPT_option_string('o',
			"output",
			"FILENAME",
			"write decrypted message to FILENAME",
			&gnunet_opt_ofilename
		),
		GNUNET_GETOPT_option_string('p',
			"port",
			"STRING",
			"GNUnet CADET port to listen/connect",
			&gnunet_opt_port
		),
		GNUNET_GETOPT_option_string('P',
			"passwords",
			"STRING",
			"exchanged passwords to protect private and broadcast channels",
			&gnunet_opt_passwords
		),
		GNUNET_GETOPT_option_flag('V',
			"verbose",
			"turn on verbose output",
			&gnunet_opt_verbose
		),
		GNUNET_GETOPT_option_uint('w',
			"wait",
			"INTEGER",
			"minutes to wait until start of decryption",
			&gnunet_opt_wait
		),
		GNUNET_GETOPT_option_uint('W',
			"aiou-timeout",
			"INTEGER",
			"timeout for point-to-point messages in minutes",
			&gnunet_opt_W
		),
		GNUNET_GETOPT_option_string('y',
			"yaot",
			"FILNAME",
			"yet another OpenPGP tool with private key in FILENAME",
			&gnunet_opt_y
		),
		GNUNET_GETOPT_option_uint('x',
			"x-tests",
			NULL,
			"number of exchange tests",
			&gnunet_opt_xtests
		),
		GNUNET_GETOPT_OPTION_END
	};
	ret = GNUNET_PROGRAM_run(argc, argv, usage, about, myoptions, &gnunet_run,
		argv[0]);
//	GNUNET_free((void *) argv);
	if (ret == GNUNET_OK)
		return 0;
	else
		return -1;
#else
	std::cerr << "WARNING: GNUnet CADET is required for the message" <<
		" exchange of this program" << std::endl;
#endif

	std::cerr << "INFO: running local test with " << peers.size() <<
		" participants" << std::endl;
	// open pipes
	for (size_t i = 0; i < peers.size(); i++)
	{
		for (size_t j = 0; j < peers.size(); j++)
		{
			if (pipe(pipefd[i][j]) < 0)
				perror("ERROR: dkg-decrypt (pipe)");
			if (pipe(broadcast_pipefd[i][j]) < 0)
				perror("ERROR: dkg-decrypt (pipe)");
		}
	}
	
	// start childs
	for (size_t i = 0; i < peers.size(); i++)
		fork_instance(i);

	// sleep for five seconds
	sleep(5);
	
	// wait for childs and close pipes
	for (size_t i = 0; i < peers.size(); i++)
	{
		int wstatus = 0;
		if (opt_verbose)
			std::cerr << "INFO: waitpid(" << pid[i] << ")" << std::endl;
		if (waitpid(pid[i], &wstatus, 0) != pid[i])
			perror("ERROR: dkg-decrypt (waitpid)");
		if (!WIFEXITED(wstatus))
		{
			std::cerr << "ERROR: protocol instance ";
			if (WIFSIGNALED(wstatus))
				std::cerr << pid[i] << " terminated by signal " <<
					WTERMSIG(wstatus) << std::endl;
			if (WCOREDUMP(wstatus))
				std::cerr << pid[i] << " dumped core" << std::endl;
			ret = -1; // fatal error
		}
		else if (WIFEXITED(wstatus))
		{
			if (opt_verbose)
				std::cerr << "INFO: protocol instance " << pid[i] <<
					" terminated with exit status " << WEXITSTATUS(wstatus) <<
					std::endl;
			if (WEXITSTATUS(wstatus))
				ret = -2; // error
		}
		for (size_t j = 0; j < peers.size(); j++)
		{
			if ((close(pipefd[i][j][0]) < 0) || (close(pipefd[i][j][1]) < 0))
				perror("ERROR: dkg-decrypt (close)");
			if ((close(broadcast_pipefd[i][j][0]) < 0) ||
				(close(broadcast_pipefd[i][j][1]) < 0))
			{
				perror("ERROR: dkg-decrypt (close)");
			}
		}
	}
	
	return ret;
}

