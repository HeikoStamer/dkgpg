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
#ifdef DKGPG_TESTSUITE
	#undef GNUNET
#endif

// copy infos from DKGPG package before overwritten by GNUnet headers
static const char *version = PACKAGE_VERSION " (" PACKAGE_NAME ")";
static const char *about = PACKAGE_STRING " " PACKAGE_URL;

#include <sstream>
#include <fstream>
#include <vector>
#include <string>
#include <algorithm>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <signal.h>

#include <libTMCG.hh>
#include <aiounicast_select.hh>

#include "dkg-tcpip-common.hh"
#include "dkg-gnunet-common.hh"
#include "dkg-io.hh"

int							pipefd[DKGPG_MAX_N][DKGPG_MAX_N][2];
int							broadcast_pipefd[DKGPG_MAX_N][DKGPG_MAX_N][2];
pid_t						pid[DKGPG_MAX_N];
std::vector<std::string>	peers;
bool						instance_forked = false;

std::string					passphrase, userid, passwords, hostname, port;
tmcg_openpgp_octets_t		keyid, subkeyid, pub, sub, uidsig, subsig, sec, ssb, uid;
std::map<size_t, size_t>	idx2dkg, dkg2idx;
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

int 					opt_verbose = 0;
bool					libgcrypt_secmem = false;
char					*opt_crs = NULL;
char					*opt_passwords = NULL;
char					*opt_hostname = NULL;
unsigned long int		opt_t = DKGPG_MAX_N, opt_s = DKGPG_MAX_N, opt_e = 0, opt_p = 55000, opt_W = 5;

bool					fips = false;
std::stringstream		crss;
mpz_t 					cache[TMCG_MAX_SSRANDOMM_CACHE], cache_mod;
size_t					cache_avail = 0;

size_t					T, S;

void run_instance
	(const size_t whoami, const time_t keytime, const time_t keyexptime, const size_t num_xtests)
{
	// create communication handles for all players
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
				std::cerr << "ERROR: P_" << whoami << ": " << "cannot read password for protecting channel to P_" << i << std::endl;
				exit(-1);
			}
			key << pwd;
			if (((i + 1) < peers.size()) && !TMCG_ParseHelper::nx(passwords, '/'))
			{
				std::cerr << "ERROR: P_" << whoami << ": " << "cannot skip to next password for protecting channel to P_" << (i + 1) << std::endl;
				exit(-1);
			}
		}
		else
			key << "dkg-generate::P_" << (i + whoami); // use a simple key -- we assume that GNUnet provides secure channels
		uP_in.push_back(pipefd[i][whoami][0]);
		uP_out.push_back(pipefd[whoami][i][1]);
		uP_key.push_back(key.str());
		bP_in.push_back(broadcast_pipefd[i][whoami][0]);
		bP_out.push_back(broadcast_pipefd[whoami][i][1]);
		bP_key.push_back(key.str());
	}

	// create VTMF instance from CRS
	BarnettSmartVTMF_dlog *vtmf;
	if (fips)
		vtmf = new BarnettSmartVTMF_dlog(crss, TMCG_DDH_SIZE, TMCG_DLSE_SIZE, false);
	else	
		vtmf = new BarnettSmartVTMF_dlog(crss, TMCG_DDH_SIZE, TMCG_DLSE_SIZE, true); // with verifiable generation of $g$
	// check the constructed VTMF instance
	if (!vtmf->CheckGroup())
	{
		std::cerr << "ERROR: P_" << whoami << ": " << "group G from CRS is incorrectly generated!" << std::endl;
		delete vtmf;
		exit(-1);
	}

	// create asynchronous authenticated unicast channels
	aiounicast_select *aiou = new aiounicast_select(peers.size(), whoami, uP_in, uP_out, uP_key, aiounicast::aio_scheduler_roundrobin, (opt_W * 60));

	// create asynchronous authenticated unicast channels for broadcast protocol
	aiounicast_select *aiou2 = new aiounicast_select(peers.size(), whoami, bP_in, bP_out, bP_key, aiounicast::aio_scheduler_roundrobin, (opt_W * 60));
			
	// create an instance of a reliable broadcast protocol (RBC)
	std::string myID = "dkg-generate|";
	for (size_t i = 0; i < peers.size(); i++)
		myID += peers[i] + "|";
	myID += T; // include parameterized t-resiliance in the ID of broadcast protocol to enforce equal parameter set
	myID += "|";
	myID += S; // include parameterized s-resiliance in the ID of broadcast protocol to enforce equal parameter set
	myID += "|";
	size_t T_RBC = (peers.size() - 1) / 3; // assume maximum asynchronous t-resilience for RBC
	CachinKursawePetzoldShoupRBC *rbc = new CachinKursawePetzoldShoupRBC(peers.size(), T_RBC, whoami, aiou2, aiounicast::aio_scheduler_roundrobin, (opt_W * 60));
	rbc->setID(myID);

	// perform a simple exchange test with debug output
	for (size_t i = 0; i < num_xtests; i++)
	{
		mpz_t xtest;
		mpz_init_set_ui(xtest, i);
		std::cerr << "INFO: P_" << whoami << ": xtest = " << xtest << " <-> ";
		rbc->Broadcast(xtest);
		for (size_t ii = 0; ii < peers.size(); ii++)
		{
			if (!rbc->DeliverFrom(xtest, ii))
				std::cerr << "<X> ";
			else
				std::cerr << xtest << " ";
		}
		std::cerr << std::endl;
		mpz_clear(xtest);
	}
			
	// create and exchange temporary keys in order to bootstrap the $h$-generation for DKG/tDSS [JL00]
	// TODO: replace N-time NIZK by one interactive (distributed) zero-knowledge proof of knowledge, i.e., removes ROM assumption here
	if (opt_verbose)
		std::cerr << "INFO: generate h by using VTMF key generation protocol" << std::endl;
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
				std::cerr << "WARNING: P_" << whoami << ": no VTMF key received from P_" << i << std::endl;
			}
			if (!rbc->DeliverFrom(nizk_c, i))
			{
				std::cerr << "WARNING: P_" << whoami << ": no NIZK c received from " << i << std::endl;
			}
			if (!rbc->DeliverFrom(nizk_r, i))
			{
				std::cerr << "WARNING: P_" << whoami << ": no NIZK r received from " << i << std::endl;
			}
			std::stringstream lej;
			lej << h_j << std::endl << nizk_c << std::endl << nizk_r << std::endl;
			if (!vtmf->KeyGenerationProtocol_UpdateKey(lej))
			{
				std::cerr << "WARNING: P_" << whoami << ": VTMF key of P_" << i << " was not correctly generated!" << std::endl;
			}
		}
	}
	vtmf->KeyGenerationProtocol_Finalize();
	mpz_clear(nizk_c), mpz_clear(nizk_r), mpz_clear(h_j);

	// create an instance of tDSS
	CanettiGennaroJareckiKrawczykRabinDSS *dss;
	if (opt_verbose)
		std::cerr << "INFO: CanettiGennaroJareckiKrawczykRabinDSS(" << peers.size() << ", " << S << ", " << whoami << ", ...)" << std::endl;
	if (fips)
		dss = new CanettiGennaroJareckiKrawczykRabinDSS(peers.size(), S, whoami, vtmf->p, vtmf->q, vtmf->g, vtmf->h,
			TMCG_DDH_SIZE, TMCG_DLSE_SIZE, false, true);
	else
		dss = new CanettiGennaroJareckiKrawczykRabinDSS(peers.size(), S, whoami, vtmf->p, vtmf->q, vtmf->g, vtmf->h,
			TMCG_DDH_SIZE, TMCG_DLSE_SIZE, true, true); // with verifiable generation of $g$
	if (!dss->CheckGroup())
	{
		std::cerr << "ERROR: P_" << whoami << ": " << "tDSS parameters are not correctly generated!" << std::endl;
		delete dss, delete rbc, delete vtmf, delete aiou, delete aiou2;
		exit(-1);
	}
	// tDSS: generate shared $x$ and extract $y = g^x \bmod p$, if s-resilience is not zero
	if (S > 0)
	{
		std::stringstream err_log;
		if (opt_verbose)
			std::cerr << "INFO: P_" << whoami << ": dss.Generate()" << std::endl;
		if (!dss->Generate(aiou, rbc, err_log, false, cache, cache_mod, &cache_avail))
		{
			std::cerr << "ERROR: P_" << whoami << ": " << "tDSS Generate() failed" << std::endl;
			std::cerr << "ERROR: P_" << whoami << ": log follows " << std::endl << err_log.str();
			delete dss, delete rbc, delete vtmf, delete aiou, delete aiou2;
			exit(-1);
		}
		if (opt_verbose > 1)
			std::cerr << "INFO: P_" << whoami << ": log follows " << std::endl << err_log.str();
	}

	// create an instance of DKG
	GennaroJareckiKrawczykRabinDKG *dkg;
	if (opt_verbose)
		std::cerr << "INFO: GennaroJareckiKrawczykRabinDKG(" << peers.size() << ", " << T << ", " << whoami << ", ...)" << std::endl;
	if (fips)
		dkg = new GennaroJareckiKrawczykRabinDKG(peers.size(), T, whoami, vtmf->p, vtmf->q, vtmf->g, vtmf->h,
			TMCG_DDH_SIZE, TMCG_DLSE_SIZE, false, true);
	else
		dkg = new GennaroJareckiKrawczykRabinDKG(peers.size(), T, whoami, vtmf->p, vtmf->q, vtmf->g, vtmf->h,
			TMCG_DDH_SIZE, TMCG_DLSE_SIZE, true, true); // with verifiable generation of $g$
	if (!dkg->CheckGroup())
	{
		std::cerr << "ERROR: P_" << whoami << ": " << "DKG parameters are not correctly generated!" << std::endl;
		delete dkg, delete dss, delete rbc, delete vtmf, delete aiou, delete aiou2;
		exit(-1);
	}
			
	// DKG: generate shared $x$ and extract $y = g^x \bmod p$
	if (T > 0)
	{
		std::stringstream err_log;
		if (opt_verbose)
			std::cerr << "INFO: P_" << whoami << ": dkg.Generate()" << std::endl;
		if (!dkg->Generate(aiou, rbc, err_log, false, cache, cache_mod, &cache_avail))
		{
			std::cerr << "ERROR: P_" << whoami << ": " << "DKG Generate() failed" << std::endl;
			std::cerr << "ERROR: P_" << whoami << ": log follows " << std::endl << err_log.str();
			delete dkg, delete dss, delete rbc, delete vtmf, delete aiou, delete aiou2;
			exit(-1);
		}
		if (opt_verbose > 1)
			std::cerr << "INFO: P_" << whoami << ": log follows " << std::endl << err_log.str();
	
		// check the generated key share
		if (opt_verbose)
			std::cerr << "INFO: P_" << whoami << ": dkg.CheckKey()" << std::endl;
		if (!dkg->CheckKey())
		{
			std::cerr << "ERROR: P_" << whoami << ": " << "DKG CheckKey() failed" << std::endl;
			delete dkg, delete dss, delete rbc, delete vtmf, delete aiou, delete aiou2;
			exit(-1);
		}
	}

	// participants must agree on a common key creation time (OpenPGP), otherwise subkeyid does not match
	if (opt_verbose)
		std::cerr << "INFO: agree on a key creation time for OpenPGP" << std::endl;
	time_t ckeytime = 0;
	std::vector<time_t> tvs;
	mpz_t mtv;
	mpz_init_set_ui(mtv, keytime);
	rbc->Broadcast(mtv);
	tvs.push_back(keytime);
	for (size_t i = 0; i < peers.size(); i++)
	{
		if (i != whoami)
		{
			if (rbc->DeliverFrom(mtv, i))
			{
				time_t utv;
				utv = (time_t)mpz_get_ui(mtv);
				tvs.push_back(utv);
			}
			else
			{
				std::cerr << "WARNING: P_" << whoami << ": no key creation time received from " << i << std::endl;
			}
		}
	}
	mpz_clear(mtv);
	std::sort(tvs.begin(), tvs.end());
	if (tvs.size() < (peers.size() - T_RBC))
	{
		std::cerr << "ERROR: P_" << whoami << ": not enough timestamps received" << std::endl;
		delete dkg, delete dss, delete rbc, delete vtmf, delete aiou, delete aiou2;
		exit(-1);
	}
	ckeytime = tvs[tvs.size()/2]; // use a median value as some kind of gentle agreement
	if (opt_verbose)
		std::cerr << "INFO: P_" << whoami << ": canonicalized key creation time = " << ckeytime << std::endl;

	// select hash algorithm for OpenPGP based on |q| (size in bit)
	tmcg_openpgp_hashalgo_t hashalgo = TMCG_OPENPGP_HASHALGO_UNKNOWN;
	if (mpz_sizeinbase(vtmf->q, 2L) == 256)
		hashalgo = TMCG_OPENPGP_HASHALGO_SHA256; // SHA256 (alg 8)
	else if (mpz_sizeinbase(vtmf->q, 2L) == 384)
		hashalgo = TMCG_OPENPGP_HASHALGO_SHA384; // SHA384 (alg 9)
	else if (mpz_sizeinbase(vtmf->q, 2L) == 512)
		hashalgo = TMCG_OPENPGP_HASHALGO_SHA512; // SHA512 (alg 10)
	else
	{
		std::cerr << "ERROR: P_" << whoami << ": selecting hash algorithm failed for |q| = " << mpz_sizeinbase(vtmf->q, 2L) << std::endl;
		delete dkg, delete dss, delete rbc, delete vtmf, delete aiou, delete aiou2;
		exit(-1);
	}

	// create an OpenPGP DSA-based primary key resp. ElGamal-based subkey using computed values from tDSS resp. DKG protocols
	std::string out, crcout, armor;
	tmcg_openpgp_octets_t all, pub, sec, uid, uidsig, sub, ssb, subsig, keyid, dsaflags, elgflags;
	tmcg_openpgp_octets_t pub_hashing, sub_hashing;
	tmcg_openpgp_octets_t uidsig_hashing, subsig_hashing, uidsig_left, subsig_left;
	tmcg_openpgp_octets_t hash, empty;
	time_t sigtime;
	gcry_sexp_t key;
	gcry_mpi_t p, q, g, y, x, r, s;
	gcry_error_t ret;
	mpz_t dsa_y, dsa_x, dsa_m, dsa_r, dsa_s;
	mpz_init(dsa_y), mpz_init(dsa_x), mpz_init(dsa_m), mpz_init(dsa_r), mpz_init(dsa_s);
	if (S > 0)
	{
		// use values of the shared DSA signing key, if s-resilience is not equal zero
		mpz_set(dsa_x, dss->x_i);
		mpz_set(dsa_y, dss->y);
	}
	else
	{
		// generate individual DSA signing key, if s-resilience is set to zero
		mpz_ssrandomm_cache(cache, cache_mod, &cache_avail, dsa_x, vtmf->q); // choose private key for DSA
		mpz_spowm(dsa_y, vtmf->g, dsa_x, vtmf->p); // compute public key for DSA
	}
	p = gcry_mpi_new(2048);
	if (!mpz_get_gcry_mpi(p, vtmf->p))
	{
		std::cerr << "ERROR: P_" << whoami << ": mpz_get_gcry_mpi() failed for p" << std::endl;
		mpz_clear(dsa_y), mpz_clear(dsa_x), mpz_clear(dsa_m), mpz_clear(dsa_r), mpz_clear(dsa_s);
		gcry_mpi_release(p);
		delete dkg, delete dss, delete rbc, delete vtmf, delete aiou, delete aiou2;
		exit(-1);
	}
	q = gcry_mpi_new(2048);
	if (!mpz_get_gcry_mpi(q, vtmf->q))
	{
		std::cerr << "ERROR: P_" << whoami << ": mpz_get_gcry_mpi() failed for q" << std::endl;
		mpz_clear(dsa_y), mpz_clear(dsa_x), mpz_clear(dsa_m), mpz_clear(dsa_r), mpz_clear(dsa_s);
		gcry_mpi_release(p);
		gcry_mpi_release(q);
		delete dkg, delete dss, delete rbc, delete vtmf, delete aiou, delete aiou2;
		exit(-1);
	}
	g = gcry_mpi_new(2048);
	if (!mpz_get_gcry_mpi(g, vtmf->g))
	{
		std::cerr << "ERROR: P_" << whoami << ": mpz_get_gcry_mpi() failed for g" << std::endl;
		mpz_clear(dsa_y), mpz_clear(dsa_x), mpz_clear(dsa_m), mpz_clear(dsa_r), mpz_clear(dsa_s);
		gcry_mpi_release(p);
		gcry_mpi_release(q);
		gcry_mpi_release(g);
		delete dkg, delete dss, delete rbc, delete vtmf, delete aiou, delete aiou2;
		exit(-1);
	}
	y = gcry_mpi_new(2048);
	if (!mpz_get_gcry_mpi(y, dsa_y))
	{
		std::cerr << "ERROR: P_" << whoami << ": mpz_get_gcry_mpi() failed for dsa_y" << std::endl;
		mpz_clear(dsa_y), mpz_clear(dsa_x), mpz_clear(dsa_m), mpz_clear(dsa_r), mpz_clear(dsa_s);
		gcry_mpi_release(p);
		gcry_mpi_release(q);
		gcry_mpi_release(g);
		gcry_mpi_release(y);
		delete dkg, delete dss, delete rbc, delete vtmf, delete aiou, delete aiou2;
		exit(-1);
	}
	if (libgcrypt_secmem)
		x = gcry_mpi_snew(2048);
	else	
		x = gcry_mpi_new(2048);
	if (!mpz_get_gcry_mpi(x, dsa_x))
	{
		std::cerr << "ERROR: P_" << whoami << ": mpz_get_gcry_mpi() failed for dsa_x" << std::endl;
		mpz_clear(dsa_y), mpz_clear(dsa_x), mpz_clear(dsa_m), mpz_clear(dsa_r), mpz_clear(dsa_s);
		gcry_mpi_release(p);
		gcry_mpi_release(q);
		gcry_mpi_release(g);
		gcry_mpi_release(y);
		gcry_mpi_release(x);
		delete dkg, delete dss, delete rbc, delete vtmf, delete aiou, delete aiou2;
		exit(-1);
	}
	mpz_clear(dsa_y), mpz_clear(dsa_x);
	size_t erroff;
	ret = gcry_sexp_build(&key, &erroff, "(key-data (public-key (dsa (p %M) (q %M) (g %M) (y %M)))"
		" (private-key (dsa (p %M) (q %M) (g %M) (y %M) (x %M))))", p, q, g, y, p, q, g, y, x);
	if (ret)
	{
		std::cerr << "ERROR: P_" << whoami << ": gcry_sexp_build() failed" << std::endl;
		mpz_clear(dsa_m), mpz_clear(dsa_r), mpz_clear(dsa_s);
		gcry_mpi_release(p);
		gcry_mpi_release(q);
		gcry_mpi_release(g);
		gcry_mpi_release(y);
		gcry_mpi_release(x);
		delete dkg, delete dss, delete rbc, delete vtmf, delete aiou, delete aiou2;
		exit(-1);
	}
	CallasDonnerhackeFinneyShawThayerRFC4880::PacketPubEncode(ckeytime, TMCG_OPENPGP_PKALGO_DSA, p, q, g, y, pub); // use common key creation time
	if (S > 0)
	{
		// create an OpenPGP private key as experimental algorithm ID 107 to store everything from tDSS
		gcry_mpi_t h, n, t, i, qualsize, x_rvss_qualsize, x_i, xprime_i;
		std::vector<gcry_mpi_t> qual, x_rvss_qual;
		std::vector<std::string> capl; // canonicalized peer list
		std::vector< std::vector<gcry_mpi_t> > c_ik;
		h = gcry_mpi_new(2048);
		if (!mpz_get_gcry_mpi(h, dss->h))
		{
			std::cerr << "ERROR: P_" << whoami << ": mpz_get_gcry_mpi() failed for dss->h" << std::endl;
			mpz_clear(dsa_m), mpz_clear(dsa_r), mpz_clear(dsa_s);
			gcry_mpi_release(p);
			gcry_mpi_release(q);
			gcry_mpi_release(g);
			gcry_mpi_release(y);
			gcry_mpi_release(x);
			gcry_mpi_release(h);
			gcry_sexp_release(key);
			delete dkg, delete dss, delete rbc, delete vtmf, delete aiou, delete aiou2;
			exit(-1);
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
		assert((dss->n == peers.size()));
		for (size_t j = 0; j < peers.size(); j++)
			capl.push_back(peers[j]);
		c_ik.resize(dss->n);
		for (size_t j = 0; j < c_ik.size(); j++)
		{
			for (size_t k = 0; k <= dss->t; k++)
			{
				gcry_mpi_t tmp;
				tmp = gcry_mpi_new(2048);
				if (!mpz_get_gcry_mpi(tmp, dss->dkg->x_rvss->C_ik[j][k]))
				{
					std::cerr << "ERROR: P_" << whoami << ": mpz_get_gcry_mpi() failed for dss->dkg->x_rvss->C_ik[j][k]" << std::endl;
					mpz_clear(dsa_m), mpz_clear(dsa_r), mpz_clear(dsa_s);
					gcry_mpi_release(p);
					gcry_mpi_release(q);
					gcry_mpi_release(g);
					gcry_mpi_release(y);
					gcry_mpi_release(x);
					gcry_mpi_release(h);
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
					gcry_sexp_release(key);
					delete dkg, delete dss, delete rbc, delete vtmf, delete aiou, delete aiou2;
					exit(-1); 
				}
				c_ik[j].push_back(tmp);
			}
		}
		if (libgcrypt_secmem)
			x_i = gcry_mpi_snew(2048);
		else		
			x_i = gcry_mpi_new(2048);
		if (!mpz_get_gcry_mpi(x_i, dss->x_i))
		{
			std::cerr << "ERROR: P_" << whoami << ": mpz_get_gcry_mpi() failed for dss->x_i" << std::endl;
			mpz_clear(dsa_m), mpz_clear(dsa_r), mpz_clear(dsa_s);
			gcry_mpi_release(p);
			gcry_mpi_release(q);
			gcry_mpi_release(g);
			gcry_mpi_release(y);
			gcry_mpi_release(x);
			gcry_mpi_release(h);
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
			gcry_mpi_release(x_i);
			gcry_sexp_release(key);
			delete dkg, delete dss, delete rbc, delete vtmf, delete aiou, delete aiou2;
			exit(-1);
		}
		if (libgcrypt_secmem)
			xprime_i = gcry_mpi_snew(2048);
		else
			xprime_i = gcry_mpi_new(2048);
		if (!mpz_get_gcry_mpi(xprime_i, dss->xprime_i))
		{
			std::cerr << "ERROR: P_" << whoami << ": mpz_get_gcry_mpi() failed for dss->xprime_i" << std::endl;
			mpz_clear(dsa_m), mpz_clear(dsa_r), mpz_clear(dsa_s);
			gcry_mpi_release(p);
			gcry_mpi_release(q);
			gcry_mpi_release(g);
			gcry_mpi_release(y);
			gcry_mpi_release(x);
			gcry_mpi_release(h);
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
			gcry_mpi_release(x_i);
			gcry_mpi_release(xprime_i);
			gcry_sexp_release(key);
			delete dkg, delete dss, delete rbc, delete vtmf, delete aiou, delete aiou2;
			exit(-1);
		}
		CallasDonnerhackeFinneyShawThayerRFC4880::PacketSecEncodeExperimental107(ckeytime, p, q, g, h, y, 
			n, t, i, qualsize, qual, x_rvss_qualsize, x_rvss_qual, capl, c_ik, x_i, xprime_i, passphrase, sec);
		gcry_mpi_release(h);
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
		gcry_mpi_release(x_i);
		gcry_mpi_release(xprime_i);
	}
	else
		CallasDonnerhackeFinneyShawThayerRFC4880::PacketSecEncode(ckeytime, TMCG_OPENPGP_PKALGO_DSA, p, q, g, y, x, passphrase, sec);
	for (size_t i = 6; i < pub.size(); i++)
		pub_hashing.push_back(pub[i]);
	CallasDonnerhackeFinneyShawThayerRFC4880::KeyidCompute(pub_hashing, keyid);
	CallasDonnerhackeFinneyShawThayerRFC4880::PacketUidEncode(userid, uid);
	// RFC 4880: "In a V4 key, the primary key MUST be a key capable of certification."
	if (S > 0)
	{
		dsaflags.push_back(0x01 | 0x02 | 0x10); // key may be used to certify other keys, to sign data and has been split by a secret-sharing mechanism
		sigtime = ckeytime; // use common key creation time as OpenPGP signature creation time
	}
	else
	{
		dsaflags.push_back(0x01 | 0x02); // key may be used to certify other keys and to sign data
		sigtime = time(NULL); // current time
	}
	// TODO: create a direct-key signature (0x1f) with the above key flags
	// positive certification (0x13) of uid and pub
	CallasDonnerhackeFinneyShawThayerRFC4880::
		PacketSigPrepareSelfSignature(TMCG_OPENPGP_SIGNATURE_POSITIVE_CERTIFICATION,
			hashalgo, sigtime, keyexptime, dsaflags, keyid, uidsig_hashing); 
	hash.clear();
	CallasDonnerhackeFinneyShawThayerRFC4880::
		CertificationHash(pub_hashing, userid, empty, uidsig_hashing, hashalgo,
			hash, uidsig_left);
	if (S > 0)
	{
		tmcg_openpgp_byte_t buffer[1024];
		gcry_mpi_t h;
		size_t buflen = 0;
		memset(buffer, 0, sizeof(buffer));
		for (size_t i = 0; ((i < hash.size()) && (i < sizeof(buffer))); i++, buflen++)
			buffer[i] = hash[i];
		ret = gcry_mpi_scan(&h, GCRYMPI_FMT_USG, buffer, buflen, NULL);
		if (ret)
		{
			std::cerr << "ERROR: P_" << whoami << ": gcry_mpi_scan() failed for h" << std::endl;
			mpz_clear(dsa_m), mpz_clear(dsa_r), mpz_clear(dsa_s);
			gcry_mpi_release(p);
			gcry_mpi_release(q);
			gcry_mpi_release(g);
			gcry_mpi_release(y);
			gcry_mpi_release(x);
			gcry_sexp_release(key);
			delete dkg, delete dss, delete rbc, delete vtmf, delete aiou, delete aiou2;
			exit(-1);
		}
		if (!mpz_set_gcry_mpi(h, dsa_m))
		{
			std::cerr << "ERROR: P_" << whoami << ": mpz_set_gcry_mpi() failed for dsa_m" << std::endl;
			gcry_mpi_release(h);
			mpz_clear(dsa_m), mpz_clear(dsa_r), mpz_clear(dsa_s);
			gcry_mpi_release(p);
			gcry_mpi_release(q);
			gcry_mpi_release(g);
			gcry_mpi_release(y);
			gcry_mpi_release(x);
			gcry_sexp_release(key);
			delete dkg, delete dss, delete rbc, delete vtmf, delete aiou, delete aiou2;
			exit(-1);
		}
		gcry_mpi_release(h);
		std::stringstream err_log_sign;
		if (opt_verbose)
			std::cerr << "INFO: P_" << whoami << ": dss.Sign() for self signature on uid" << std::endl;
		if (!dss->Sign(peers.size(), whoami, dsa_m, dsa_r, dsa_s, aiou, rbc, err_log_sign))
		{
			std::cerr << "ERROR: P_" << whoami << ": " << "tDSS Sign() failed" << std::endl;
			std::cerr << "ERROR: P_" << whoami << ": log follows " << std::endl << err_log_sign.str();
			mpz_clear(dsa_m), mpz_clear(dsa_r), mpz_clear(dsa_s);
			gcry_mpi_release(p);
			gcry_mpi_release(q);
			gcry_mpi_release(g);
			gcry_mpi_release(y);
			gcry_mpi_release(x);
			gcry_sexp_release(key);
			delete dkg, delete dss, delete rbc, delete vtmf, delete aiou, delete aiou2;
			exit(-1);
		}
		if (opt_verbose > 1)
			std::cerr << "INFO: P_" << whoami << ": log follows " << std::endl << err_log_sign.str();
		r = gcry_mpi_new(2048);
		if (!mpz_get_gcry_mpi(r, dsa_r))
		{
			std::cerr << "ERROR: P_" << whoami << ": mpz_get_gcry_mpi() failed for dsa_r" << std::endl;
			mpz_clear(dsa_m), mpz_clear(dsa_r), mpz_clear(dsa_s);
			gcry_mpi_release(p);
			gcry_mpi_release(q);
			gcry_mpi_release(g);
			gcry_mpi_release(y);
			gcry_mpi_release(x);
			gcry_mpi_release(r);
			gcry_sexp_release(key);
			delete dkg, delete dss, delete rbc, delete vtmf, delete aiou, delete aiou2;
			exit(-1);
		}
		s = gcry_mpi_new(2048);
		if (!mpz_get_gcry_mpi(s, dsa_s))
		{
			std::cerr << "ERROR: P_" << whoami << ": mpz_get_gcry_mpi() failed for dsa_s" << std::endl;
			mpz_clear(dsa_m), mpz_clear(dsa_r), mpz_clear(dsa_s);
			gcry_mpi_release(p);
			gcry_mpi_release(q);
			gcry_mpi_release(g);
			gcry_mpi_release(y);
			gcry_mpi_release(x);
			gcry_mpi_release(r);
			gcry_mpi_release(s);
			gcry_sexp_release(key);
			delete dkg, delete dss, delete rbc, delete vtmf, delete aiou, delete aiou2;
			exit(-1);
		}
	}
	else
	{
		r = gcry_mpi_new(2048);
		s = gcry_mpi_new(2048);
		ret = CallasDonnerhackeFinneyShawThayerRFC4880::AsymmetricSignDSA(hash, key, r, s);
		if (ret)
		{
			std::cerr << "ERROR: P_" << whoami << ": CallasDonnerhackeFinneyShawThayerRFC4880::AsymmetricSignDSA() failed" << std::endl;
			mpz_clear(dsa_m), mpz_clear(dsa_r), mpz_clear(dsa_s);
			gcry_mpi_release(p);
			gcry_mpi_release(q);
			gcry_mpi_release(g);
			gcry_mpi_release(y);
			gcry_mpi_release(x);
			gcry_mpi_release(r);
			gcry_mpi_release(s);
			gcry_sexp_release(key);
			delete dkg, delete dss, delete rbc, delete vtmf, delete aiou, delete aiou2;
			exit(-1);
		}
	}
	CallasDonnerhackeFinneyShawThayerRFC4880::
		PacketSigEncode(uidsig_hashing, uidsig_left, r, s, uidsig);
	gcry_mpi_release(r);
	gcry_mpi_release(s);
	gcry_mpi_release(x);
	gcry_mpi_release(y);
	if (T > 0)
	{
		y = gcry_mpi_new(2048);
		if (!mpz_get_gcry_mpi(y, dkg->y)) // computed by DKG (cf. LibTMCG source code)
		{
			std::cerr << "ERROR: P_" << whoami << ": mpz_get_gcry_mpi() failed for dkg->y" << std::endl;
			mpz_clear(dsa_m), mpz_clear(dsa_r), mpz_clear(dsa_s);
			gcry_mpi_release(p);
			gcry_mpi_release(q);
			gcry_mpi_release(g);
			gcry_mpi_release(y);
			gcry_sexp_release(key);
			delete dkg, delete dss, delete rbc, delete vtmf, delete aiou, delete aiou2;
			exit(-1);
		}
		CallasDonnerhackeFinneyShawThayerRFC4880::
			PacketSubEncode(ckeytime, TMCG_OPENPGP_PKALGO_ELGAMAL, p, q, g, y,
				sub); // use common key creation time
		// create an OpenPGP private subkey as experimental algorithm ID 109 to store everything from DKG
		gcry_mpi_t h, n, t, i, qualsize, x_i, xprime_i;
		std::vector<gcry_mpi_t> qual, v_i;
		std::vector< std::vector<gcry_mpi_t> > c_ik;
		h = gcry_mpi_new(2048);
		if (!mpz_get_gcry_mpi(h, dkg->h))
		{
			std::cerr << "ERROR: P_" << whoami << ": mpz_get_gcry_mpi() failed for dkg->h" << std::endl;
			mpz_clear(dsa_m), mpz_clear(dsa_r), mpz_clear(dsa_s);
			gcry_mpi_release(p);
			gcry_mpi_release(q);
			gcry_mpi_release(g);
			gcry_mpi_release(y);
			gcry_mpi_release(h);
			gcry_sexp_release(key);
			delete dkg, delete dss, delete rbc, delete vtmf, delete aiou, delete aiou2;
			exit(-1);
		}
		n = gcry_mpi_set_ui(NULL, dkg->n);
		t = gcry_mpi_set_ui(NULL, dkg->t);
		i = gcry_mpi_set_ui(NULL, dkg->i);
		qualsize = gcry_mpi_set_ui(NULL, dkg->QUAL.size());
		for (size_t j = 0; j < dkg->QUAL.size(); j++)
		{
			gcry_mpi_t tmp = gcry_mpi_set_ui(NULL, dkg->QUAL[j]);
			qual.push_back(tmp);
		}
		v_i.resize(dkg->n);
		for (size_t j = 0; j < v_i.size(); j++)
		{
			v_i[j] = gcry_mpi_new(2048);
			if (!mpz_get_gcry_mpi(v_i[j], dkg->v_i[j]))
			{
				std::cerr << "ERROR: P_" << whoami << ": mpz_get_gcry_mpi() failed for dkg->v_i[j]" << std::endl;
				mpz_clear(dsa_m), mpz_clear(dsa_r), mpz_clear(dsa_s);
				gcry_mpi_release(p);
				gcry_mpi_release(q);
				gcry_mpi_release(g);
				gcry_mpi_release(y);
				gcry_mpi_release(h);
				gcry_mpi_release(n);
				gcry_mpi_release(t);
				gcry_mpi_release(i);
				gcry_mpi_release(qualsize);
				for (size_t jj = 0; jj < qual.size(); jj++)
					gcry_mpi_release(qual[jj]);
				for (size_t jj = 0; jj < v_i.size(); jj++)
					gcry_mpi_release(v_i[jj]);
				for (size_t jj = 0; jj < c_ik.size(); jj++)
					for (size_t kk = 0; kk < c_ik[jj].size(); kk++)
						gcry_mpi_release(c_ik[jj][kk]);
				gcry_mpi_release(v_i[j]);
				gcry_sexp_release(key);
				delete dkg, delete dss, delete rbc, delete vtmf, delete aiou, delete aiou2;
				exit(-1); 
			}
		}
		c_ik.resize(dkg->n);
		for (size_t j = 0; j < c_ik.size(); j++)
		{
			for (size_t k = 0; k <= dkg->t; k++)
			{
				gcry_mpi_t tmp;
				tmp = gcry_mpi_new(2048);
				if (!mpz_get_gcry_mpi(tmp, dkg->C_ik[j][k]))
				{
					std::cerr << "ERROR: P_" << whoami << ": mpz_get_gcry_mpi() failed for dkg->C_ik[j][k]" << std::endl;
					mpz_clear(dsa_m), mpz_clear(dsa_r), mpz_clear(dsa_s);
					gcry_mpi_release(p);
					gcry_mpi_release(q);
					gcry_mpi_release(g);
					gcry_mpi_release(y);
					gcry_mpi_release(h);
					gcry_mpi_release(n);
					gcry_mpi_release(t);
					gcry_mpi_release(i);
					gcry_mpi_release(qualsize);
					for (size_t jj = 0; jj < qual.size(); jj++)
						gcry_mpi_release(qual[jj]);
					for (size_t jj = 0; jj < v_i.size(); jj++)
						gcry_mpi_release(v_i[jj]);
					for (size_t jj = 0; jj < c_ik.size(); jj++)
						for (size_t kk = 0; kk < c_ik[jj].size(); kk++)
							gcry_mpi_release(c_ik[jj][kk]);
					gcry_mpi_release(tmp);
					gcry_sexp_release(key);
					delete dkg, delete dss, delete rbc, delete vtmf, delete aiou, delete aiou2;
					exit(-1); 
				}
				c_ik[j].push_back(tmp);
			}
		}
		if (libgcrypt_secmem)
			x_i = gcry_mpi_snew(2048);
		else
			x_i = gcry_mpi_new(2048);
		if (!mpz_get_gcry_mpi(x_i, dkg->x_i))
		{
			std::cerr << "ERROR: P_" << whoami << ": mpz_get_gcry_mpi() failed for dkg->x_i" << std::endl;
			mpz_clear(dsa_m), mpz_clear(dsa_r), mpz_clear(dsa_s);
			gcry_mpi_release(p);
			gcry_mpi_release(q);
			gcry_mpi_release(g);
			gcry_mpi_release(y);
			gcry_mpi_release(h);
			gcry_mpi_release(n);
			gcry_mpi_release(t);
			gcry_mpi_release(i);
			gcry_mpi_release(qualsize);
			for (size_t j = 0; j < qual.size(); j++)
				gcry_mpi_release(qual[j]);
			for (size_t j = 0; j < v_i.size(); j++)
				gcry_mpi_release(v_i[j]);
			for (size_t j = 0; j < c_ik.size(); j++)
				for (size_t k = 0; k < c_ik[j].size(); k++)
					gcry_mpi_release(c_ik[j][k]);
			gcry_mpi_release(x_i);
			gcry_sexp_release(key);
			delete dkg, delete dss, delete rbc, delete vtmf, delete aiou, delete aiou2;
			exit(-1);
		}
		if (libgcrypt_secmem)
			xprime_i = gcry_mpi_snew(2048);
		else
			xprime_i = gcry_mpi_new(2048);
		if (!mpz_get_gcry_mpi(xprime_i, dkg->xprime_i))
		{
			std::cerr << "ERROR: P_" << whoami << ": mpz_get_gcry_mpi() failed for dkg->xprime_i" << std::endl;
			mpz_clear(dsa_m), mpz_clear(dsa_r), mpz_clear(dsa_s);
			gcry_mpi_release(p);
			gcry_mpi_release(q);
			gcry_mpi_release(g);
			gcry_mpi_release(y);
			gcry_mpi_release(h);
			gcry_mpi_release(n);
			gcry_mpi_release(t);
			gcry_mpi_release(i);
			gcry_mpi_release(qualsize);
			for (size_t j = 0; j < qual.size(); j++)
				gcry_mpi_release(qual[j]);
			for (size_t j = 0; j < v_i.size(); j++)
				gcry_mpi_release(v_i[j]);
			for (size_t j = 0; j < c_ik.size(); j++)
				for (size_t k = 0; k < c_ik[j].size(); k++)
					gcry_mpi_release(c_ik[j][k]);
			gcry_mpi_release(x_i);
			gcry_mpi_release(xprime_i);
			gcry_sexp_release(key);
			delete dkg, delete dss, delete rbc, delete vtmf, delete aiou, delete aiou2;
			exit(-1);
		}
		CallasDonnerhackeFinneyShawThayerRFC4880::
			PacketSsbEncodeExperimental109(ckeytime, p, q, g, h, y,	n, t, i,
				qualsize, qual, v_i, c_ik, x_i, xprime_i, passphrase, ssb);
		gcry_mpi_release(h);
		gcry_mpi_release(n);
		gcry_mpi_release(t);
		gcry_mpi_release(i);
		gcry_mpi_release(qualsize);
		for (size_t j = 0; j < qual.size(); j++)
			gcry_mpi_release(qual[j]);
		for (size_t j = 0; j < v_i.size(); j++)
			gcry_mpi_release(v_i[j]);
		for (size_t j = 0; j < c_ik.size(); j++)
			for (size_t k = 0; k < c_ik[j].size(); k++)
				gcry_mpi_release(c_ik[j][k]);
		gcry_mpi_release(x_i);
		gcry_mpi_release(xprime_i);
		gcry_mpi_release(y);
		elgflags.push_back(0x04 | 0x10); // key may be used to encrypt communications and has been split by a secret-sharing mechanism
		if (S > 0)
			sigtime = ckeytime; // use common key creation time as OpenPGP signature creation time
		else
			sigtime = time(NULL); // otherwise use current time
		// Subkey Binding Signature (0x18) of sub
		CallasDonnerhackeFinneyShawThayerRFC4880::
			PacketSigPrepareSelfSignature(TMCG_OPENPGP_SIGNATURE_SUBKEY_BINDING,
				hashalgo, sigtime, keyexptime, elgflags, keyid, subsig_hashing);
		for (size_t i = 6; i < sub.size(); i++)
			sub_hashing.push_back(sub[i]);
		hash.clear();
		CallasDonnerhackeFinneyShawThayerRFC4880::
			KeyHash(pub_hashing, sub_hashing, subsig_hashing, hashalgo, hash,
				subsig_left);
		if (S > 0)
		{
			tmcg_openpgp_byte_t buffer[1024];
			gcry_mpi_t h;
			size_t buflen = 0;
			memset(buffer, 0, sizeof(buffer));
			for (size_t i = 0; ((i < hash.size()) && (i < sizeof(buffer))); i++, buflen++)
				buffer[i] = hash[i];
			ret = gcry_mpi_scan(&h, GCRYMPI_FMT_USG, buffer, buflen, NULL);
			if (ret)
			{
				std::cerr << "ERROR: P_" << whoami << ": gcry_mpi_scan() failed for h" << std::endl;
				mpz_clear(dsa_m), mpz_clear(dsa_r), mpz_clear(dsa_s);
				gcry_mpi_release(p);
				gcry_mpi_release(q);
				gcry_mpi_release(g);
				gcry_sexp_release(key);
				delete dkg, delete dss, delete rbc, delete vtmf, delete aiou, delete aiou2;
				exit(-1);
			}
			if (!mpz_set_gcry_mpi(h, dsa_m))
			{
				std::cerr << "ERROR: P_" << whoami << ": mpz_set_gcry_mpi() failed for dsa_m" << std::endl;
				gcry_mpi_release(h);
				mpz_clear(dsa_m), mpz_clear(dsa_r), mpz_clear(dsa_s);
				gcry_mpi_release(p);
				gcry_mpi_release(q);
				gcry_mpi_release(g);
				gcry_sexp_release(key);
				delete dkg, delete dss, delete rbc, delete vtmf, delete aiou, delete aiou2;
				exit(-1);
			}
			gcry_mpi_release(h);
			std::stringstream err_log_sign;
			if (opt_verbose)
				std::cerr << "INFO: P_" << whoami << ": dss.Sign() for subkey binding signature" << std::endl;
			if (!dss->Sign(peers.size(), whoami, dsa_m, dsa_r, dsa_s, aiou, rbc, err_log_sign))
			{
				std::cerr << "ERROR: P_" << whoami << ": " << "tDSS Sign() failed" << std::endl;
				std::cerr << "ERROR: P_" << whoami << ": log follows " << std::endl << err_log_sign.str();
				mpz_clear(dsa_m), mpz_clear(dsa_r), mpz_clear(dsa_s);
				gcry_mpi_release(p);
				gcry_mpi_release(q);
				gcry_mpi_release(g);
				gcry_sexp_release(key);
				delete dkg, delete dss, delete rbc, delete vtmf, delete aiou, delete aiou2;
				exit(-1);
			}
			if (opt_verbose > 1)
				std::cerr << "INFO: P_" << whoami << ": log follows " << std::endl << err_log_sign.str();
			r = gcry_mpi_new(2048);
			if (!mpz_get_gcry_mpi(r, dsa_r))
			{
				std::cerr << "ERROR: P_" << whoami << ": mpz_get_gcry_mpi() failed for dsa_r" << std::endl;
				mpz_clear(dsa_m), mpz_clear(dsa_r), mpz_clear(dsa_s);
				gcry_mpi_release(p);
				gcry_mpi_release(q);
				gcry_mpi_release(g);
				gcry_mpi_release(r);
				gcry_sexp_release(key);
				delete dkg, delete dss, delete rbc, delete vtmf, delete aiou, delete aiou2;
				exit(-1);
			}
			s = gcry_mpi_new(2048);
			if (!mpz_get_gcry_mpi(s, dsa_s))
			{
				std::cerr << "ERROR: P_" << whoami << ": mpz_get_gcry_mpi() failed for dsa_s" << std::endl;
				mpz_clear(dsa_m), mpz_clear(dsa_r), mpz_clear(dsa_s);
				gcry_mpi_release(p);
				gcry_mpi_release(q);
				gcry_mpi_release(g);
				gcry_mpi_release(r);
				gcry_mpi_release(s);
				gcry_sexp_release(key);
				delete dkg, delete dss, delete rbc, delete vtmf, delete aiou, delete aiou2;
				exit(-1);
			}
		}
		else
		{
			r = gcry_mpi_new(2048);
			s = gcry_mpi_new(2048);
			ret = CallasDonnerhackeFinneyShawThayerRFC4880::
				AsymmetricSignDSA(hash, key, r, s);
			if (ret)
			{
				std::cerr << "ERROR: P_" << whoami << ": CallasDonnerhackeFinneyShawThayerRFC4880::AsymmetricSignDSA() failed" << std::endl;
				mpz_clear(dsa_m), mpz_clear(dsa_r), mpz_clear(dsa_s);
				gcry_mpi_release(p);
				gcry_mpi_release(q);
				gcry_mpi_release(g);
				gcry_mpi_release(r);
				gcry_mpi_release(s);
				gcry_sexp_release(key);
				delete dkg, delete dss, delete rbc, delete vtmf, delete aiou, delete aiou2;
				exit(-1);
			}
		}
		CallasDonnerhackeFinneyShawThayerRFC4880::
			PacketSigEncode(subsig_hashing, subsig_left, r, s, subsig);
		gcry_mpi_release(r);
		gcry_mpi_release(s);
	}
	mpz_clear(dsa_m), mpz_clear(dsa_r), mpz_clear(dsa_s);
	gcry_mpi_release(p);
	gcry_mpi_release(q);
	gcry_mpi_release(g);
	gcry_sexp_release(key);
	
	// at the end: deliver some more rounds for still waiting parties
	time_t synctime = aiounicast::aio_timeout_long;
	if (opt_verbose)
		std::cerr << "INFO: P_" << whoami << ": waiting approximately " <<
			(synctime * (T_RBC + 1)) << " seconds for stalled parties" <<
			std::endl;
	rbc->Sync(synctime);

	// export generated public keys in OpenPGP armor format
	std::stringstream pubfilename;
	pubfilename << peers[whoami] << "_dkg-pub.asc";
	armor = "", all.clear();
	all.insert(all.end(), pub.begin(), pub.end());
	all.insert(all.end(), uid.begin(), uid.end());
	all.insert(all.end(), uidsig.begin(), uidsig.end());
	all.insert(all.end(), sub.begin(), sub.end());
	all.insert(all.end(), subsig.begin(), subsig.end());
	CallasDonnerhackeFinneyShawThayerRFC4880::
		ArmorEncode(TMCG_OPENPGP_ARMOR_PUBLIC_KEY_BLOCK, all, armor);
	if (opt_verbose > 1)
		std::cout << armor << std::endl;
	std::ofstream pubofs((pubfilename.str()).c_str(), std::ofstream::out);
	if (!pubofs.good())
	{
		std::cerr << "ERROR: P_" << whoami << ": opening public key file failed" << std::endl;
		delete dkg, delete dss, delete rbc, delete vtmf, delete aiou, delete aiou2;
		exit(-1);
	}
	pubofs << armor;
	if (!pubofs.good())
	{
		std::cerr << "ERROR: P_" << whoami << ": writing public key file failed" << std::endl;
		delete dkg, delete dss, delete rbc, delete vtmf, delete aiou, delete aiou2;
		exit(-1);
	}
	pubofs.close();

	// export generated private keys in OpenPGP armor format
	std::stringstream secfilename;
	secfilename << peers[whoami] << "_dkg-sec.asc";
	armor = "", all.clear();
	all.insert(all.end(), sec.begin(), sec.end());
	all.insert(all.end(), uid.begin(), uid.end());
	all.insert(all.end(), uidsig.begin(), uidsig.end());
	all.insert(all.end(), ssb.begin(), ssb.end());
	all.insert(all.end(), subsig.begin(), subsig.end());
	CallasDonnerhackeFinneyShawThayerRFC4880::
		ArmorEncode(TMCG_OPENPGP_ARMOR_PRIVATE_KEY_BLOCK, all, armor);
	if (opt_verbose > 1)
		std::cout << armor << std::endl;
	if (!create_strict_permissions((secfilename.str()).c_str()))
	{
		if (errno == EEXIST)
		{
			if (!check_strict_permissions((secfilename.str()).c_str()))
			{
				std::cerr << "WARNING: weak permissions of existing private key file detected" << std::endl;
				if (!set_strict_permissions((secfilename.str()).c_str()))
				{
					std::cerr << "ERROR: P_" << whoami << ": setting permissions for private key file failed" << std::endl;
					delete dkg, delete dss, delete rbc, delete vtmf, delete aiou, delete aiou2;
					exit(-1);
				}
			}
			std::cerr << "WARNING: existing private key file have been overwritten" << std::endl;
		}
		else
		{
			std::cerr << "ERROR: P_" << whoami << ": creating private key file failed" << std::endl;
			delete dkg, delete dss, delete rbc, delete vtmf, delete aiou, delete aiou2;
			exit(-1);
		}
	}
	std::ofstream secofs((secfilename.str()).c_str(), std::ofstream::out);
	if (!secofs.good())
	{
		std::cerr << "ERROR: P_" << whoami << ": opening private key file failed" << std::endl;
		delete dkg, delete dss, delete rbc, delete vtmf, delete aiou, delete aiou2;
		exit(-1);
	}
	secofs << armor;
	if (!secofs.good())
	{
		std::cerr << "ERROR: P_" << whoami << ": writing private key file failed" << std::endl;
		delete dkg, delete dss, delete rbc, delete vtmf, delete aiou, delete aiou2;
		exit(-1);
	}
	secofs.close();

	// release DKG
	delete dkg;

	// release tDSS
	delete dss;

	// release RBC			
	delete rbc;

	// release VTMF
	delete vtmf;
			
	// release handles (unicast channel)
	uP_in.clear(), uP_out.clear(), uP_key.clear();
	if (opt_verbose)
		std::cerr << "INFO: P_" << whoami << ": aiou.numRead = " << aiou->numRead <<
			" aiou.numWrite = " << aiou->numWrite << std::endl;

	// release handles (broadcast channel)
	bP_in.clear(), bP_out.clear(), bP_key.clear();
	if (opt_verbose)
		std::cerr << "INFO: P_" << whoami << ": aiou2.numRead = " << aiou2->numRead <<
			" aiou2.numWrite = " << aiou2->numWrite << std::endl;

	// release asynchronous unicast and broadcast
	delete aiou, delete aiou2;
}

bool fips_verify
	(mpz_srcptr fips_p, mpz_srcptr fips_q, mpz_srcptr fips_g,
	mpz_srcptr fips_hashalgo, mpz_srcptr fips_dps, mpz_srcptr fips_counter, mpz_srcptr fips_index)
{
		// 1. $L = \mathbf{len}(p)$.
		size_t fips_L = mpz_sizeinbase(fips_p, 2L);
		// 2. $N = \mathbf{len}(q)$.
		size_t fips_N = mpz_sizeinbase(fips_q, 2L);
		// 3. Check that the $(L, N)$ pair is in the list of acceptable $(L, N)$ pairs.
		//    If the pair is not in the list, the return INVALID.
		if (!((fips_L == 2048) && (fips_N == 256)) && !((fips_L == 3072) && (fips_N == 256)))
			return false;
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
		mpz_fhash(U, mpz_get_ui(fips_hashalgo), fips_dps);
		mpz_tdiv_r_2exp(U, U, fips_N - 1);
		// 8. $computed\_q = 2^{N-1} + U + 1 - (U \bmod 2)$.
		mpz_set_ui(computed_q, 1L);
		mpz_mul_2exp(computed_q, computed_q, fips_N - 1);
		mpz_add(computed_q, computed_q, U);
		mpz_add_ui(computed_q, computed_q, 1L);
		if (mpz_odd_p(U))
			mpz_sub_ui(computed_q, computed_q, 1L);
		// 9. Test whether or not $computed\_q$ is prime as specified in Appendix C.3.
		//    If $(computed\_q \neq q)$ or ($computed\_q$ is not prime), the return INVALID.
		if (mpz_cmp(computed_q, fips_q) || !mpz_probab_prime_p(computed_q, 56))
		{
			mpz_clear(U), mpz_clear(computed_q);
			return false;
		}
		// 10. $n = \lceil L / outlen \rceil - 1$.
		size_t fips_n = (fips_L / (mpz_fhash_len(mpz_get_ui(fips_hashalgo)) * 8)) - 1;
		// 11. $b = L - 1 - (n * outlen)$.
		size_t fips_b = fips_L - 1 - (fips_n * mpz_fhash_len(mpz_get_ui(fips_hashalgo)) * 8);
		// 12. $offset = 1$.
		size_t fips_offset = 1;
		// 13. For $i = 0$ to $counter$ do
		mpz_t q2, W, X, c, computed_p;
		mpz_init(q2), mpz_init(W), mpz_init(X), mpz_init(c), mpz_init(computed_p);
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
				// $V_j = \mathbf{Hash}((domain_parameter_seed + offset + j) \bmod 2^{seedlen})$.
				mpz_t tmp;
				mpz_init_set(tmp, fips_dps);
				mpz_add_ui(tmp, tmp, fips_offset);
				mpz_add_ui(tmp, tmp, j);
				mpz_tdiv_r_2exp(tmp, tmp, fips_seedlen);
				mpz_fhash(V_j[j], mpz_get_ui(fips_hashalgo), tmp);
				mpz_clear(tmp);
			}
			// 13.2 $W = V_0 + (V_1 * 2^{outlen}) + \cdots + (V_{n-1} * 2^{(n-1)*outlen}) + ((V_n \bmod 2^b) * 2^{n*outlen})$.
			mpz_set_ui(W, 0L);
			for (size_t j = 0; j <= fips_n; j++)
			{
				mpz_t tmp;
				mpz_init_set(tmp, V_j[j]);
				if (j == fips_n)
					mpz_tdiv_r_2exp(tmp, tmp, fips_b);
				mpz_mul_2exp(tmp, tmp, (j * mpz_fhash_len(mpz_get_ui(fips_hashalgo)) * 8));
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
			// 13.7 Test whether or not $computed\_p$ is prime as specified in Appendix C.3.
			// 13.8 If $computed\_p$ is determined to be prime, then go to step 14. 
			if (mpz_probab_prime_p(computed_p, 56))
				break;
			// 13.9 $offset = offset + n + 1$.
			fips_offset += (fips_n + 1);
		}
		// 14. If ($(i \neq counter)$ or $(computed\_p \neq p)$ or ($computed\_p$ is not a prime)),
		//     then return INVALID.
		if ((fips_i != mpz_get_ui(fips_counter)) || mpz_cmp(computed_p, fips_p) || !mpz_probab_prime_p(computed_p, 56))
		{
			mpz_clear(U), mpz_clear(computed_q), mpz_clear(q2), mpz_clear(W), mpz_clear(X), mpz_clear(c), mpz_clear(computed_p);
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
			mpz_clear(U), mpz_clear(computed_q), mpz_clear(q2), mpz_clear(W), mpz_clear(X), mpz_clear(c), mpz_clear(computed_p);
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
			mpz_clear(U), mpz_clear(computed_q), mpz_clear(q2), mpz_clear(W), mpz_clear(X), mpz_clear(c), mpz_clear(computed_p);
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
			mpz_clear(U), mpz_clear(computed_q), mpz_clear(q2), mpz_clear(W), mpz_clear(X), mpz_clear(c), mpz_clear(computed_p);
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
				mpz_clear(U), mpz_clear(computed_q), mpz_clear(q2), mpz_clear(W), mpz_clear(X), mpz_clear(c), mpz_clear(computed_p);
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
			mpz_fhash_ggen(W, mpz_get_ui(fips_hashalgo), fips_dps, "ggen", fips_index, count);
			// 11. $computed\_g = W^e \bmod p$.
			mpz_powm(computed_g, W, e, fips_p);
			// 12. If $(computed\_g < 2)$, the go to step 7.
			if (mpz_cmp_ui(computed_g, 2L) < 0)
				continue;
			// 13. If $(computed\_g = g)$, then return VALID, else return INVALID.
			if (mpz_cmp(computed_g, fips_g))
			{
				mpz_clear(U), mpz_clear(computed_q), mpz_clear(q2), mpz_clear(W), mpz_clear(X), mpz_clear(c), mpz_clear(computed_p);
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
		mpz_clear(U), mpz_clear(computed_q), mpz_clear(q2), mpz_clear(W), mpz_clear(X), mpz_clear(c), mpz_clear(computed_p);
		for (size_t j = 0; j <= fips_n; j++)
		{
			mpz_clear(V_j[j]);
			delete [] V_j[j];
		}
		V_j.clear();
		mpz_clear(e), mpz_clear(count), mpz_clear(computed_g);
		return true;
}

#ifdef GNUNET
char *gnunet_opt_crs = NULL;
char *gnunet_opt_hostname = NULL;
char *gnunet_opt_passwords = NULL;
char *gnunet_opt_port = NULL;
unsigned int gnunet_opt_t_resilience = DKGPG_MAX_N;
unsigned int gnunet_opt_s_resilience = DKGPG_MAX_N;
unsigned int gnunet_opt_keyexptime = 0;
unsigned int gnunet_opt_xtests = 0;
unsigned int gnunet_opt_wait = 5;
unsigned int gnunet_opt_W = opt_W;
int gnunet_opt_verbose = 0;
#endif

void fork_instance
	(const size_t whoami)
{
	if ((pid[whoami] = fork()) < 0)
		perror("ERROR: dkg-generate (fork)");
	else
	{
		if (pid[whoami] == 0)
		{
			/* BEGIN child code: participant P_i */
			time_t keytime = time(NULL);
#ifdef GNUNET
			run_instance(whoami, keytime, gnunet_opt_keyexptime, gnunet_opt_xtests);
#else
			run_instance(whoami, keytime, opt_e, 0);
#endif
			if (opt_verbose)
				std::cerr << "INFO: P_" << whoami << ": exit(0)" << std::endl;
			exit(0);
			/* END child code: participant P_i */
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
	// setup CRS (common reference string) |p| = 3072 bit, |q| = 256 bit
	// The domain parameters of the underlying fixed group have been
	// generated by the author. You can run dkg-gencrs and then use the
	// option "-g" to employ your own domain parameter set.
	static std::string crs = "fips-crs|etc0k13hu6mDWyye0MUepXvXJf1M6Uqt13"
		"mAyAEhJ292TMOxG5HilFlFaG2YUIXsPISxWKjZqBY0VO6YjF1DIGsIzQ6GK9"
		"Myk9MGSVxP44lfjVIodRRFk2anRLktvO2Kcq0Z6hP3yvQNmM0sl5JTvzrJLt"
		"WDk3B7W3D9WTEjLRqBw3ULUlQz1pVCQELXaUcz8AOZv5iGAec9Vyf2YyWA8L"
		"xvVZXcLEemvD7ompIVuQM1Baos9fXqs3AmegAKPZdEQUCU5LdTeNvLOq5J2c"
		"Yx4jWMqVJlOyDdlMtdOXzzz59m58atKxN9RG5npkNshxk7zDfd0NOM9wyFfT"
		"wfVakACyp1so0osIDPGtJgVSqCDf5f2KOMRHrScAayCkTSAaWiPn8fFAOuDT"
		"UGiZS9Sj8ftSvT3yo6MooyNVd6U90BwQE2OAuTe7GPLE8cBu7sGjOMK8bkXc"
		"TuSSnGeV77LEiRUyd2Egqrkz84arBDerBdZgONliQiTK1YjF4COMXDpLixuR"
		"iN|kNJC9FeFYk5xs7d0bwhA2xoxbrUPLMvalMXmHHD3wNn|PY8SlRuWwjTAV"
		"1e99wxssLrNXcRWTxIFoKIP5RAyZLqZGct2M3wXURqAmtagS6MDl7PPWQ3ju"
		"pFYHxkGtv2MwROsB9cQVHmH9xspZ9ERFAbE8qNtpLeHHMUqFD9S7GZi1QwuY"
		"ryqrlj8nhZCfAOaQLA08Z7Ki36wlGmTaY9iTIRy4cZkdSjOwxT5kOcp0Y0yg"
		"5sWo5M4vSOdQeVf92qzgmFYbL77OX3M0xwQkTTDy8ITrFlEJEBClAZmTMc55"
		"opm4bKb7tvrr07YtUknMX0IaRW7eBWUjmnAMx09bPjFpA9NWMorqqzvKnU02"
		"PRTGpuROhFVg64BXS2X8Oj7Y8aRsejljzjMz7fXOVpNfCXlUBNNgkkURvSOj"
		"vs55mHzqrkoup9f5Fma5zTRYpwD2YJSczEytU2wZaTLxQrMkwZhhpFDiuxC7"
		"7x7soBo1ynYtD8AJtWDYdkmU6bSxPBSYRXCOD3BJnvAApNogQQx49TG254ve"
		"asLh5kDXSllYkKqv3hJOFV6|sfrJREYoxAPXzCHLjNOyabkDzpQxlMul6wWe"
		"X4Zqu7dIjkWg5PdlTrPk8QIaMX2DWSttERDAfxUaWmtCFNxSjGUV3jb0H1fv"
		"0DjviPfHYQyVKOTHHjtkEopPAP8TvkQdVV4CWyTYZ0O2fwlEGOCMDZBbjGjn"
		"rfEOeptn08B3OwA9MYbCq958LTIdIta8b1KDnr2ckTKCbpTazJgq4LUrFOZC"
		"tKMk2ZlKXeN0X3iWb8oEG3JPE3kJGuzQQ44Wnx7ZzzLohDhGSUMgXULUezB8"
		"EUVnXpq7oIaYqjAachOTmaQpPSygbBWAhwnvRB2LhoJQpLNUzTgJ8vh4DALd"
		"u3gsuR7cthjS6vGqcq84aMJJ8ypoqA8wpEDenc9xjmZ4bc9EZCyZShSLeIyY"
		"ymv7CFgtuiCyjFUBXjfM928Tar27a4mDpAhluUoXa0O5VfV70e04LlnzgQ8w"
		"RtCqfaGcWesaHzPEk|8|DKGPGdkgpgDKGPGdkgpgDKGPGdkgpgDKGPGdkgpg"
		"DKGST|38|1k|";
	static const char *usage = "dkg-generate [OPTIONS] PEERS";
#ifdef GNUNET
	char *loglev = NULL;
	char *logfile = NULL;
	char *cfg_fn = NULL;
	static const struct GNUNET_GETOPT_CommandLineOption options[] = {
		GNUNET_GETOPT_option_cfgfile(&cfg_fn),
		GNUNET_GETOPT_option_help(about),
		GNUNET_GETOPT_option_uint('e',
			"expiration",
			"TIME",
			"expiration time of generated keys in seconds",
			&gnunet_opt_keyexptime
		),
		GNUNET_GETOPT_option_string('g',
			"group",
			"STRING",
			"common reference string that defines the underlying DDH-hard group",
			&gnunet_opt_crs
		),
		GNUNET_GETOPT_option_string('H',
			"hostname",
			"STRING",
			"hostname (e.g. onion address) of this peer within PEERS",
			&gnunet_opt_hostname
		),
		GNUNET_GETOPT_option_logfile(&logfile),
		GNUNET_GETOPT_option_loglevel(&loglev),
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
		GNUNET_GETOPT_option_uint('s',
			"s-resilience",
			"INTEGER",
			"resilience of threshold DSS protocol (signature scheme)",
			&gnunet_opt_s_resilience
		),
		GNUNET_GETOPT_option_uint('t',
			"t-resilience",
			"INTEGER",
			"resilience of DKG protocol (threshold decryption)",
			&gnunet_opt_t_resilience
		),
		GNUNET_GETOPT_option_version(version),
		GNUNET_GETOPT_option_flag('V',
			"verbose",
			"turn on verbose output",
			&gnunet_opt_verbose
		),
		GNUNET_GETOPT_option_uint('w',
			"wait",
			"TIME",
			"minutes to wait until start of key generation protocol",
			&gnunet_opt_wait
		),
		GNUNET_GETOPT_option_uint('W',
			"aiou-timeout",
			"TIME",
			"timeout for point-to-point messages in minutes",
			&gnunet_opt_W
		),
		GNUNET_GETOPT_option_uint('x',
			"x-tests",
			NULL,
			"number of exchange tests",
			&gnunet_opt_xtests
		),
		GNUNET_GETOPT_OPTION_END
	};
	if (GNUNET_STRINGS_get_utf8_args(argc, argv, &argc, &argv) != GNUNET_OK)
	{
		std::cerr << "ERROR: GNUNET_STRINGS_get_utf8_args() failed" << std::endl;
    		return -1;
	}
	if (GNUNET_GETOPT_run(usage, options, argc, argv) == GNUNET_SYSERR)
	{
		std::cerr << "ERROR: GNUNET_GETOPT_run() failed" << std::endl;
		return -1;
	}
	if (gnunet_opt_crs != NULL)
		opt_crs = gnunet_opt_crs;
	if (gnunet_opt_passwords != NULL)
		opt_passwords = gnunet_opt_passwords;
	if (gnunet_opt_hostname != NULL)
		opt_hostname = gnunet_opt_hostname;
	if (gnunet_opt_crs != NULL)
		crs = gnunet_opt_crs; // get different CRS from GNUnet options
	if (gnunet_opt_passwords != NULL)
		passwords = gnunet_opt_passwords; // get passwords from GNUnet options
	if (gnunet_opt_hostname != NULL)
		hostname = gnunet_opt_hostname; // get hostname from GNUnet options
	if (gnunet_opt_W != opt_W)
		opt_W = gnunet_opt_W; // get aiou message timeout from GNUnet options
#endif


	// create peer list from remaining arguments
	for (size_t i = 0; i < (size_t)(argc - 1); i++)
	{
		std::string arg = argv[i+1];
		// ignore options
		if ((arg.find("-c") == 0) || (arg.find("-p") == 0) || (arg.find("-t") == 0) || (arg.find("-w") == 0) || (arg.find("-W") == 0) || 
			(arg.find("-L") == 0) || (arg.find("-l") == 0) || (arg.find("-g") == 0) || (arg.find("-x") == 0) ||
			(arg.find("-s") == 0) || (arg.find("-e") == 0) || (arg.find("-P") == 0) || (arg.find("-H") == 0))
		{
			size_t idx = ++i;
			if ((arg.find("-g") == 0) && (idx < (size_t)(argc - 1)) && (opt_crs == NULL))
			{
				crs = argv[i+1]; // overwrite included CRS
				opt_crs = (char*)crs.c_str();
			}
			if ((arg.find("-H") == 0) && (idx < (size_t)(argc - 1)) && (opt_hostname == NULL))
			{
				hostname = argv[i+1];
				opt_hostname = (char*)hostname.c_str();
			}
			if ((arg.find("-P") == 0) && (idx < (size_t)(argc - 1)) && (opt_passwords == NULL))
			{
				passwords = argv[i+1];
				opt_passwords = (char*)passwords.c_str();
			}
			if ((arg.find("-t") == 0) && (idx < (size_t)(argc - 1)) && (opt_t == DKGPG_MAX_N))
				opt_t = strtoul(argv[i+1], NULL, 10);
			if ((arg.find("-s") == 0) && (idx < (size_t)(argc - 1)) && (opt_s == DKGPG_MAX_N))
				opt_s = strtoul(argv[i+1], NULL, 10);
			if ((arg.find("-e") == 0) && (idx < (size_t)(argc - 1)) && (opt_e == 0))
				opt_e = strtoul(argv[i+1], NULL, 10);
			if ((arg.find("-p") == 0) && (idx < (size_t)(argc - 1)) && (port.length() == 0))
				port = argv[i+1];
			if ((arg.find("-W") == 0) && (idx < (size_t)(argc - 1)) && (opt_W == 5))
				opt_W = strtoul(argv[i+1], NULL, 10);
			continue;
		}
		else if ((arg.find("--") == 0) || (arg.find("-v") == 0) || (arg.find("-h") == 0) || (arg.find("-V") == 0))
		{
			if ((arg.find("-h") == 0) || (arg.find("--help") == 0))
			{
#ifndef GNUNET
				std::cout << usage << std::endl;
				std::cout << about << std::endl;
				std::cout << "Arguments mandatory for long options are also mandatory for short options." << std::endl;
				std::cout << "  -h, --help     print this help" << std::endl;
				std::cout << "  -e TIME        expiration time of generated keys in seconds" << std::endl;
				std::cout << "  -g STRING      common reference string that defines underlying DDH-hard group" << std::endl;
				std::cout << "  -H STRING      hostname (e.g. onion address) of this peer within PEERS" << std::endl;
				std::cout << "  -p INTEGER     start port for built-in TCP/IP message exchange service" << std::endl; 
				std::cout << "  -P STRING      exchanged passwords to protect private and broadcast channels" << std::endl;
				std::cout << "  -s INTEGER     resilience of threshold DSS protocol (signature scheme)" << std::endl;
				std::cout << "  -t INTEGER     resilience of DKG protocol (threshold decryption)" << std::endl;
				std::cout << "  -v, --version  print the version number" << std::endl;
				std::cout << "  -V, --verbose  turn on verbose output" << std::endl;
				std::cout << "  -W TIME        timeout for point-to-point messages in minutes" << std::endl;
#endif
				return 0; // not continue
			}
			if ((arg.find("-v") == 0) || (arg.find("--version") == 0))
			{
#ifndef GNUNET
				std::cout << "dkg-generate v" << version << " without GNUNET support" << std::endl;
#endif
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
	peers.push_back("Test2");
	peers.push_back("Test3");
	peers.push_back("Test4");
	opt_verbose = 1;
	opt_e = 7200;
	if (mpz_wrandom_ui() % 2)
	{
		// sometimes test a non-FIPS CRS
		crs = "crs|VMyMoPc2vb51ofxb4f2rebOSONnfhitfGcYxdav2D4wqBTeZrC"
			"E000000000000000000000000000000000000000000000000000"
			"0000000000000000000000000000000000000000000000000000"
			"0000000000000000000000000000000000000000000000000000"
			"0000000000000000000000000000000000000000000000000000"
			"0000000000000000000000000000000000000000000000000000"
			"0000000000000000000000000000000001|uDwReTJvQLAzuFRRO"
			"6qqtd1MvZaQaSBxTzKOJjAbUA3|UQ51BEgx2Et2uVFsRwcj6wvIh"
			"Vr78A3nWht7i9COt8bRjAd3bLFE4f2j6ueWjGusTW6n2mwczSpCV"
			"f0jzpvou6Rt3B3AlNbJJC8i4436z63OiLco2wNsC8DxDq6mCe1Bi"
			"Jeatdes9sV29tH9G4nMtI4RZi1Tcb4DZBJm1LehNGJVmXqznonEZ"
			"UTAyHfuoxf02P0rc4z4rPRM8a80sqTwYLEzHfcJsTs9Qvp8jwbhb"
			"VscxTGxItIkOWDTHm7H3JH5kMDRwGJBTeAmPztoOkGq7BOUlpKxi"
			"NWe4fVKzn7CMyvVyQyvcbJwMP8WqtJfuZamgKASsekXDRt62JUC5"
			"MCOuuCd|YakYaYak000000000000000000000000000000000000"
			"0000000000000000000000000000000000000000000000000000"
			"0000000000000000000000000000000000000000000000000000"
			"0000000000000000000000000000000000000000000000000000"
			"0000000000000000000000000000000000000000000000000000"
			"0000000000000000000000000000000000000000000000000|";
	}
#endif

	// check command line arguments
	if ((opt_hostname != NULL) && (opt_passwords == NULL))
	{
		std::cerr << "ERROR: option \"-P\" is necessary due to insecure network" << std::endl;
		return -1;
	}
	if (peers.size() < 1)
	{
		std::cerr << "ERROR: no peers given as argument; usage: " << usage << std::endl;
		return -1;
	}

	// canonicalize peer list and setup threshold values
	std::sort(peers.begin(), peers.end());
	std::vector<std::string>::iterator it = std::unique(peers.begin(), peers.end());
	peers.resize(std::distance(peers.begin(), it));
	T = (peers.size() - 1) / 2; // default: maximum t-resilience for DKG (RBC is not affected by this)
	S = (peers.size() - 1) / 2; // default: maximum s-resilience for tDSS (RBC is also not affected by this)
	if ((peers.size() < 3)  || (peers.size() > DKGPG_MAX_N))
	{
		std::cerr << "ERROR: too few or too many peers given" << std::endl;
		return -1;
	}
	if (opt_verbose)
	{
		std::cerr << "INFO: canonicalized peer list = " << std::endl;
		for (size_t i = 0; i < peers.size(); i++)
			std::cerr << peers[i] << std::endl;
	}

	// lock memory
	if (!lock_memory())
	{
		std::cerr << "WARNING: locking memory failed; CAP_IPC_LOCK required for memory protection" << std::endl;
		// at least try to use libgcrypt's secure memory
		if (!gcry_check_version(TMCG_LIBGCRYPT_VERSION))
		{
			std::cerr << "ERROR: libgcrypt version >= " << TMCG_LIBGCRYPT_VERSION << " required" << std::endl;
			return -1;
		}
		gcry_control(GCRYCTL_SUSPEND_SECMEM_WARN);
		gcry_control(GCRYCTL_USE_SECURE_RNDPOOL);
		gcry_control(GCRYCTL_INIT_SECMEM, 16384, 0);
		gcry_control(GCRYCTL_RESUME_SECMEM_WARN);
		gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
		libgcrypt_secmem = true;
	}

	// initialize LibTMCG
	if (!init_libTMCG())
	{
		std::cerr << "ERROR: initialization of LibTMCG failed" << std::endl;
		return -1;
	}
	if (opt_verbose)
		std::cerr << "INFO: using LibTMCG version " << version_libTMCG() << std::endl;

	// read userid and passphrase
#ifdef DKGPG_TESTSUITE
	userid = "TestGroup <testing@localhost>";
	passphrase = "Test";
#else
	std::cerr << "1. Please enter an OpenPGP-style user ID (name <email>): ";
	std::getline(std::cin, userid);
	std::cin.clear();
	std::string passphrase_check;
	do
	{
		passphrase = "", passphrase_check = "";
		if (!get_passphrase("2. Passphrase to protect your part of the private key", passphrase))
			return -1;
		if (!get_passphrase("Please repeat the given passphrase to continue", passphrase_check))
			return -1;
		if (passphrase != passphrase_check)
			std::cerr << "WARNING: passphrase does not match; please try again" << std::endl;
		else if (passphrase == "")
			std::cerr << "WARNING: no key protection due to empty passphrase" << std::endl;
	}
	while (passphrase != passphrase_check);
#endif

#ifdef GNUNET
	if (gnunet_opt_t_resilience != DKGPG_MAX_N)
		T = gnunet_opt_t_resilience; // get value of T from GNUnet options
	if (gnunet_opt_s_resilience != DKGPG_MAX_N)
		S = gnunet_opt_s_resilience; // get value of S from GNUnet options
#else
	if (opt_t != DKGPG_MAX_N)
		T = opt_t; // get vaule of T from options
	if (opt_s != DKGPG_MAX_N)
		S = opt_s; // get vaule of S from options
#endif
	if (T >= peers.size())
		T = (peers.size() - 1); // apply an upper limit on T
	if (S > ((peers.size() - 1) / 2))
		S = (peers.size() - 1) / 2; // apply an upper limit on S
	// check magic of CRS (common reference string)
	if (TMCG_ParseHelper::cm(crs, "crs", '|'))
	{
		if (opt_verbose)
			std::cerr << "INFO: verifying domain parameters (according to LibTMCG::VTMF constructor)" << std::endl;
	}
	else if (TMCG_ParseHelper::cm(crs, "fips-crs", '|'))
	{
		if (opt_verbose)
			std::cerr << "INFO: verifying domain parameters (according to FIPS 186-4 section A.1.1.2)" << std::endl;
		fips = true;
	}
	else
	{
		std::cerr << "ERROR: common reference string (CRS) is not valid!" << std::endl;
		return -1;
	}
	// parse p, q, g, k from CRS
	std::string mpz_str;
	mpz_t crsmpz, fips_p, fips_q, fips_g;
	mpz_init(crsmpz), mpz_init(fips_p), mpz_init(fips_q), mpz_init(fips_g);
	for (size_t i = 0; i < 4; i++)
	{
		if (!TMCG_ParseHelper::gs(crs, '|', mpz_str))
		{
			std::cerr << "ERROR: common reference string (CRS) is corrupted!" << std::endl;
			mpz_clear(crsmpz), mpz_clear(fips_p), mpz_clear(fips_q), mpz_clear(fips_g);
			return -1;
		}
		else if ((mpz_set_str(crsmpz, mpz_str.c_str(), TMCG_MPZ_IO_BASE) < 0) || !TMCG_ParseHelper::nx(crs, '|'))
		{
			std::cerr << "ERROR: common reference string (CRS) is corrupted!" << std::endl;
			mpz_clear(crsmpz), mpz_clear(fips_p), mpz_clear(fips_q), mpz_clear(fips_g);
			return -1;
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
			std::cerr << " (" << mpz_sizeinbase(crsmpz, 2L) << " bits) = " << crsmpz << std::endl;
	}
	mpz_clear(crsmpz);
	if (fips)
	{
		mpz_t fips_hashalgo, fips_dps, fips_counter, fips_index;
		mpz_init_set_ui(fips_hashalgo, 0L), mpz_init_set_ui(fips_dps, 0L);
		mpz_init_set_ui(fips_counter, 0L), mpz_init_set_ui(fips_index, 0L);
		if (!TMCG_ParseHelper::gs(crs, '|', mpz_str))
		{
			std::cerr << "ERROR: common reference string (CRS) is corrupted!" << std::endl;
			mpz_clear(fips_p), mpz_clear(fips_q), mpz_clear(fips_g);
			mpz_clear(fips_hashalgo), mpz_clear(fips_dps), mpz_clear(fips_counter), mpz_clear(fips_index);
			return -1;
		}
		if ((mpz_set_str(fips_hashalgo, mpz_str.c_str(), TMCG_MPZ_IO_BASE) < 0) || !TMCG_ParseHelper::nx(crs, '|'))
		{
			std::cerr << "ERROR: common reference string (CRS) is corrupted!" << std::endl;
			mpz_clear(fips_p), mpz_clear(fips_q), mpz_clear(fips_g);
			mpz_clear(fips_hashalgo), mpz_clear(fips_dps), mpz_clear(fips_counter), mpz_clear(fips_index);
			return -1;
		}
		if (!TMCG_ParseHelper::gs(crs, '|', mpz_str))
		{
			std::cerr << "ERROR: common reference string (CRS) is corrupted!" << std::endl;
			mpz_clear(fips_p), mpz_clear(fips_q), mpz_clear(fips_g);
			mpz_clear(fips_hashalgo), mpz_clear(fips_dps), mpz_clear(fips_counter), mpz_clear(fips_index);
			return -1;
		}
		if ((mpz_set_str(fips_dps, mpz_str.c_str(), TMCG_MPZ_IO_BASE) < 0) || (!TMCG_ParseHelper::nx(crs, '|')))
		{
			std::cerr << "ERROR: common reference string (CRS) is corrupted!" << std::endl;
			mpz_clear(fips_p), mpz_clear(fips_q), mpz_clear(fips_g);
			mpz_clear(fips_hashalgo), mpz_clear(fips_dps), mpz_clear(fips_counter), mpz_clear(fips_index);
			return -1;
		}
		if (!TMCG_ParseHelper::gs(crs, '|', mpz_str))
		{
			std::cerr << "ERROR: common reference string (CRS) is corrupted!" << std::endl;
			mpz_clear(fips_p), mpz_clear(fips_q), mpz_clear(fips_g);
			mpz_clear(fips_hashalgo), mpz_clear(fips_dps), mpz_clear(fips_counter), mpz_clear(fips_index);
			return -1;
		}
		if ((mpz_set_str(fips_counter, mpz_str.c_str(), TMCG_MPZ_IO_BASE) < 0) || (!TMCG_ParseHelper::nx(crs, '|')))
		{
			std::cerr << "ERROR: common reference string (CRS) is corrupted!" << std::endl;
			mpz_clear(fips_p), mpz_clear(fips_q), mpz_clear(fips_g);
			mpz_clear(fips_hashalgo), mpz_clear(fips_dps), mpz_clear(fips_counter), mpz_clear(fips_index);
			return -1;
		}
		if (!TMCG_ParseHelper::gs(crs, '|', mpz_str))
		{
			std::cerr << "ERROR: common reference string (CRS) is corrupted!" << std::endl;
			mpz_clear(fips_p), mpz_clear(fips_q), mpz_clear(fips_g);
			mpz_clear(fips_hashalgo), mpz_clear(fips_dps), mpz_clear(fips_counter), mpz_clear(fips_index);
			return -1;
		}
		if ((mpz_set_str(fips_index, mpz_str.c_str(), TMCG_MPZ_IO_BASE) < 0) || (!TMCG_ParseHelper::nx(crs, '|')))
		{
			std::cerr << "ERROR: common reference string (CRS) is corrupted!" << std::endl;
			mpz_clear(fips_p), mpz_clear(fips_q), mpz_clear(fips_g);
			mpz_clear(fips_hashalgo), mpz_clear(fips_dps), mpz_clear(fips_counter), mpz_clear(fips_index);
			return -1;
		}
		if (mpz_get_ui(fips_hashalgo) != GCRY_MD_SHA256) 
		{
			std::cerr << "ERROR: hash function is not approved according to FIPS 186-4!" << std::endl;
			mpz_clear(fips_p), mpz_clear(fips_q), mpz_clear(fips_g);
			mpz_clear(fips_hashalgo), mpz_clear(fips_dps), mpz_clear(fips_counter), mpz_clear(fips_index);
			return -1;
		}
		// check the domain parameters according to FIPS 186-4 sections A.1.1.3 and A.2.4
		if (!fips_verify(fips_p, fips_q, fips_g, fips_hashalgo, fips_dps, fips_counter, fips_index))
		{
			std::cerr << "ERROR: domain parameters are not set according to FIPS 186-4!" << std::endl;
			mpz_clear(fips_p), mpz_clear(fips_q), mpz_clear(fips_g);
			mpz_clear(fips_hashalgo), mpz_clear(fips_dps), mpz_clear(fips_counter), mpz_clear(fips_index);
			return -1;
		}
		// release
		mpz_clear(fips_hashalgo), mpz_clear(fips_dps), mpz_clear(fips_counter), mpz_clear(fips_index);
	}
	// initialize cache
	std::cerr << "3. We need a lot of entropy to cache very strong randomness for key generation." << std::endl;
	std::cerr << "   Please use other programs, move the mouse, and type on your keyboard: " << std::endl; 
	mpz_ssrandomm_cache_init(cache, cache_mod, &cache_avail, ((2 * (S + 1)) + (2 * (T + 1))), fips_q);
	std::cerr << "Thank you!" << std::endl;
	mpz_clear(fips_p), mpz_clear(fips_q), mpz_clear(fips_g);
	// initialize return code
	int ret = 0;
	// create underlying point-to-point channels, if built-in TCP/IP service requested
	if (opt_hostname != NULL)
	{
		if (port.length())
			opt_p = strtoul(port.c_str(), NULL, 10); // get start port from options
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
		// release cache
		mpz_ssrandomm_cache_done(cache, cache_mod, &cache_avail);
		// finish
		return ret;
	}

#ifdef GNUNET
	static const struct GNUNET_GETOPT_CommandLineOption myoptions[] = {
		GNUNET_GETOPT_option_uint('e',
			"expiration",
			"TIME",
			"expiration time of generated keys in seconds",
			&gnunet_opt_keyexptime
		),
		GNUNET_GETOPT_option_string('g',
			"group",
			"STRING",
			"common reference string that defines the underlying DDH-hard group",
			&gnunet_opt_crs
		),
		GNUNET_GETOPT_option_string('H',
			"hostname",
			"STRING",
			"hostname (e.g. onion address) of this peer within PEERS",
			&gnunet_opt_hostname
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
		GNUNET_GETOPT_option_uint('s',
			"s-resilience",
			"INTEGER",
			"resilience of threshold DSS protocol (signature scheme)",
			&gnunet_opt_s_resilience
		),
		GNUNET_GETOPT_option_uint('t',
			"t-resilience",
			"INTEGER",
			"resilience of DKG protocol (threshold decryption)",
			&gnunet_opt_t_resilience
		),
		GNUNET_GETOPT_option_flag('V',
			"verbose",
			"turn on verbose output",
			&gnunet_opt_verbose
		),
		GNUNET_GETOPT_option_uint('w',
			"wait",
			"TIME",
			"minutes to wait until start of key generation protocol",
			&gnunet_opt_wait
		),
		GNUNET_GETOPT_option_uint('W',
			"aiou-timeout",
			"TIME",
			"timeout for point-to-point messages in minutes",
			&gnunet_opt_W
		),
		GNUNET_GETOPT_option_uint('x',
			"x-tests",
			NULL,
			"number of exchange tests",
			&gnunet_opt_xtests
		),
		GNUNET_GETOPT_OPTION_END
	};
	ret = GNUNET_PROGRAM_run(argc, argv, usage, about, myoptions, &gnunet_run, argv[0]);
	GNUNET_free((void *) argv);
	// release cache
	mpz_ssrandomm_cache_done(cache, cache_mod, &cache_avail);
	// finish
	if (ret == GNUNET_OK)
		return 0;
	else
		return -1;
#else
	std::cerr << "WARNING: GNUnet CADET is required for the message exchange of this program" << std::endl;
#endif

	std::cerr << "INFO: running local test with " << peers.size() << " participants" << std::endl;
	std::cerr << "WARNING: due to cache issues the generated shares are identical, don't use them!" << std::endl;
	// open pipes
	for (size_t i = 0; i < peers.size(); i++)
	{
		for (size_t j = 0; j < peers.size(); j++)
		{
			if (pipe(pipefd[i][j]) < 0)
				perror("ERROR: dkg-generate (pipe)");
			if (pipe(broadcast_pipefd[i][j]) < 0)
				perror("ERROR: dkg-generate (pipe)");
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
			perror("ERROR: dkg-generate (waitpid)");
		if (!WIFEXITED(wstatus))
		{
			std::cerr << "ERROR: protocol instance ";
			if (WIFSIGNALED(wstatus))
				std::cerr << pid[i] << " terminated by signal " << WTERMSIG(wstatus) << std::endl;
			if (WCOREDUMP(wstatus))
				std::cerr << pid[i] << " dumped core" << std::endl;
			ret = -1; // fatal error
		}
		else if (WIFEXITED(wstatus))
		{
			if (opt_verbose)
				std::cerr << "INFO: protocol instance " << pid[i] << " terminated with exit status " << WEXITSTATUS(wstatus) << std::endl;
			if (WEXITSTATUS(wstatus))
				ret = -2; // error
		}
		for (size_t j = 0; j < peers.size(); j++)
		{
			if ((close(pipefd[i][j][0]) < 0) || (close(pipefd[i][j][1]) < 0))
				perror("ERROR: dkg-generate (close)");
			if ((close(broadcast_pipefd[i][j][0]) < 0) || (close(broadcast_pipefd[i][j][1]) < 0))
				perror("ERROR: dkg-generate (close)");
		}
	}
	
	// release cache
	mpz_ssrandomm_cache_done(cache, cache_mod, &cache_avail);
	// finish
	return ret;
}

