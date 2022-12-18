/*******************************************************************************
   This file is part of Distributed Privacy Guard (DKGPG).

 Copyright (C) 2017, 2018, 2019, 2022  Heiko Stamer <HeikoStamer@gmx.net>

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
#ifdef DKGPG_TESTSUITE_Y
	#undef GNUNET
#endif
#ifdef DKGPG_TESTSUITE_TS
	#undef GNUNET
#endif

// copy infos from DKGPG package before overwritten by GNUnet headers
static const char *version = PACKAGE_VERSION " (" PACKAGE_NAME ")";
static const char *about = PACKAGE_STRING " " PACKAGE_URL;
static const char *protocol = "DKGPG-generate-1.1";

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
#include "dkg-common.hh"

int							pipefd[DKGPG_MAX_N][DKGPG_MAX_N][2];
int							self_pipefd[2];
int							broadcast_pipefd[DKGPG_MAX_N][DKGPG_MAX_N][2];
int							broadcast_self_pipefd[2];
pid_t						pid[DKGPG_MAX_N];
std::vector<std::string>	peers;
bool						instance_forked = false;

tmcg_openpgp_secure_string_t	passphrase;
std::vector<std::string>		userid;
std::string						passwords, hostname, port;
int 							opt_verbose = 0;
bool							opt_y = false, opt_timestamping = false;
bool							opt_nopassphrase = false, opt_rfc4880bis = true; 
unsigned long int				opt_t = DKGPG_MAX_N, opt_s = DKGPG_MAX_N;
unsigned long int				opt_e = 0, opt_p = 55000, opt_W = 5;

bool							fips = false, rfc = false;
std::stringstream				crss;
mpz_t 							cache[TMCG_MAX_SSRANDOMM_CACHE], cache_mod;
size_t							cache_avail = 0;

size_t							T, S;

void run_instance
	(const size_t whoami, const time_t keytime, const time_t keyexptime,
	 const size_t num_xtests)
{
	if (opt_y)
	{
		// create VTMF instance from CRS
		BarnettSmartVTMF_dlog *vtmf;
		if (fips)
		{
			vtmf = new BarnettSmartVTMF_dlog(crss, TMCG_DDH_SIZE, TMCG_DLSE_SIZE,
				false); // without VTMF-verifiable generation of $g$ (FIPS mode)
		}
		else if (rfc)
		{
			vtmf = new BarnettSmartVTMF_dlog_GroupQR(crss, TMCG_DDH_SIZE,
				TMCG_DLSE_SIZE);
		}
		else
		{
			vtmf = new BarnettSmartVTMF_dlog(crss, TMCG_DDH_SIZE, TMCG_DLSE_SIZE,
				true); // with VTMF-verifiable generation of $g$ (VTMF-vgog)
		}
		// check the constructed VTMF instance
		if (!vtmf->CheckGroup())
		{
			std::cerr << "ERROR: group G from CRS is bad" << std::endl;
			delete vtmf;
			exit(-1);
		}
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
			std::cerr << "ERROR: selecting hash algorithm failed for |q| = " <<
				mpz_sizeinbase(vtmf->q, 2L) << std::endl;
			delete vtmf;
			exit(-1);
		}
		// generate a non-shared DSA primary key
		mpz_t dsa_y, dsa_x;
		mpz_init(dsa_y), mpz_init(dsa_x);
		tmcg_mpz_ssrandomm_cache(cache, cache_mod, cache_avail, dsa_x, vtmf->q);
		tmcg_mpz_spowm(dsa_y, vtmf->g, dsa_x, vtmf->p);
		// extract parameters for OpenPGP key structures
		std::string armor;
		tmcg_openpgp_octets_t all, pub, sec, dirsig;
		tmcg_openpgp_octets_t sub, ssb, subsig, dsaflags, elgflags, issuer;
		tmcg_openpgp_octets_t pub_hashing, sub_hashing;
		tmcg_openpgp_octets_t dirsig_hashing, dirsig_left;
		tmcg_openpgp_octets_t subsig_hashing, subsig_left;
		tmcg_openpgp_octets_t hash, empty;
		time_t sigtime;
		gcry_sexp_t key;
		gcry_mpi_t p, q, g, y, x, r, s;
		gcry_error_t ret;
		p = gcry_mpi_new(2048);
		if (!tmcg_mpz_get_gcry_mpi(p, vtmf->p))
		{
			std::cerr << "ERROR: tmcg_mpz_get_gcry_mpi() failed" << std::endl;
			mpz_clear(dsa_y), mpz_clear(dsa_x);
			gcry_mpi_release(p);
			delete vtmf;
			exit(-1);
		}
		q = gcry_mpi_new(2048);
		if (!tmcg_mpz_get_gcry_mpi(q, vtmf->q))
		{
			std::cerr << "ERROR: tmcg_mpz_get_gcry_mpi() failed" << std::endl;
			mpz_clear(dsa_y), mpz_clear(dsa_x);
			gcry_mpi_release(p);
			gcry_mpi_release(q);
			delete vtmf;
			exit(-1);
		}
		g = gcry_mpi_new(2048);
		if (!tmcg_mpz_get_gcry_mpi(g, vtmf->g))
		{
			std::cerr << "ERROR: tmcg_mpz_get_gcry_mpi() failed" << std::endl;
			mpz_clear(dsa_y), mpz_clear(dsa_x);
			gcry_mpi_release(p);
			gcry_mpi_release(q);
			gcry_mpi_release(g);
			delete vtmf;
			exit(-1);
		}
		y = gcry_mpi_new(2048);
		if (!tmcg_mpz_get_gcry_mpi(y, dsa_y))
		{
			std::cerr << "ERROR: tmcg_mpz_get_gcry_mpi() failed" << std::endl;
			mpz_clear(dsa_y), mpz_clear(dsa_x);
			gcry_mpi_release(p);
			gcry_mpi_release(q);
			gcry_mpi_release(g);
			gcry_mpi_release(y);
			delete vtmf;
			exit(-1);
		}
		x = gcry_mpi_snew(2048);
		if (!tmcg_mpz_get_gcry_mpi(x, dsa_x))
		{
			std::cerr << "ERROR: tmcg_mpz_get_gcry_mpi() failed" << std::endl;
			mpz_clear(dsa_y), mpz_clear(dsa_x);
			gcry_mpi_release(p);
			gcry_mpi_release(q);
			gcry_mpi_release(g);
			gcry_mpi_release(y);
			gcry_mpi_release(x);
			delete vtmf;
			exit(-1);
		}
		mpz_clear(dsa_y), mpz_clear(dsa_x);
		size_t erroff;
		ret = gcry_sexp_build(&key, &erroff,
			"(key-data (public-key (dsa (p %M) (q %M) (g %M) (y %M)))"
			" (private-key (dsa (p %M) (q %M) (g %M) (y %M) (x %M))))",
			p, q, g, y, p, q, g, y, x);
		if (ret)
		{
			std::cerr << "ERROR: gcry_sexp_build() failed" << std::endl;
			gcry_mpi_release(p);
			gcry_mpi_release(q);
			gcry_mpi_release(g);
			gcry_mpi_release(y);
			gcry_mpi_release(x);
			delete vtmf;
			exit(-1);
		}
		CallasDonnerhackeFinneyShawThayerRFC4880::
			PacketPubEncode(keytime, TMCG_OPENPGP_PKALGO_DSA, p, q, g, y, pub);
		CallasDonnerhackeFinneyShawThayerRFC4880::
			PacketSecEncode(keytime, TMCG_OPENPGP_PKALGO_DSA, p, q, g, y, x,
				passphrase, sec);
		CallasDonnerhackeFinneyShawThayerRFC4880::
			PacketBodyExtract(pub, 0, pub_hashing);
		CallasDonnerhackeFinneyShawThayerRFC4880::
			FingerprintCompute(pub_hashing, issuer);
		std::vector<tmcg_openpgp_octets_t> uid, uidsig;
		uid.resize(userid.size());
		uidsig.resize(userid.size());
		for (size_t i = 0; i < userid.size(); i++)
		{
			CallasDonnerhackeFinneyShawThayerRFC4880::
				PacketUidEncode(userid[i], uid[i]);
		}
		dsaflags.push_back(0x01 | 0x02);
		if (opt_timestamping)
		{
			// FIXME: openpgp-wg: the first octet of usage flags should be zero?
			dsaflags.push_back(0x08); // "This key may be used for timestamping"
		}
		sigtime = time(NULL); // current time
		CallasDonnerhackeFinneyShawThayerRFC4880::
			PacketSigPrepareDesignatedRevoker(TMCG_OPENPGP_PKALGO_DSA, hashalgo,
				sigtime, dsaflags, issuer, (tmcg_openpgp_pkalgo_t)0, empty,
				opt_rfc4880bis, dirsig_hashing);
		hash.clear();
		CallasDonnerhackeFinneyShawThayerRFC4880::
			KeyHash(pub_hashing, dirsig_hashing, hashalgo, hash, dirsig_left);
		r = gcry_mpi_new(2048);
		s = gcry_mpi_new(2048);
		ret = CallasDonnerhackeFinneyShawThayerRFC4880::
			AsymmetricSignDSA(hash, key, r, s);
		if (ret)
		{
			std::cerr << "ERROR: AsymmetricSignDSA() failed" << std::endl;
			gcry_mpi_release(p);
			gcry_mpi_release(q);
			gcry_mpi_release(g);
			gcry_mpi_release(y);
			gcry_mpi_release(x);
			gcry_mpi_release(r);
			gcry_mpi_release(s);
			gcry_sexp_release(key);
			delete vtmf;
			exit(-1);
		}
		CallasDonnerhackeFinneyShawThayerRFC4880::
			PacketSigEncode(dirsig_hashing, dirsig_left, r, s, dirsig);
		gcry_mpi_release(r);
		gcry_mpi_release(s);
		for (size_t i = 0; i < uid.size(); i++)
		{
			tmcg_openpgp_octets_t uidsig_hashing, uidsig_left;
			CallasDonnerhackeFinneyShawThayerRFC4880::
				PacketSigPrepareSelfSignature(TMCG_OPENPGP_SIGNATURE_POSITIVE_CERTIFICATION,
					TMCG_OPENPGP_PKALGO_DSA, hashalgo, sigtime, keyexptime,
					dsaflags, issuer, opt_rfc4880bis, uidsig_hashing); 
			hash.clear();
			CallasDonnerhackeFinneyShawThayerRFC4880::
				CertificationHash(pub_hashing, userid[i], empty, uidsig_hashing,
				hashalgo, hash, uidsig_left);
			r = gcry_mpi_new(2048);
			s = gcry_mpi_new(2048);
			ret = CallasDonnerhackeFinneyShawThayerRFC4880::
				AsymmetricSignDSA(hash, key, r, s);
			if (ret)
			{
				std::cerr << "ERROR: AsymmetricSignDSA() failed" << std::endl;
				gcry_mpi_release(p);
				gcry_mpi_release(q);
				gcry_mpi_release(g);
				gcry_mpi_release(y);
				gcry_mpi_release(x);
				gcry_mpi_release(r);
				gcry_mpi_release(s);
				gcry_sexp_release(key);
				delete vtmf;
				exit(-1);
			}
			CallasDonnerhackeFinneyShawThayerRFC4880::
				PacketSigEncode(uidsig_hashing, uidsig_left, r, s, uidsig[i]);
			gcry_mpi_release(r);
			gcry_mpi_release(s);
		}
		gcry_mpi_release(x);
		gcry_mpi_release(y);
		// generate a non-shared ElGamal subkey with same domain parameter set
		mpz_t elg_y, elg_x;
		mpz_init(elg_y), mpz_init(elg_x);
		tmcg_mpz_ssrandomm_cache(cache, cache_mod, cache_avail, elg_x, vtmf->q);
		tmcg_mpz_spowm(elg_y, vtmf->g, elg_x, vtmf->p);
		// extract further parameters for OpenPGP key structures
		y = gcry_mpi_new(2048);
		if (!tmcg_mpz_get_gcry_mpi(y, elg_y))
		{
			std::cerr << "ERROR: tmcg_mpz_get_gcry_mpi() failed" << std::endl;
			mpz_clear(elg_y), mpz_clear(elg_x);
			gcry_mpi_release(p);
			gcry_mpi_release(q);
			gcry_mpi_release(g);
			gcry_mpi_release(y);
			gcry_sexp_release(key);
			delete vtmf;
			exit(-1);
		}
		x = gcry_mpi_snew(2048);
		if (!tmcg_mpz_get_gcry_mpi(x, elg_x))
		{
			std::cerr << "ERROR: tmcg_mpz_get_gcry_mpi() failed" << std::endl;
			mpz_clear(elg_y), mpz_clear(elg_x);
			gcry_mpi_release(p);
			gcry_mpi_release(q);
			gcry_mpi_release(g);
			gcry_mpi_release(y);
			gcry_mpi_release(x);
			delete vtmf;
			exit(-1);
		}
		mpz_clear(elg_y), mpz_clear(elg_x);
		CallasDonnerhackeFinneyShawThayerRFC4880::
			PacketSubEncode(keytime, TMCG_OPENPGP_PKALGO_ELGAMAL, p, q, g, y,
				sub);
		CallasDonnerhackeFinneyShawThayerRFC4880::
			PacketSsbEncode(keytime, TMCG_OPENPGP_PKALGO_ELGAMAL, p, q, g, y,
				x, passphrase, ssb);
		gcry_mpi_release(x);
		gcry_mpi_release(y);
		elgflags.push_back(0x04 | 0x08);
		sigtime = time(NULL); // current time
		// Subkey Binding Signature (0x18) of sub
		CallasDonnerhackeFinneyShawThayerRFC4880::
			PacketSigPrepareSelfSignature(TMCG_OPENPGP_SIGNATURE_SUBKEY_BINDING,
				TMCG_OPENPGP_PKALGO_DSA, hashalgo, sigtime, keyexptime,
				elgflags, issuer, opt_rfc4880bis, subsig_hashing);
		CallasDonnerhackeFinneyShawThayerRFC4880::
			PacketBodyExtract(sub, 0, sub_hashing);
		hash.clear();
		CallasDonnerhackeFinneyShawThayerRFC4880::
			KeyHash(pub_hashing, sub_hashing, subsig_hashing, hashalgo, hash,
				subsig_left);
		r = gcry_mpi_new(2048);
		s = gcry_mpi_new(2048);
		ret = CallasDonnerhackeFinneyShawThayerRFC4880::
			AsymmetricSignDSA(hash, key, r, s);
		if (ret)
		{
			std::cerr << "ERROR: AsymmetricSignDSA() failed" << std::endl;
			gcry_mpi_release(p);
			gcry_mpi_release(q);
			gcry_mpi_release(g);
			gcry_mpi_release(r);
			gcry_mpi_release(s);
			gcry_sexp_release(key);
			delete vtmf;
			exit(-1);
		}
		CallasDonnerhackeFinneyShawThayerRFC4880::
			PacketSigEncode(subsig_hashing, subsig_left, r, s, subsig);
		gcry_mpi_release(r);
		gcry_mpi_release(s);
		// release
		gcry_mpi_release(p);
		gcry_mpi_release(q);
		gcry_mpi_release(g);
		gcry_sexp_release(key);
		delete vtmf;
		// export generated public keys in OpenPGP armor format
		std::stringstream pubfilename;
		pubfilename << peers[whoami] << "-pub.asc";
		armor = "", all.clear();
		all.insert(all.end(), pub.begin(), pub.end());
		all.insert(all.end(), dirsig.begin(), dirsig.end());
		for (size_t i = 0; i < uid.size(); i++)
		{
			all.insert(all.end(), uid[i].begin(), uid[i].end());
			all.insert(all.end(), uidsig[i].begin(), uidsig[i].end());
		}
		all.insert(all.end(), sub.begin(), sub.end());
		all.insert(all.end(), subsig.begin(), subsig.end());
		CallasDonnerhackeFinneyShawThayerRFC4880::
			ArmorEncode(TMCG_OPENPGP_ARMOR_PUBLIC_KEY_BLOCK, all, armor);
		if (opt_verbose > 1)
			std::cout << armor << std::endl;
		std::ofstream pubofs((pubfilename.str()).c_str(), std::ofstream::out);
		if (!pubofs.good())
		{
			std::cerr << "ERROR: opening public key file failed" << std::endl;
			exit(-1);
		}
		pubofs << armor;
		if (!pubofs.good())
		{
			std::cerr << "ERROR: writing public key file failed" << std::endl;
			exit(-1);
		}
		pubofs.close();
		// export generated private keys in OpenPGP armor format
		std::stringstream secfilename;
		secfilename << peers[whoami] << "-sec.asc";
		armor = "", all.clear();
		all.insert(all.end(), sec.begin(), sec.end());
		all.insert(all.end(), dirsig.begin(), dirsig.end());
		for (size_t i = 0; i < uid.size(); i++)
		{
			all.insert(all.end(), uid[i].begin(), uid[i].end());
			all.insert(all.end(), uidsig[i].begin(), uidsig[i].end());
		}
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
					std::cerr << "WARNING: weak permissions of existing" <<
						" private key file detected" << std::endl;
					if (!set_strict_permissions((secfilename.str()).c_str()))
					{
						std::cerr << "ERROR: setting permissions for" <<
						" private key file failed" << std::endl;
						exit(-1);
					}
				}
				std::cerr << "WARNING: existing private key file has been" <<
					" overwritten" << std::endl;
			}
			else
			{
				std::cerr << "ERROR: creating private key file failed" <<
					std::endl;
				exit(-1);
			}
		}
		std::ofstream secofs((secfilename.str()).c_str(), std::ofstream::out);
		if (!secofs.good())
		{
			std::cerr << "ERROR: opening private key file failed" << std::endl;
			exit(-1);
		}
		secofs << armor;
		if (!secofs.good())
		{
			std::cerr << "ERROR: writing private key file failed" << std::endl;
			exit(-1);
		}
		secofs.close();
		exit(0);
	}

	// create communication handles for all players
	std::vector<int> uP_in, uP_out, bP_in, bP_out;
	std::vector<std::string> uP_key, bP_key;
	for (size_t i = 0; i < peers.size(); i++)
	{
		std::stringstream key;
		if (passwords.length() > 0)
		{
			std::string pwd;
			if (!TMCG_ParseHelper::gs(passwords, '/', pwd))
			{
				std::cerr << "ERROR: P_" << whoami << ": " << "cannot read" <<
					" password for protecting channel to P_" << i << std::endl;
				exit(-1);
			}
			key << pwd;
			if (((i + 1) < peers.size()) &&
				!TMCG_ParseHelper::nx(passwords, '/'))
			{
				std::cerr << "ERROR: P_" << whoami << ": " << "cannot skip" <<
					" to next password for protecting channel to P_" <<
					(i + 1) << std::endl;
				exit(-1);
			}
		}
		else
		{
			// use simple key -- we assume that GNUnet provides secure channels
			key << "dkg-generate::P_" << (i + whoami);
		}
		if (i == whoami)
			uP_in.push_back(self_pipefd[0]);
		else
			uP_in.push_back(pipefd[i][whoami][0]);
		uP_out.push_back(pipefd[whoami][i][1]);
		uP_key.push_back(key.str());
		if (i == whoami)
			bP_in.push_back(broadcast_self_pipefd[0]);
		else
			bP_in.push_back(broadcast_pipefd[i][whoami][0]);
		bP_out.push_back(broadcast_pipefd[whoami][i][1]);
		bP_key.push_back(key.str());
	}

	// create VTMF instance from CRS
	BarnettSmartVTMF_dlog *vtmf;
	if (fips)
	{
		vtmf = new BarnettSmartVTMF_dlog(crss, TMCG_DDH_SIZE, TMCG_DLSE_SIZE,
			false); // without VTMF-verifiable generation of $g$ (FIPS mode)
	}
	else if (rfc)
	{
		vtmf = new BarnettSmartVTMF_dlog_GroupQR(crss, TMCG_DDH_SIZE,
			TMCG_DLSE_SIZE);
	}
	else
	{
		vtmf = new BarnettSmartVTMF_dlog(crss, TMCG_DDH_SIZE, TMCG_DLSE_SIZE,
			true); // with VTMF-verifiable generation of $g$ (VTMF-vgog)
	}
	// check the constructed VTMF instance
	if (!vtmf->CheckGroup())
	{
		std::cerr << "ERROR: P_" << whoami << ": " << "group G from CRS is" <<
			" incorrectly generated!" << std::endl;
		delete vtmf;
		exit(-1);
	}

	// create asynchronous authenticated unicast channels
	aiounicast_select *aiou = new aiounicast_select(peers.size(), whoami,
		uP_in, uP_out, uP_key, aiounicast::aio_scheduler_roundrobin,
		(opt_W * 60));

	// create asynchronous authenticated unicast channels for broadcast protocol
	aiounicast_select *aiou2 = new aiounicast_select(peers.size(), whoami,
		bP_in, bP_out, bP_key, aiounicast::aio_scheduler_roundrobin,
		(opt_W * 60));
			
	// create an instance of a reliable broadcast protocol (RBC)
	std::string myID = "dkg-generate|" + std::string(protocol) + "|";
	for (size_t i = 0; i < peers.size(); i++)
		myID += peers[i] + "|";
	// include parameters in the ID of broadcast protocol to enforce equal set
	std::stringstream myss;
	myss << T << "|" << S << "|";
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
			
	// create and exchange temporary VTMF keys in order to bootstrap the
	// $h$-generation for tElG and tDSS/DSA protocols [JL00]
	if (opt_verbose)
	{
		std::cerr << "INFO: generate h by using VTMF key generation protocol" <<
			 std::endl;
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
				std::cerr << "WARNING: P_" << whoami << ": no VTMF key" <<
					" received from P_" << i << std::endl;
			}
			if (!rbc->DeliverFrom(nizk_c, i))
			{
				std::cerr << "WARNING: P_" << whoami << ": no NIZK c" <<
					" received from " << i << std::endl;
			}
			if (!rbc->DeliverFrom(nizk_r, i))
			{
				std::cerr << "WARNING: P_" << whoami << ": no NIZK r" <<
					" received from " << i << std::endl;
			}
			std::stringstream l;
			l << h_j << std::endl << nizk_c << std::endl << nizk_r << std::endl;
			if (!vtmf->KeyGenerationProtocol_UpdateKey(l))
			{
				std::cerr << "WARNING: P_" << whoami << ": VTMF key of P_" <<
					i << " was not correctly generated!" << std::endl;
			}
		}
	}
	vtmf->KeyGenerationProtocol_Finalize();
	mpz_clear(nizk_c), mpz_clear(nizk_r), mpz_clear(h_j);

	// create an instance of tDSS/DSA
	CanettiGennaroJareckiKrawczykRabinDSS *dss;
	if (opt_verbose)
	{
		std::cerr << "INFO: CanettiGennaroJareckiKrawczykRabinDSS(" <<
			peers.size() << ", " << S << ", " << whoami << ", ...)" <<
			std::endl;
	}
	if (fips)
	{
		dss = new CanettiGennaroJareckiKrawczykRabinDSS(peers.size(), S, whoami,
			vtmf->p, vtmf->q, vtmf->g, vtmf->h,
			TMCG_DDH_SIZE, TMCG_DLSE_SIZE, false, true);
	}
	else
	{
		dss = new CanettiGennaroJareckiKrawczykRabinDSS(peers.size(), S, whoami,
			vtmf->p, vtmf->q, vtmf->g, vtmf->h,
			TMCG_DDH_SIZE, TMCG_DLSE_SIZE, true, true); // with VTMF-vgog
	}
	if (!dss->CheckGroup())
	{
		std::cerr << "ERROR: P_" << whoami << ": " << "tDSS parameters are" <<
			" not correctly generated!" << std::endl;
		delete dss;
		delete rbc, delete vtmf, delete aiou, delete aiou2;
		exit(-1);
	}
	if (S > 0)
	{
		// tDSS/DSA: generate shared $x$ and extract $y = g^x \bmod p$
		std::stringstream err_log;
		if (opt_verbose)
		{
			std::cerr << "INFO: P_" << whoami << ": dss.Generate()" <<
				std::endl;
		}
		if (!dss->Generate(aiou, rbc, err_log, false, cache, cache_mod,
			&cache_avail))
		{
			std::cerr << "ERROR: P_" << whoami << ": " <<
				"tDSS Generate() failed" << std::endl;
			std::cerr << "ERROR: P_" << whoami << ": log follows " <<
				std::endl << err_log.str();
			delete dss;
			delete rbc, delete vtmf, delete aiou, delete aiou2;
			exit(-1);
		}
		if (opt_verbose > 1)
		{
			std::cerr << "INFO: P_" << whoami << ": log follows " <<
				std::endl << err_log.str();
		}
	}

	// create an instance of tElG
	GennaroJareckiKrawczykRabinDKG *dkg;
	if (opt_verbose)
	{
		std::cerr << "INFO: GennaroJareckiKrawczykRabinDKG(" << peers.size() <<
			", " << T << ", " << whoami << ", ...)" << std::endl;
	}
	if (fips)
	{
		dkg = new GennaroJareckiKrawczykRabinDKG(peers.size(), T, whoami,
			vtmf->p, vtmf->q, vtmf->g, vtmf->h,
			TMCG_DDH_SIZE, TMCG_DLSE_SIZE, false, true);
	}
	else
	{
		dkg = new GennaroJareckiKrawczykRabinDKG(peers.size(), T, whoami,
			vtmf->p, vtmf->q, vtmf->g, vtmf->h,
			TMCG_DDH_SIZE, TMCG_DLSE_SIZE, true, true); // with VTMF-vgog
	}
	if (!dkg->CheckGroup())
	{
		std::cerr << "ERROR: P_" << whoami << ": " <<
			"DKG parameters are not correctly generated!" << std::endl;
		delete dkg, delete dss;
		delete rbc, delete vtmf, delete aiou, delete aiou2;
		exit(-1);
	}
	if (T > 0)
	{
		// tElG: generate shared $x$ and extract $y = g^x \bmod p$
		std::stringstream err_log;
		if (opt_verbose)
		{
			std::cerr << "INFO: P_" << whoami << ": dkg.Generate()" <<
				std::endl;
		}
		if (!dkg->Generate(aiou, rbc, err_log, false, cache, cache_mod,
			&cache_avail))
		{
			std::cerr << "ERROR: P_" << whoami << ": " <<
				"DKG Generate() failed" << std::endl;
			std::cerr << "ERROR: P_" << whoami << ": log follows " <<
				std::endl << err_log.str();
			delete dkg, delete dss;
			delete rbc, delete vtmf, delete aiou, delete aiou2;
			exit(-1);
		}
		if (opt_verbose > 1)
		{
			std::cerr << "INFO: P_" << whoami << ": log follows " <<
				std::endl << err_log.str();
		}
		// check the generated key share
		if (opt_verbose)
		{
			std::cerr << "INFO: P_" << whoami << ": dkg.CheckKey()" <<
				std::endl;
		}
		if (!dkg->CheckKey())
		{
			std::cerr << "ERROR: P_" << whoami << ": " <<
				"DKG CheckKey() failed" << std::endl;
			delete dkg, delete dss;
			delete rbc, delete vtmf, delete aiou, delete aiou2;
			exit(-1);
		}
	}

	// all participants must agree on a common key creation time (OpenPGP),
	// because otherwise key ID and subkey ID does not match
	time_t ckeytime = agree_time(keytime, whoami, peers.size(), opt_verbose,
		rbc);

	// select hash algorithm for OpenPGP based on |q| (size in bit)
	tmcg_openpgp_hashalgo_t hashalgo = TMCG_OPENPGP_HASHALGO_UNKNOWN;
	if (!select_hashalgo(dss, hashalgo))
	{
		std::cerr << "ERROR: P_" << whoami << ": selecting hash algorithm" <<
			" failed for |q| = " << mpz_sizeinbase(dss->q, 2L) << std::endl;
		delete dkg, delete dss;
		delete rbc, delete vtmf, delete aiou, delete aiou2;
		exit(-1);
	}

	// create an OpenPGP DSA-based primary key resp. ElGamal-based subkey using
	// computed values from tDSS/DSA resp. tElG protocols of LibTMCG
	mpz_t dsa_y, dsa_x, dsa_m, dsa_r, dsa_s;
	mpz_init(dsa_y), mpz_init(dsa_x);
	mpz_init(dsa_m), mpz_init(dsa_r), mpz_init(dsa_s);
	if (S > 0)
	{
		// use tDSS/DSA values for primary key, if s-resilience is not zero
		mpz_set(dsa_x, dss->x_i);
		mpz_set(dsa_y, dss->y);
	}
	else
	{
		// generate a non-shared DSA primary key, if s-resilience is zero
		tmcg_mpz_ssrandomm_cache(cache, cache_mod, cache_avail, dsa_x, vtmf->q);
		tmcg_mpz_spowm(dsa_y, vtmf->g, dsa_x, vtmf->p);
	}
	// extract further public parameters for OpenPGP key structures
	std::string armor;
	tmcg_openpgp_octets_t all, pub, sec, dirsig;
	tmcg_openpgp_octets_t sub, ssb, subsig, dsaflags, elgflags, issuer;
	tmcg_openpgp_octets_t pub_hashing, sub_hashing;
	tmcg_openpgp_octets_t dirsig_hashing, dirsig_left;
	tmcg_openpgp_octets_t subsig_hashing, subsig_left;
	tmcg_openpgp_octets_t hash, empty;
	time_t sigtime;
	gcry_sexp_t key;
	gcry_mpi_t p, q, g, y, x, r, s;
	gcry_error_t ret;
	p = gcry_mpi_new(2048);
	if (!tmcg_mpz_get_gcry_mpi(p, vtmf->p))
	{
		std::cerr << "ERROR: P_" << whoami <<
			": tmcg_mpz_get_gcry_mpi() failed for p" << std::endl;
		mpz_clear(dsa_y), mpz_clear(dsa_x);
		mpz_clear(dsa_m), mpz_clear(dsa_r), mpz_clear(dsa_s);
		gcry_mpi_release(p);
		delete dkg, delete dss;
		delete rbc, delete vtmf, delete aiou, delete aiou2;
		exit(-1);
	}
	q = gcry_mpi_new(2048);
	if (!tmcg_mpz_get_gcry_mpi(q, vtmf->q))
	{
		std::cerr << "ERROR: P_" << whoami <<
			": tmcg_mpz_get_gcry_mpi() failed for q" << std::endl;
		mpz_clear(dsa_y), mpz_clear(dsa_x);
		mpz_clear(dsa_m), mpz_clear(dsa_r), mpz_clear(dsa_s);
		gcry_mpi_release(p);
		gcry_mpi_release(q);
		delete dkg, delete dss;
		delete rbc, delete vtmf, delete aiou, delete aiou2;
		exit(-1);
	}
	g = gcry_mpi_new(2048);
	if (!tmcg_mpz_get_gcry_mpi(g, vtmf->g))
	{
		std::cerr << "ERROR: P_" << whoami <<
			": tmcg_mpz_get_gcry_mpi() failed for g" << std::endl;
		mpz_clear(dsa_y), mpz_clear(dsa_x);
		mpz_clear(dsa_m), mpz_clear(dsa_r), mpz_clear(dsa_s);
		gcry_mpi_release(p);
		gcry_mpi_release(q);
		gcry_mpi_release(g);
		delete dkg, delete dss;
		delete rbc, delete vtmf, delete aiou, delete aiou2;
		exit(-1);
	}
	y = gcry_mpi_new(2048);
	if (!tmcg_mpz_get_gcry_mpi(y, dsa_y))
	{
		std::cerr << "ERROR: P_" << whoami <<
			": tmcg_mpz_get_gcry_mpi() failed for dsa_y" << std::endl;
		mpz_clear(dsa_y), mpz_clear(dsa_x);
		mpz_clear(dsa_m), mpz_clear(dsa_r), mpz_clear(dsa_s);
		gcry_mpi_release(p);
		gcry_mpi_release(q);
		gcry_mpi_release(g);
		gcry_mpi_release(y);
		delete dkg, delete dss;
		delete rbc, delete vtmf, delete aiou, delete aiou2;
		exit(-1);
	}
	x = gcry_mpi_snew(2048);
	if (!tmcg_mpz_get_gcry_mpi(x, dsa_x))
	{
		std::cerr << "ERROR: P_" << whoami <<
			": tmcg_mpz_get_gcry_mpi() failed for dsa_x" << std::endl;
		mpz_clear(dsa_y), mpz_clear(dsa_x);
		mpz_clear(dsa_m), mpz_clear(dsa_r), mpz_clear(dsa_s);
		gcry_mpi_release(p);
		gcry_mpi_release(q);
		gcry_mpi_release(g);
		gcry_mpi_release(y);
		gcry_mpi_release(x);
		delete dkg, delete dss;
		delete rbc, delete vtmf, delete aiou, delete aiou2;
		exit(-1);
	}
	mpz_clear(dsa_y), mpz_clear(dsa_x);
	size_t erroff;
	ret = gcry_sexp_build(&key, &erroff,
		"(key-data (public-key (dsa (p %M) (q %M) (g %M) (y %M)))"
		" (private-key (dsa (p %M) (q %M) (g %M) (y %M) (x %M))))",
		p, q, g, y, p, q, g, y, x);
	if (ret)
	{
		std::cerr << "ERROR: P_" << whoami <<
			": gcry_sexp_build() failed" << std::endl;
		mpz_clear(dsa_m), mpz_clear(dsa_r), mpz_clear(dsa_s);
		gcry_mpi_release(p);
		gcry_mpi_release(q);
		gcry_mpi_release(g);
		gcry_mpi_release(y);
		gcry_mpi_release(x);
		delete dkg, delete dss;
		delete rbc, delete vtmf, delete aiou, delete aiou2;
		exit(-1);
	}
	CallasDonnerhackeFinneyShawThayerRFC4880::
		PacketPubEncode(ckeytime, TMCG_OPENPGP_PKALGO_DSA, p, q, g, y, pub);
	if (S > 0)
	{
		// create an OpenPGP private key as experimental algorithm ID 107
		// store everything required from tDSS/DSA there
		gcry_mpi_t h, n, t, i, qualsize, x_rvss_qualsize, x_i, xprime_i;
		std::vector<gcry_mpi_t> qual, x_rvss_qual;
		std::vector<std::string> capl; // canonicalized peer list
		std::vector< std::vector<gcry_mpi_t> > c_ik;
		h = gcry_mpi_new(2048);
		if (!tmcg_mpz_get_gcry_mpi(h, dss->h))
		{
			std::cerr << "ERROR: P_" << whoami <<
				": tmcg_mpz_get_gcry_mpi() failed for dss->h" << std::endl;
			mpz_clear(dsa_m), mpz_clear(dsa_r), mpz_clear(dsa_s);
			gcry_mpi_release(p);
			gcry_mpi_release(q);
			gcry_mpi_release(g);
			gcry_mpi_release(y);
			gcry_mpi_release(x);
			gcry_mpi_release(h);
			gcry_sexp_release(key);
			delete dkg, delete dss;
			delete rbc, delete vtmf, delete aiou, delete aiou2;
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
				if (!tmcg_mpz_get_gcry_mpi(tmp, dss->dkg->x_rvss->C_ik[j][k]))
				{
					std::cerr << "ERROR: P_" << whoami <<
						": tmcg_mpz_get_gcry_mpi() failed for C_ik" << std::endl;
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
					delete dkg, delete dss;
					delete rbc, delete vtmf, delete aiou, delete aiou2;
					exit(-1); 
				}
				c_ik[j].push_back(tmp);
			}
		}
		x_i = gcry_mpi_snew(2048);
		if (!tmcg_mpz_get_gcry_mpi(x_i, dss->x_i))
		{
			std::cerr << "ERROR: P_" << whoami <<
				": tmcg_mpz_get_gcry_mpi() failed for dss->x_i" << std::endl;
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
			delete dkg, delete dss;
			delete rbc, delete vtmf, delete aiou, delete aiou2;
			exit(-1);
		}
		xprime_i = gcry_mpi_snew(2048);
		if (!tmcg_mpz_get_gcry_mpi(xprime_i, dss->xprime_i))
		{
			std::cerr << "ERROR: P_" << whoami << ": tmcg_mpz_get_gcry_mpi()" <<
				" failed for dss->xprime_i" << std::endl;
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
			delete dkg, delete dss;
			delete rbc, delete vtmf, delete aiou, delete aiou2;
			exit(-1);
		}
		CallasDonnerhackeFinneyShawThayerRFC4880::
			PacketSecEncodeExperimental107(ckeytime, p, q, g, h, y, n, t, i,
				qualsize, qual, x_rvss_qualsize, x_rvss_qual, capl, c_ik,
				x_i, xprime_i, passphrase, sec);
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
	{
		CallasDonnerhackeFinneyShawThayerRFC4880::
			PacketSecEncode(ckeytime, TMCG_OPENPGP_PKALGO_DSA, p, q, g, y, x,
				passphrase, sec);
	}
	CallasDonnerhackeFinneyShawThayerRFC4880::
		PacketBodyExtract(pub, 0, pub_hashing);
	CallasDonnerhackeFinneyShawThayerRFC4880::
		FingerprintCompute(pub_hashing, issuer);
	std::vector<tmcg_openpgp_octets_t> uid, uidsig;
	uid.resize(userid.size());
	uidsig.resize(userid.size());
	for (size_t i = 0; i < userid.size(); i++)
	{
		CallasDonnerhackeFinneyShawThayerRFC4880::
			PacketUidEncode(userid[i], uid[i]);
	}
	// "In a V4 key, the primary key MUST be a key capable of certification."
	if (S > 0)
	{
		// key may be used to certify other keys, to sign data and has been
		// split by a secret-sharing mechanism
		dsaflags.push_back(0x01 | 0x02 | 0x10);
		if (opt_timestamping)
		{
			// FIXME: openpgp-wg: the first octet of usage flags should be zero?
			dsaflags.push_back(0x08); // "This key may be used for timestamping"
		}
		// reuse key creation time as signature creation time
		sigtime = ckeytime;
	}
	else
	{
		// key may be used to certify other keys and to sign data
		dsaflags.push_back(0x01 | 0x02);
		if (opt_timestamping)
		{
			// FIXME: openpgp-wg: the first octet of usage flags should be zero?
			dsaflags.push_back(0x08); // "This key may be used for timestamping"
		}
		// for a non-shared DSA primary key no common timestamp required 
		sigtime = time(NULL); // current time
	}
	// create an additional direct-key signature (0x1f) with above key flags
	// "The split key (0x10) [...] flags are placed on a self-signature only;
	//  they are meaningless on a certification signature. They SHOULD be
	//  placed only on a direct-key signature (type 0x1f) or a subkey signature
	//  (type 0x18), one that refers to the key the flag applies to." [RFC 4880]
	CallasDonnerhackeFinneyShawThayerRFC4880::
		PacketSigPrepareDesignatedRevoker(TMCG_OPENPGP_PKALGO_DSA, hashalgo,
			sigtime, dsaflags, issuer, (tmcg_openpgp_pkalgo_t)0, empty,
			opt_rfc4880bis, dirsig_hashing);
	hash.clear();
	CallasDonnerhackeFinneyShawThayerRFC4880::
		KeyHash(pub_hashing, dirsig_hashing, hashalgo, hash, dirsig_left);
	if (S > 0)
	{
		tmcg_openpgp_byte_t buffer[1024];
		gcry_mpi_t h;
		size_t buflen = 0;
		memset(buffer, 0, sizeof(buffer));
		for (size_t i = 0; i < hash.size(); i++, buflen++)
		{
			if (i < sizeof(buffer))
				buffer[i] = hash[i];
		}
		ret = gcry_mpi_scan(&h, GCRYMPI_FMT_USG, buffer, buflen, NULL);
		if (ret)
		{
			std::cerr << "ERROR: P_" << whoami <<
				": gcry_mpi_scan() failed for h" << std::endl;
			mpz_clear(dsa_m), mpz_clear(dsa_r), mpz_clear(dsa_s);
			gcry_mpi_release(p);
			gcry_mpi_release(q);
			gcry_mpi_release(g);
			gcry_mpi_release(y);
			gcry_mpi_release(x);
			gcry_sexp_release(key);
			delete dkg, delete dss;
			delete rbc, delete vtmf, delete aiou, delete aiou2;
			exit(-1);
		}
		if (!tmcg_mpz_set_gcry_mpi(h, dsa_m))
		{
			std::cerr << "ERROR: P_" << whoami <<
				": tmcg_mpz_set_gcry_mpi() failed for dsa_m" << std::endl;
			gcry_mpi_release(h);
			mpz_clear(dsa_m), mpz_clear(dsa_r), mpz_clear(dsa_s);
			gcry_mpi_release(p);
			gcry_mpi_release(q);
			gcry_mpi_release(g);
			gcry_mpi_release(y);
			gcry_mpi_release(x);
			gcry_sexp_release(key);
			delete dkg, delete dss;
			delete rbc, delete vtmf, delete aiou, delete aiou2;
			exit(-1);
		}
		gcry_mpi_release(h);
		std::stringstream err_log_sign;
		if (opt_verbose)
		{
			std::cerr << "INFO: P_" << whoami <<
				": dss.Sign() for direct-key signature (0x1f)" << std::endl;
		}
		if (!dss->Sign(peers.size(), whoami, dsa_m, dsa_r, dsa_s, aiou, rbc,
			err_log_sign))
		{
			std::cerr << "ERROR: P_" << whoami << ": tDSS Sign() failed" <<
				std::endl;
			std::cerr << "ERROR: P_" << whoami << ": log follows " <<
				std::endl << err_log_sign.str();
			mpz_clear(dsa_m), mpz_clear(dsa_r), mpz_clear(dsa_s);
			gcry_mpi_release(p);
			gcry_mpi_release(q);
			gcry_mpi_release(g);
			gcry_mpi_release(y);
			gcry_mpi_release(x);
			gcry_sexp_release(key);
			delete dkg, delete dss;
			delete rbc, delete vtmf, delete aiou, delete aiou2;
			exit(-1);
		}
		if (opt_verbose > 1)
		{
			std::cerr << "INFO: P_" << whoami << ": log follows " <<
				std::endl << err_log_sign.str();
		}
		r = gcry_mpi_new(2048);
		if (!tmcg_mpz_get_gcry_mpi(r, dsa_r))
		{
			std::cerr << "ERROR: P_" << whoami <<
				": tmcg_mpz_get_gcry_mpi() failed for dsa_r" << std::endl;
			mpz_clear(dsa_m), mpz_clear(dsa_r), mpz_clear(dsa_s);
			gcry_mpi_release(p);
			gcry_mpi_release(q);
			gcry_mpi_release(g);
			gcry_mpi_release(y);
			gcry_mpi_release(x);
			gcry_mpi_release(r);
			gcry_sexp_release(key);
			delete dkg, delete dss;
			delete rbc, delete vtmf, delete aiou, delete aiou2;
			exit(-1);
		}
		s = gcry_mpi_new(2048);
		if (!tmcg_mpz_get_gcry_mpi(s, dsa_s))
		{
			std::cerr << "ERROR: P_" << whoami <<
				": tmcg_mpz_get_gcry_mpi() failed for dsa_s" << std::endl;
			mpz_clear(dsa_m), mpz_clear(dsa_r), mpz_clear(dsa_s);
			gcry_mpi_release(p);
			gcry_mpi_release(q);
			gcry_mpi_release(g);
			gcry_mpi_release(y);
			gcry_mpi_release(x);
			gcry_mpi_release(r);
			gcry_mpi_release(s);
			gcry_sexp_release(key);
			delete dkg, delete dss;
			delete rbc, delete vtmf, delete aiou, delete aiou2;
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
			std::cerr << "ERROR: P_" << whoami <<
				": AsymmetricSignDSA() failed" << std::endl;
			mpz_clear(dsa_m), mpz_clear(dsa_r), mpz_clear(dsa_s);
			gcry_mpi_release(p);
			gcry_mpi_release(q);
			gcry_mpi_release(g);
			gcry_mpi_release(y);
			gcry_mpi_release(x);
			gcry_mpi_release(r);
			gcry_mpi_release(s);
			gcry_sexp_release(key);
			delete dkg, delete dss;
			delete rbc, delete vtmf, delete aiou, delete aiou2;
			exit(-1);
		}
	}
	CallasDonnerhackeFinneyShawThayerRFC4880::
		PacketSigEncode(dirsig_hashing, dirsig_left, r, s, dirsig);
	gcry_mpi_release(r);
	gcry_mpi_release(s);
	for (size_t i = 0; i < uid.size(); i++)
	{
		tmcg_openpgp_octets_t uidsig_hashing, uidsig_left;
		// create a positive certification (0x13) of the included user ID
		CallasDonnerhackeFinneyShawThayerRFC4880::
			PacketSigPrepareSelfSignature(TMCG_OPENPGP_SIGNATURE_POSITIVE_CERTIFICATION,
				TMCG_OPENPGP_PKALGO_DSA, hashalgo, sigtime, keyexptime,
				dsaflags, issuer, opt_rfc4880bis, uidsig_hashing); 
		hash.clear();
		CallasDonnerhackeFinneyShawThayerRFC4880::
			CertificationHash(pub_hashing, userid[i], empty, uidsig_hashing, hashalgo,
				hash, uidsig_left);
		if (S > 0)
		{
			tmcg_openpgp_byte_t buffer[1024];
			gcry_mpi_t h;
			size_t buflen = 0;
			memset(buffer, 0, sizeof(buffer));
			for (size_t i = 0; i < hash.size(); i++, buflen++)
			{
				if (i < sizeof(buffer))
					buffer[i] = hash[i];
			}
			ret = gcry_mpi_scan(&h, GCRYMPI_FMT_USG, buffer, buflen, NULL);
			if (ret)
			{
				std::cerr << "ERROR: P_" << whoami <<
					": gcry_mpi_scan() failed for h" << std::endl;
				mpz_clear(dsa_m), mpz_clear(dsa_r), mpz_clear(dsa_s);
				gcry_mpi_release(p);
				gcry_mpi_release(q);
				gcry_mpi_release(g);
				gcry_mpi_release(y);
				gcry_mpi_release(x);
				gcry_sexp_release(key);
				delete dkg, delete dss;
				delete rbc, delete vtmf, delete aiou, delete aiou2;
				exit(-1);
			}
			if (!tmcg_mpz_set_gcry_mpi(h, dsa_m))
			{
				std::cerr << "ERROR: P_" << whoami <<
					": tmcg_mpz_set_gcry_mpi() failed for dsa_m" << std::endl;
				gcry_mpi_release(h);
				mpz_clear(dsa_m), mpz_clear(dsa_r), mpz_clear(dsa_s);
				gcry_mpi_release(p);
				gcry_mpi_release(q);
				gcry_mpi_release(g);
				gcry_mpi_release(y);
				gcry_mpi_release(x);
				gcry_sexp_release(key);
				delete dkg, delete dss;
				delete rbc, delete vtmf, delete aiou, delete aiou2;
				exit(-1);
			}
			gcry_mpi_release(h);
			std::stringstream err_log_sign;
			if (opt_verbose)
			{
				std::cerr << "INFO: P_" << whoami <<
					": dss.Sign() for self signature on" <<
					" uid #" << (i+1) << std::endl;
			}
			if (!dss->Sign(peers.size(), whoami, dsa_m, dsa_r, dsa_s, aiou, rbc,
				err_log_sign))
			{
				std::cerr << "ERROR: P_" << whoami << ": tDSS Sign() failed" <<
					std::endl;
				std::cerr << "ERROR: P_" << whoami << ": log follows " <<
					std::endl << err_log_sign.str();
				mpz_clear(dsa_m), mpz_clear(dsa_r), mpz_clear(dsa_s);
				gcry_mpi_release(p);
				gcry_mpi_release(q);
				gcry_mpi_release(g);
				gcry_mpi_release(y);
				gcry_mpi_release(x);
				gcry_sexp_release(key);
				delete dkg, delete dss;
				delete rbc, delete vtmf, delete aiou, delete aiou2;
				exit(-1);
			}
			if (opt_verbose > 1)
			{
				std::cerr << "INFO: P_" << whoami << ": log follows " <<
					std::endl << err_log_sign.str();
			}
			r = gcry_mpi_new(2048);
			if (!tmcg_mpz_get_gcry_mpi(r, dsa_r))
			{
				std::cerr << "ERROR: P_" << whoami <<
					": tmcg_mpz_get_gcry_mpi() failed for dsa_r" << std::endl;
				mpz_clear(dsa_m), mpz_clear(dsa_r), mpz_clear(dsa_s);
				gcry_mpi_release(p);
				gcry_mpi_release(q);
				gcry_mpi_release(g);
				gcry_mpi_release(y);
				gcry_mpi_release(x);
				gcry_mpi_release(r);
				gcry_sexp_release(key);
				delete dkg, delete dss;
				delete rbc, delete vtmf, delete aiou, delete aiou2;
				exit(-1);
			}
			s = gcry_mpi_new(2048);
			if (!tmcg_mpz_get_gcry_mpi(s, dsa_s))
			{
				std::cerr << "ERROR: P_" << whoami <<
					": tmcg_mpz_get_gcry_mpi() failed for dsa_s" << std::endl;
				mpz_clear(dsa_m), mpz_clear(dsa_r), mpz_clear(dsa_s);
				gcry_mpi_release(p);
				gcry_mpi_release(q);
				gcry_mpi_release(g);
				gcry_mpi_release(y);
				gcry_mpi_release(x);
				gcry_mpi_release(r);
				gcry_mpi_release(s);
				gcry_sexp_release(key);
				delete dkg, delete dss;
				delete rbc, delete vtmf, delete aiou, delete aiou2;
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
				std::cerr << "ERROR: P_" << whoami <<
					": AsymmetricSignDSA() failed" << std::endl;
				mpz_clear(dsa_m), mpz_clear(dsa_r), mpz_clear(dsa_s);
				gcry_mpi_release(p);
				gcry_mpi_release(q);
				gcry_mpi_release(g);
				gcry_mpi_release(y);
				gcry_mpi_release(x);
				gcry_mpi_release(r);
				gcry_mpi_release(s);
				gcry_sexp_release(key);
				delete dkg, delete dss;
				delete rbc, delete vtmf, delete aiou, delete aiou2;
				exit(-1);
			}
		}
		CallasDonnerhackeFinneyShawThayerRFC4880::
			PacketSigEncode(uidsig_hashing, uidsig_left, r, s, uidsig[i]);
		gcry_mpi_release(r);
		gcry_mpi_release(s);
	}
	gcry_mpi_release(x);
	gcry_mpi_release(y);
	if (T > 0)
	{
		y = gcry_mpi_new(2048);
		// some parameters are computed by tElG protocols of LibTMCG
		if (!tmcg_mpz_get_gcry_mpi(y, dkg->y))
		{
			std::cerr << "ERROR: P_" << whoami <<
				": tmcg_mpz_get_gcry_mpi() failed for dkg->y" << std::endl;
			mpz_clear(dsa_m), mpz_clear(dsa_r), mpz_clear(dsa_s);
			gcry_mpi_release(p);
			gcry_mpi_release(q);
			gcry_mpi_release(g);
			gcry_mpi_release(y);
			gcry_sexp_release(key);
			delete dkg, delete dss;
			delete rbc, delete vtmf, delete aiou, delete aiou2;
			exit(-1);
		}
		CallasDonnerhackeFinneyShawThayerRFC4880::
			PacketSubEncode(ckeytime, TMCG_OPENPGP_PKALGO_ELGAMAL, p, q, g, y,
				sub); // use common key creation time
		// create an OpenPGP private subkey as experimental algorithm ID 109
		// to store everything required for tElG protocols
		gcry_mpi_t h, n, t, i, qualsize, x_i, xprime_i;
		std::vector<gcry_mpi_t> qual, v_i;
		std::vector< std::vector<gcry_mpi_t> > c_ik;
		h = gcry_mpi_new(2048);
		if (!tmcg_mpz_get_gcry_mpi(h, dkg->h))
		{
			std::cerr << "ERROR: P_" << whoami <<
				": tmcg_mpz_get_gcry_mpi() failed for dkg->h" << std::endl;
			mpz_clear(dsa_m), mpz_clear(dsa_r), mpz_clear(dsa_s);
			gcry_mpi_release(p);
			gcry_mpi_release(q);
			gcry_mpi_release(g);
			gcry_mpi_release(y);
			gcry_mpi_release(h);
			gcry_sexp_release(key);
			delete dkg, delete dss;
			delete rbc, delete vtmf, delete aiou, delete aiou2;
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
			if (!tmcg_mpz_get_gcry_mpi(v_i[j], dkg->v_i[j]))
			{
				std::cerr << "ERROR: P_" << whoami <<
					": tmcg_mpz_get_gcry_mpi() failed for dkg->v_i[j]" <<
					std::endl;
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
				delete dkg, delete dss;
				delete rbc, delete vtmf, delete aiou, delete aiou2;
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
				if (!tmcg_mpz_get_gcry_mpi(tmp, dkg->C_ik[j][k]))
				{
					std::cerr << "ERROR: P_" << whoami <<
						": tmcg_mpz_get_gcry_mpi() failed for C_ik" <<
						std::endl;
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
					delete dkg, delete dss;
					delete rbc, delete vtmf, delete aiou, delete aiou2;
					exit(-1); 
				}
				c_ik[j].push_back(tmp);
			}
		}
		x_i = gcry_mpi_snew(2048);
		if (!tmcg_mpz_get_gcry_mpi(x_i, dkg->x_i))
		{
			std::cerr << "ERROR: P_" << whoami <<
				": tmcg_mpz_get_gcry_mpi() failed for dkg->x_i" << std::endl;
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
			delete dkg, delete dss;
			delete rbc, delete vtmf, delete aiou, delete aiou2;
			exit(-1);
		}
		xprime_i = gcry_mpi_snew(2048);
		if (!tmcg_mpz_get_gcry_mpi(xprime_i, dkg->xprime_i))
		{
			std::cerr << "ERROR: P_" << whoami <<
				": tmcg_mpz_get_gcry_mpi() failed for dkg->xprime_i" << std::endl;
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
			delete dkg, delete dss;
			delete rbc, delete vtmf, delete aiou, delete aiou2;
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
		// key may be used to encrypt communications and has been split by
		// a secret-sharing mechanism
		elgflags.push_back(0x04 | 0x10);
		if (S > 0)
		{
			// use common key creation time as OpenPGP signature creation time
			sigtime = ckeytime;
		}
		else
			sigtime = time(NULL); // otherwise use current time
		// Subkey Binding Signature (0x18) of sub
		CallasDonnerhackeFinneyShawThayerRFC4880::
			PacketSigPrepareSelfSignature(TMCG_OPENPGP_SIGNATURE_SUBKEY_BINDING,
				TMCG_OPENPGP_PKALGO_DSA, hashalgo, sigtime, keyexptime,
				elgflags, issuer, opt_rfc4880bis, subsig_hashing);
		CallasDonnerhackeFinneyShawThayerRFC4880::
			PacketBodyExtract(sub, 0, sub_hashing);
		hash.clear();
		CallasDonnerhackeFinneyShawThayerRFC4880::
			KeyHash(pub_hashing, sub_hashing, subsig_hashing, hashalgo, hash,
				subsig_left);
		if (S > 0)
		{
			tmcg_openpgp_byte_t buffer[1024];
			gcry_mpi_t ha;
			size_t buflen = 0;
			memset(buffer, 0, sizeof(buffer));
			for (size_t j = 0; j < hash.size(); j++, buflen++)
			{
				if (j < sizeof(buffer))
					buffer[j] = hash[j];
			}
			ret = gcry_mpi_scan(&ha, GCRYMPI_FMT_USG, buffer, buflen, NULL);
			if (ret)
			{
				std::cerr << "ERROR: P_" << whoami <<
					": gcry_mpi_scan() failed for ha" << std::endl;
				mpz_clear(dsa_m), mpz_clear(dsa_r), mpz_clear(dsa_s);
				gcry_mpi_release(p);
				gcry_mpi_release(q);
				gcry_mpi_release(g);
				gcry_sexp_release(key);
				delete dkg, delete dss;
				delete rbc, delete vtmf, delete aiou, delete aiou2;
				exit(-1);
			}
			if (!tmcg_mpz_set_gcry_mpi(ha, dsa_m))
			{
				std::cerr << "ERROR: P_" << whoami <<
					": tmcg_mpz_set_gcry_mpi() failed for dsa_m" << std::endl;
				gcry_mpi_release(ha);
				mpz_clear(dsa_m), mpz_clear(dsa_r), mpz_clear(dsa_s);
				gcry_mpi_release(p);
				gcry_mpi_release(q);
				gcry_mpi_release(g);
				gcry_sexp_release(key);
				delete dkg, delete dss;
				delete rbc, delete vtmf, delete aiou, delete aiou2;
				exit(-1);
			}
			gcry_mpi_release(ha);
			std::stringstream err_log_sign;
			if (opt_verbose)
			{
				std::cerr << "INFO: P_" << whoami <<
					": dss.Sign() for subkey binding signature" << std::endl;
			}
			if (!dss->Sign(peers.size(), whoami, dsa_m, dsa_r, dsa_s, aiou, rbc,
				err_log_sign))
			{
				std::cerr << "ERROR: P_" << whoami << ": tDSS Sign() failed" <<
					std::endl;
				std::cerr << "ERROR: P_" << whoami << ": log follows " <<
					std::endl << err_log_sign.str();
				mpz_clear(dsa_m), mpz_clear(dsa_r), mpz_clear(dsa_s);
				gcry_mpi_release(p);
				gcry_mpi_release(q);
				gcry_mpi_release(g);
				gcry_sexp_release(key);
				delete dkg, delete dss;
				delete rbc, delete vtmf, delete aiou, delete aiou2;
				exit(-1);
			}
			if (opt_verbose > 1)
			{
				std::cerr << "INFO: P_" << whoami << ": log follows " <<
					std::endl << err_log_sign.str();
			}
			r = gcry_mpi_new(2048);
			if (!tmcg_mpz_get_gcry_mpi(r, dsa_r))
			{
				std::cerr << "ERROR: P_" << whoami <<
					": tmcg_mpz_get_gcry_mpi() failed for dsa_r" << std::endl;
				mpz_clear(dsa_m), mpz_clear(dsa_r), mpz_clear(dsa_s);
				gcry_mpi_release(p);
				gcry_mpi_release(q);
				gcry_mpi_release(g);
				gcry_mpi_release(r);
				gcry_sexp_release(key);
				delete dkg, delete dss;
				delete rbc, delete vtmf, delete aiou, delete aiou2;
				exit(-1);
			}
			s = gcry_mpi_new(2048);
			if (!tmcg_mpz_get_gcry_mpi(s, dsa_s))
			{
				std::cerr << "ERROR: P_" << whoami <<
					": tmcg_mpz_get_gcry_mpi() failed for dsa_s" << std::endl;
				mpz_clear(dsa_m), mpz_clear(dsa_r), mpz_clear(dsa_s);
				gcry_mpi_release(p);
				gcry_mpi_release(q);
				gcry_mpi_release(g);
				gcry_mpi_release(r);
				gcry_mpi_release(s);
				gcry_sexp_release(key);
				delete dkg, delete dss;
				delete rbc, delete vtmf, delete aiou, delete aiou2;
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
				std::cerr << "ERROR: P_" << whoami <<
					": AsymmetricSignDSA() failed" << std::endl;
				mpz_clear(dsa_m), mpz_clear(dsa_r), mpz_clear(dsa_s);
				gcry_mpi_release(p);
				gcry_mpi_release(q);
				gcry_mpi_release(g);
				gcry_mpi_release(r);
				gcry_mpi_release(s);
				gcry_sexp_release(key);
				delete dkg, delete dss;
				delete rbc, delete vtmf, delete aiou, delete aiou2;
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
	time_t synctime = (opt_W * 6);
	if (opt_verbose)
	{
		std::cerr << "INFO: P_" << whoami << ": waiting approximately " <<
			(synctime * (T_RBC + 1)) << " seconds for stalled parties" <<
			std::endl;
	}
	rbc->Sync(synctime);

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
	{
		std::cerr << "INFO: P_" << whoami << ": unicast channels";
		aiou->PrintStatistics(std::cerr);
		std::cerr << std::endl;
	}

	// release handles (broadcast channel)
	bP_in.clear(), bP_out.clear(), bP_key.clear();
	if (opt_verbose)
	{
		std::cerr << "INFO: P_" << whoami << ": broadcast channel";
		aiou2->PrintStatistics(std::cerr);
		std::cerr << std::endl;
	}

	// release asynchronous unicast and broadcast
	delete aiou, delete aiou2;

	// export generated public keys in OpenPGP armor format
	std::stringstream pubfilename;
	pubfilename << peers[whoami] << "_dkg-pub.asc";
	armor = "", all.clear();
	all.insert(all.end(), pub.begin(), pub.end());
	all.insert(all.end(), dirsig.begin(), dirsig.end());
	for (size_t i = 0; i < uid.size(); i++)
	{
		all.insert(all.end(), uid[i].begin(), uid[i].end());
		all.insert(all.end(), uidsig[i].begin(), uidsig[i].end());
	}
	all.insert(all.end(), sub.begin(), sub.end());
	all.insert(all.end(), subsig.begin(), subsig.end());
	CallasDonnerhackeFinneyShawThayerRFC4880::
		ArmorEncode(TMCG_OPENPGP_ARMOR_PUBLIC_KEY_BLOCK, all, armor);
	if (opt_verbose > 1)
		std::cout << armor << std::endl;
	if (!write_key_file(pubfilename.str(), armor))
		exit(-1);

	// export generated private keys in OpenPGP armor format
	std::stringstream secfilename;
	secfilename << peers[whoami] << "_dkg-sec.asc";
	std::string sfilename = secfilename.str();
	armor = "", all.clear();
	all.insert(all.end(), sec.begin(), sec.end());
	all.insert(all.end(), dirsig.begin(), dirsig.end());
	for (size_t i = 0; i < uid.size(); i++)
	{
		all.insert(all.end(), uid[i].begin(), uid[i].end());
		all.insert(all.end(), uidsig[i].begin(), uidsig[i].end());
	}
	all.insert(all.end(), ssb.begin(), ssb.end());
	all.insert(all.end(), subsig.begin(), subsig.end());
	CallasDonnerhackeFinneyShawThayerRFC4880::
		ArmorEncode(TMCG_OPENPGP_ARMOR_PRIVATE_KEY_BLOCK, all, armor);
	if (opt_verbose > 1)
		std::cout << armor << std::endl;
	if (!create_strict_permissions(sfilename))
	{
		if (errno == EEXIST)
		{
			if (!check_strict_permissions(sfilename))
			{
				std::cerr << "WARNING: weak permissions of existing private" <<
					" key file detected" << std::endl;
				if (!set_strict_permissions(sfilename))
				{
					std::cerr << "ERROR: P_" << whoami << ": setting" <<
						" permissions for private key file failed" << std::endl;
					exit(-1);
				}
			}
			std::cerr << "WARNING: existing private key file have been" <<
				" overwritten" << std::endl;
		}
		else
		{
			std::cerr << "ERROR: P_" << whoami << ": creating private key" <<
				" file failed" << std::endl;
			exit(-1);
		}
	}
	if (!write_key_file(sfilename, armor))
		exit(-1);
}

#ifdef GNUNET
char *gnunet_opt_crs = NULL;
char *gnunet_opt_hostname = NULL;
char *gnunet_opt_passwords = NULL;
char *gnunet_opt_port = NULL;
char *gnunet_opt_u = NULL;
unsigned int gnunet_opt_t_resilience = DKGPG_MAX_N;
unsigned int gnunet_opt_s_resilience = DKGPG_MAX_N;
unsigned int gnunet_opt_keyexptime = 0;
unsigned int gnunet_opt_xtests = 0;
unsigned int gnunet_opt_wait = 5;
unsigned int gnunet_opt_W = opt_W;
int gnunet_opt_verbose = 0;
int gnunet_opt_y = 0;
int gnunet_opt_timestamping = 0;
int gnunet_opt_nopassphrase = 0;
int gnunet_opt_norfc4880bis = 0;
#endif

void fork_instance
	(const size_t whoami)
{
	if ((pid[whoami] = fork()) < 0)
		perror("ERROR: dkg-generate:fork_instance (fork)");
	else
	{
		if (pid[whoami] == 0)
		{
			/* BEGIN child code: participant P_i */
			if ((self_pipefd[0] == -1) && (self_pipefd[1] == -1))
			{
				// duplication of file descriptors for run_localtest()
				self_pipefd[0] = dup(pipefd[whoami][whoami][0]);
				self_pipefd[1] = dup(pipefd[whoami][whoami][1]);
			}
			if ((broadcast_self_pipefd[0] == -1) &&
				(broadcast_self_pipefd[1] == -1))
			{
				// duplication of file descriptors for run_localtest()
				broadcast_self_pipefd[0] =
					dup(broadcast_pipefd[whoami][whoami][0]);
				broadcast_self_pipefd[1] =
					dup(broadcast_pipefd[whoami][whoami][1]);
			}
			time_t keytime = time(NULL);
#ifdef GNUNET
			run_instance(whoami, keytime, gnunet_opt_keyexptime,
				gnunet_opt_xtests);
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
	// The domain parameters of the underlying fixed fallback group have
	// been generated by the author. You can run dkg-gencrs and then use
	// the option "-g" to employ your own individual domain parameter set.
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
			"INTEGER",
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
		GNUNET_GETOPT_option_flag('n',
			"no-rfc4880bis",
			"disable RFC 4880bis features",
			&gnunet_opt_norfc4880bis
		),
		GNUNET_GETOPT_option_flag('N',
			"no-passphrase",
			"disable private key protection",
			&gnunet_opt_nopassphrase
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
		GNUNET_GETOPT_option_flag('T',
			"timestamping",
			"state that the generated key is used for timestamping",
			&gnunet_opt_timestamping
		),
		GNUNET_GETOPT_option_string('u',
			"uid",
			"STRING",
			"user ID tied to the generated key",
			&gnunet_opt_u
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
			"minutes to wait until start of key generation protocol",
			&gnunet_opt_wait
		),
		GNUNET_GETOPT_option_uint('W',
			"aiou-timeout",
			"INTEGER",
			"timeout for point-to-point messages in minutes",
			&gnunet_opt_W
		),
		GNUNET_GETOPT_option_uint('x',
			"x-tests",
			NULL,
			"number of exchange tests",
			&gnunet_opt_xtests
		),
		GNUNET_GETOPT_option_flag('y',
			"yaot",
			"yet another OpenPGP tool",
			&gnunet_opt_y
		),
		GNUNET_GETOPT_OPTION_END
	};
//	if (GNUNET_STRINGS_get_utf8_args(argc, argv, &argc, &argv) != GNUNET_OK)
//	{
//		std::cerr << "ERROR: GNUNET_STRINGS_get_utf8_args() failed" <<
//			std::endl;
//		return -1;
//	}
	static const struct GNUNET_OS_ProjectData gnunet_dkgpg_pd = {
		.libname = "none",
		.project_dirname = "dkgpg",
		.binary_name = "dkg-generate",
		.env_varname = "none",
		.env_varname_alt = "none",
		.base_config_varname = "none",
		.bug_email = "heikostamer@gmx.net",
		.homepage = "https://www.nongnu.org/dkgpg/",
		.config_file = "dkgpg.conf",
		.user_config_file = "~/.config/dkgpg.conf",
		.version = version,
		.is_gnu = 0,
		.gettext_domain = NULL,
		.gettext_path = NULL
	};
	GNUNET_OS_init(&gnunet_dkgpg_pd);
	if (GNUNET_GETOPT_run(usage, options, argc, argv) == GNUNET_SYSERR)
	{
		std::cerr << "ERROR: GNUNET_GETOPT_run() failed" << std::endl;
		return -1;
	}
	if (gnunet_opt_crs != NULL)
		crs = gnunet_opt_crs; // get different CRS from GNUnet options
	if (gnunet_opt_passwords != NULL)
		passwords = gnunet_opt_passwords; // get passwords from GNUnet options
	if (gnunet_opt_hostname != NULL)
		hostname = gnunet_opt_hostname; // get hostname from GNUnet options
	if (gnunet_opt_W != opt_W)
		opt_W = gnunet_opt_W; // get aiou message timeout from GNUnet options
	if (gnunet_opt_u != NULL)
	{
		std::string u = gnunet_opt_u; // get userid from GNUnet options
		userid.push_back(u);
	}
#endif

	// create peer list from remaining arguments
	for (size_t i = 0; i < (size_t)(argc - 1); i++)
	{
		std::string arg = argv[i+1];
		// ignore options
		if ((arg.find("-c") == 0) || (arg.find("-p") == 0) ||
			(arg.find("-t") == 0) || (arg.find("-w") == 0) ||
			(arg.find("-W") == 0) || (arg.find("-L") == 0) ||
			(arg.find("-l") == 0) || (arg.find("-g") == 0) ||
			(arg.find("-x") == 0) || (arg.find("-s") == 0) ||
			(arg.find("-e") == 0) || (arg.find("-P") == 0) ||
			(arg.find("-H") == 0) || (arg.find("-u") == 0))
		{
			size_t idx = ++i;
			if ((arg.find("-g") == 0) && (idx < (size_t)(argc - 1)) &&
				(crs.length() == 0))
			{
				crs = argv[i+1]; // overwrite fallback CRS from dkg-common.hh
			}
			if ((arg.find("-H") == 0) && (idx < (size_t)(argc - 1)) &&
				(hostname.length() == 0))
			{
				hostname = argv[i+1];
			}
			if ((arg.find("-P") == 0) && (idx < (size_t)(argc - 1)) &&
				(passwords.length() == 0))
			{
				passwords = argv[i+1];
			}
			if ((arg.find("-t") == 0) && (idx < (size_t)(argc - 1)) &&
				(opt_t == DKGPG_MAX_N))
			{
				opt_t = strtoul(argv[i+1], NULL, 10);
			}
			if ((arg.find("-s") == 0) && (idx < (size_t)(argc - 1)) &&
				(opt_s == DKGPG_MAX_N))
			{
				opt_s = strtoul(argv[i+1], NULL, 10);
			}
			if ((arg.find("-e") == 0) && (idx < (size_t)(argc - 1)) &&
				(opt_e == 0))
			{
				opt_e = strtoul(argv[i+1], NULL, 10);
			}
			if ((arg.find("-p") == 0) && (idx < (size_t)(argc - 1)) &&
				(port.length() == 0))
			{
				port = argv[i+1];
			}
			if ((arg.find("-u") == 0) && (idx < (size_t)(argc - 1)))
			{
				std::string u = argv[i+1];
				userid.push_back(u);
			}
			if ((arg.find("-W") == 0) && (idx < (size_t)(argc - 1)) &&
				(opt_W == 5))
			{
				opt_W = strtoul(argv[i+1], NULL, 10);
			}
			continue;
		}
		else if ((arg.find("--") == 0) || (arg.find("-v") == 0) ||
			(arg.find("-h") == 0) || (arg.find("-V") == 0) ||
			(arg.find("-y") == 0) || (arg.find("-T") == 0) ||
			(arg.find("-N") == 0) || (arg.find("-n") == 0))
		{
			if ((arg.find("-h") == 0) || (arg.find("--help") == 0))
			{
#ifndef GNUNET
				std::cout << usage << std::endl;
				std::cout << about << std::endl;
				std::cout << "Arguments mandatory for long options are also" <<
					" mandatory for short options." << std::endl;
				std::cout << "  -h, --help     print this help" << std::endl;
				std::cout << "  -e INTEGER     expiration time of generated" <<
					" keys in seconds" << std::endl;
				std::cout << "  -g STRING      common reference string that" <<
					" defines underlying DDH-hard group" << std::endl;
				std::cout << "  -H STRING      hostname (e.g. onion address)" <<
					" of this peer within PEERS" << std::endl;
				std::cout << "  -n, --no-rfc4880bis  disable RFC 4880bis" <<
					" features" << std::endl;
				std::cout << "  -N, --no-passphrase  disable private key" <<
					" protection" << std::endl;
				std::cout << "  -p INTEGER     start port for built-in" <<
					" TCP/IP message exchange service" << std::endl; 
				std::cout << "  -P STRING      exchanged passwords to" <<
					" protect private and broadcast channels" << std::endl;
				std::cout << "  -s INTEGER     resilience of threshold DSS" <<
					" protocol (signature scheme)" << std::endl;
				std::cout << "  -t INTEGER     resilience of tElG protocol" <<
					" (threshold decryption)" << std::endl;
				std::cout << "  -T, --timestamping  state that the generated" <<
					" key is used for timestamping" << std::endl;
				std::cout << "  -u STRING      user ID tied to the generated" <<
					" key" << std::endl;
				std::cout << "  -v, --version  print the version number" <<
					std::endl;
				std::cout << "  -V, --verbose  turn on verbose output" <<
					std::endl;
				std::cout << "  -W INTEGER     timeout for point-to-point" <<
					" messages in minutes" << std::endl;
				std::cout << "  -y, --yaot     yet another OpenPGP tool" <<
					std::endl;
#endif
				return 0; // not continue
			}
			if ((arg.find("-v") == 0) || (arg.find("--version") == 0))
			{
#ifndef GNUNET
				std::cout << "dkg-generate v" << version <<
					" without GNUNET support" << std::endl;
#endif
				return 0; // not continue
			}
			if ((arg.find("-V") == 0) || (arg.find("--verbose") == 0))
				opt_verbose++; // increase verbosity
			if ((arg.find("-y") == 0) || (arg.find("--yaot") == 0))
				opt_y = true;
			if ((arg.find("-T") == 0) || (arg.find("--timestamping") == 0))
				opt_timestamping = true;
			if ((arg.find("-N") == 0) || (arg.find("--no-passphrase") == 0))
				opt_nopassphrase = true;
			if ((arg.find("-n") == 0) || (arg.find("--no-rfc4880bis") == 0))
				opt_rfc4880bis = false;
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
	peers.push_back("Test1");
	peers.push_back("Test2");
	peers.push_back("Test3");
	peers.push_back("Test4");
	opt_verbose = 2;
	opt_e = 10800;
	if (tmcg_mpz_wrandom_ui() % 2) // FIXME: libgcrypt is not initialized yet
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
#else
#ifdef DKGPG_TESTSUITE_TS
	peers.push_back("TestTS1");
	peers.push_back("TestTS2");
	peers.push_back("TestTS3");
	peers.push_back("TestTS4");
	opt_verbose = 2;
	opt_e = 10800;
	opt_timestamping = true;
#else
#ifdef DKGPG_TESTSUITE_Y
	peers.push_back("TestY");
	opt_y = true;
	opt_verbose = 2;
	opt_e = 10800;
	opt_timestamping = true;
	if (tmcg_mpz_wrandom_ui() % 2) // FIXME: libgcrypt is not initialized yet
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
#endif
#endif

	// check command line arguments
	if ((hostname.length() > 0) && (passwords.length() == 0) && !opt_y)
	{
		std::cerr << "ERROR: option \"-P\" is necessary due to insecure" <<
			" network" << std::endl;
		return -1;
	}
	if (peers.size() < 1)
	{
		std::cerr << "ERROR: no peers given as argument; usage: " <<
			usage << std::endl;
		return -1;
	}

	// canonicalize peer list and setup threshold values for tDSS/DSA and tElG
	canonicalize(peers);
	T = (peers.size() - 1) / 2; // default: maximum t-resilience for tElG
	S = (peers.size() - 1) / 2; // default: maximum s-resilience for tDSS/DSA
	if (((peers.size() < 3)  || (peers.size() > DKGPG_MAX_N)) && !opt_y)
	{
		std::cerr << "ERROR: too few or too many peers given" << std::endl;
		return -1;
	}
	if ((peers.size() != 1) && opt_y)
	{
		std::cerr << "ERROR: too many peers given" << std::endl;
		return -1;
	}
	if (opt_verbose && !opt_y)
	{
		std::cerr << "INFO: canonicalized peer list = " << std::endl;
		for (size_t i = 0; i < peers.size(); i++)
			std::cerr << peers[i] << std::endl;
	}

	// lock memory
	bool force_secmem = false, should_unlock = false;
	if (!lock_memory())
	{
		std::cerr << "WARNING: locking memory failed; CAP_IPC_LOCK required" <<
			" for full memory protection" << std::endl;
		// at least try to use libgcrypt's secure memory
		force_secmem = true;
	}
	else
		should_unlock = true;

	// initialize LibTMCG
	if (!init_libTMCG(force_secmem))
	{
		std::cerr << "ERROR: initialization of LibTMCG failed" << std::endl;
		if (should_unlock)
			unlock_memory();
		return -1;
	}
	if (opt_verbose)
	{
		std::cerr << "INFO: using LibTMCG version " << version_libTMCG() <<
			std::endl;
	}

	// read userid and passphrase
#ifdef DKGPG_TESTSUITE
	userid.push_back("TestGroup <testing@localhost>");
	if (tmcg_mpz_wrandom_ui() % 2)
		userid.push_back("TestGroup2 <second@localhost>");
	passphrase = "Test";
#else
#ifdef DKGPG_TESTSUITE_TS
	userid.push_back("TestGroupTS <testing@localhost>");
	passphrase = "Test";
#else
#ifdef DKGPG_TESTSUITE_Y
	userid.push_back("TestGroupY <testing@localhost>");
	if (tmcg_mpz_wrandom_ui() % 2)
		userid.push_back("TestGroupY2 <second@localhost>");
	if (tmcg_mpz_wrandom_ui() % 2)
		userid.push_back("TestGroupY3 <third@localhost>");
	passphrase = "TestY";
#else
	if (userid.size() == 0)
	{
		std::string u;
		std::cerr << "Please enter an OpenPGP-style user ID (name <email>): ";
		std::getline(std::cin, u);
		std::cin.clear();
		userid.push_back(u);
	}
	if (opt_nopassphrase)
	{
		std::cerr << "WARNING: private key protection disabled due to option" <<
			" --no-passphrase" << std::endl;
	}
	else
	{
		tmcg_openpgp_secure_string_t passphrase_check;
		std::string ps1 = "Passphrase to protect your part of the private key";
		std::string ps2 = "Please repeat the given passphrase to continue";
		do
		{
			passphrase = "", passphrase_check = "";
			if (!get_passphrase(ps1, false, passphrase))
			{
				if (should_unlock)
					unlock_memory();
				return -1;
			}
			if (!get_passphrase(ps2, false, passphrase_check))
			{
				if (should_unlock)
					unlock_memory();
				return -1;
			}
			if (passphrase != passphrase_check)
				std::cerr << "WARNING: passphrase does not match;" <<
					" please try again" << std::endl;
			else if (passphrase == "")
				std::cerr << "WARNING: private key protection disabled due" <<
					" to empty passphrase" << std::endl;
		}
		while (passphrase != passphrase_check);
	}
#endif
#endif
#endif

	// check and canonicalize user ID list
	for (size_t i = 0; i < userid.size(); i++)
	{
		if (!valid_utf8(userid[i]))
		{
			std::cerr << "ERROR: invalid UTF-8 encoding found at" <<
				" user ID #" << (i+1) << std::endl;
			if (should_unlock)
				unlock_memory();
			return -1;
		}
	}
	canonicalize(userid);
	if (opt_verbose)
	{
		std::cerr << "INFO: user ID list = " << std::endl;
		for (size_t i = 0; i < userid.size(); i++)
			std::cerr << "#" << (i+1) << ": " << userid[i] << std::endl;
	}

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
	// check magic bytes of CRS (common reference string)
	if (TMCG_ParseHelper::cm(crs, "crs", '|'))
	{
		if (opt_verbose)
		{
			std::cerr << "INFO: verifying domain parameters (according to" <<
				" LibTMCG::VTMF constructor)" << std::endl;
		}
	}
	else if (TMCG_ParseHelper::cm(crs, "fips-crs", '|'))
	{
		if (opt_verbose)
		{
			std::cerr << "INFO: verifying domain parameters (according to" <<
				" FIPS 186-4 section A.1.1.2)" << std::endl;
		}
		fips = true;
	}
	else if (TMCG_ParseHelper::cm(crs, "rfc-crs", '|'))
	{
		if (opt_verbose)
		{
			std::cerr << "INFO: verifying domain parameters (fixed by RFC" <<
				" 7919)" << std::endl;
		}
		rfc = true;
	}
	else
	{
		std::cerr << "ERROR: common reference string (CRS) is not valid" <<
			std::endl;
		if (should_unlock)
			unlock_memory();
		return -1;
	}
	// extract p, q, g from CRS
	mpz_t fips_p, fips_q, fips_g;
	mpz_init(fips_p), mpz_init(fips_q), mpz_init(fips_g);
	if (!pqg_extract(crs, fips, opt_verbose, fips_p, fips_q, fips_g, crss))
	{
		mpz_clear(fips_p), mpz_clear(fips_q), mpz_clear(fips_g);
		if (should_unlock)
			unlock_memory();
		return -1;
	}
	// initialize cache
	std::cerr << "We need a lot of entropy to cache very strong" <<
		" randomness for key generation." << std::endl;
	std::cerr << "Please use other programs, move the mouse, and type on" <<
		" your keyboard: " << std::endl;
	if (opt_y)
		tmcg_mpz_ssrandomm_cache_init(cache, cache_mod, cache_avail, 2, fips_q);
	else
		tmcg_mpz_ssrandomm_cache_init(cache, cache_mod, cache_avail,
			((2 * (S + 1)) + (2 * (T + 1))), fips_q);
	std::cerr << "Thank you!" << std::endl;
	mpz_clear(fips_p), mpz_clear(fips_q), mpz_clear(fips_g);
	// initialize return code and do the main work
	int ret = 0;
	if ((hostname.length() > 0) && !opt_y)
	{
		// start interactive variant, if built-in TCP/IP requested
		ret = run_tcpip(peers.size(), opt_p, hostname, port);
	}
	else if (opt_y)
	{
		// start a single instance as replacement for GnuPG et al.
		fork_instance(0);
		ret = wait_instance(0, opt_verbose, pid);
	}
	else
	{
#ifdef GNUNET
		static const struct GNUNET_GETOPT_CommandLineOption myoptions[] = {
			GNUNET_GETOPT_option_uint('e',
				"expiration",
				"INTEGER",
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
			GNUNET_GETOPT_option_flag('n',
				"no-rfc4880bis",
				"disable RFC 4880bis features",
				&gnunet_opt_norfc4880bis
			),
			GNUNET_GETOPT_option_flag('N',
				"no-passphrase",
				"disable private key protection",
				&gnunet_opt_nopassphrase
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
			GNUNET_GETOPT_option_flag('T',
				"timestamping",
				"state that the generated key is used for timestamping",
				&gnunet_opt_timestamping
			),
			GNUNET_GETOPT_option_string('u',
				"uid",
				"STRING",
				"user ID tied to the generated key",
				&gnunet_opt_u
			),
			GNUNET_GETOPT_option_flag('V',
				"verbose",
				"turn on verbose output",
				&gnunet_opt_verbose
			),
			GNUNET_GETOPT_option_uint('w',
				"wait",
				"INTEGER",
				"minutes to wait until start of key generation protocol",
				&gnunet_opt_wait
			),
			GNUNET_GETOPT_option_uint('W',
				"aiou-timeout",
				"INTEGER",
				"timeout for point-to-point messages in minutes",
				&gnunet_opt_W
			),
			GNUNET_GETOPT_option_uint('x',
				"x-tests",
				NULL,
				"number of exchange tests",
				&gnunet_opt_xtests
			),
			GNUNET_GETOPT_option_flag('y',
				"yaot",
				"yet another OpenPGP tool",
				&gnunet_opt_y
			),
			GNUNET_GETOPT_OPTION_END
		};
		ret = GNUNET_PROGRAM_run(argc, argv, usage, about, myoptions,
			&gnunet_run, argv[0]);
		if (ret != GNUNET_OK)
			ret = -1;
#else
		ret = run_localtest(peers.size(), opt_verbose, pid, pipefd, self_pipefd,
			broadcast_pipefd, broadcast_self_pipefd, &fork_instance);
#endif
	}
	// release cache
	tmcg_mpz_ssrandomm_cache_done(cache, cache_mod, cache_avail);
	// finish
	if (should_unlock)
		unlock_memory();
	return ret;
}

