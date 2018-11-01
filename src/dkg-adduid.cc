/*******************************************************************************
   This file is part of Distributed Privacy Guard (DKGPG).

 Copyright (C) 2018  Heiko Stamer <HeikoStamer@gmx.net>

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
static const char *protocol = "DKGPG-adduid-1.0";

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

#include <libTMCG.hh>
#include <aiounicast_select.hh>

#include "dkg-tcpip-common.hh"
#include "dkg-gnunet-common.hh"
#include "dkg-io.hh"
#include "dkg-common.hh"

int 						pipefd[DKGPG_MAX_N][DKGPG_MAX_N][2];
int							broadcast_pipefd[DKGPG_MAX_N][DKGPG_MAX_N][2];
pid_t 						pid[DKGPG_MAX_N];
std::vector<std::string>	peers;
bool						instance_forked = false;

tmcg_openpgp_secure_string_t	passphrase;
std::string						kfilename, userid;
std::string						passwords, hostname, port;

int 							opt_verbose = 0;
char							*opt_P = NULL;
char							*opt_H = NULL;
char							*opt_k = NULL, *opt_u = NULL;
unsigned long int				opt_p = 55000, opt_W = 5;

void run_instance
	(size_t whoami, const time_t sigtime, const size_t num_xtests)
{
	// read the key file
	std::string armored_seckey, thispeer = peers[whoami];
	if (!check_strict_permissions(thispeer + "_dkg-sec.asc"))
	{
		std::cerr << "WARNING: weak permissions of private key file" <<
			" detected" << std::endl;
		if (!set_strict_permissions(thispeer + "_dkg-sec.asc"))
			exit(-1);
	}
	if (!read_key_file(thispeer + "_dkg-sec.asc", armored_seckey))
		exit(-1);

	// read the keyring
	std::string armored_pubring;
	if (opt_k)
	{
		if (!read_key_file(kfilename, armored_pubring))
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
		if (!get_passphrase("Enter passphrase to unlock private key", false,
			passphrase))
		{
			std::cerr << "ERROR: cannot read passphrase" << std::endl;
			delete ring;
			exit(-1);
		}
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
	if (!prv->pub->valid || prv->Weak(opt_verbose))
	{
		std::cerr << "ERROR: primary key is invalid or weak" << std::endl;
		delete ring;
		delete prv;
		exit(-1);
	}
	if (prv->pkalgo != TMCG_OPENPGP_PKALGO_EXPERIMENTAL7)
	{
		std::cerr << "ERROR: primary key is not a tDSS/DSA key" << std::endl;
		delete ring;
		delete prv;
		exit(-1);
	}

	// create an instance of tDSS by stored parameters from private key
	CanettiGennaroJareckiKrawczykRabinDSS *dss = NULL;
	if (!init_tDSS(prv, opt_verbose, dss))
	{
		delete dss;
		delete ring;
		delete prv;
		exit(-1);
	}
	// create one-to-one mapping based on the stored canonicalized peer list
	if (!prv->tDSS_CreateMapping(peers, opt_verbose))
	{
		std::cerr << "ERROR: creating 1-to-1 CAPL mapping failed" << std::endl;
		delete dss;
		delete ring;
		delete prv;
		exit(-1);
	}

	// create communication handles between all players
	std::vector<int> uP_in, uP_out, bP_in, bP_out;
	std::vector<std::string> uP_key, bP_key;
	for (size_t i = 0; i < peers.size(); i++)
	{
		std::stringstream key;
		if (opt_P != NULL)
		{
			std::string pwd;
			if (!TMCG_ParseHelper::gs(passwords, '/', pwd))
			{
				std::cerr << "ERROR: P_" << whoami << ": " << "cannot read" <<
					" password for protecting channel to P_" << i << std::endl;
				delete dss;
				delete ring;
				delete prv;
				exit(-1);
			}
			key << pwd;
			if (((i + 1) < peers.size()) &&
				!TMCG_ParseHelper::nx(passwords, '/'))
			{
				std::cerr << "ERROR: P_" << whoami << ": " << "cannot skip" <<
					" to next password for protecting channel to P_" <<
					(i + 1) << std::endl;
				delete dss;
				delete ring;
				delete prv;
				exit(-1);
			}
		}
		else
		{
			// use simple key -- we assume that GNUnet provides secure channels
			key << "dkg-adduid::P_" << (i + whoami);
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

	// create asynchronous authenticated unicast channels for broadcast protocol
	aiounicast_select *aiou2 = new aiounicast_select(peers.size(), whoami,
		bP_in, bP_out, bP_key, aiounicast::aio_scheduler_roundrobin,
		(opt_W * 60));
			
	// create an instance of a reliable broadcast protocol (RBC)
	std::string myID = "dkg-adduid|" + std::string(protocol) + "|";
	for (size_t i = 0; i < peers.size(); i++)
		myID += peers[i] + "|";
	if (opt_verbose)
		std::cerr << "RBC: myID = " << myID << std::endl;
	// assume maximum asynchronous t-resilience for RBC
	size_t T_RBC = (peers.size() - 1) / 3;
	CachinKursawePetzoldShoupRBC *rbc =
		new CachinKursawePetzoldShoupRBC(peers.size(), T_RBC, whoami, aiou2,
			aiounicast::aio_scheduler_roundrobin, (opt_W * 60));
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

	// participants must agree on a common signature creation time (OpenPGP)
	if (opt_verbose)
		std::cerr << "INFO: agree on a signature creation time for OpenPGP" <<
			std::endl;
	time_t csigtime = 0;
	std::vector<time_t> tvs;
	mpz_t mtv;
	mpz_init_set_ui(mtv, sigtime);
	rbc->Broadcast(mtv);
	tvs.push_back(sigtime);
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
				std::cerr << "WARNING: P_" << whoami << ": no signature" <<
					" creation time stamp received from " << i << std::endl;
			}
		}
	}
	mpz_clear(mtv);
	std::sort(tvs.begin(), tvs.end());
	if (tvs.size() < (peers.size() - T_RBC))
	{
		std::cerr << "ERROR: P_" << whoami << ": not enough timestamps" <<
			" received" << std::endl;
		delete rbc, delete aiou, delete aiou2;
		delete dss;
		delete ring;
		delete prv;
		exit(-1);
	}
	// use a median value as some kind of gentle agreement
	csigtime = tvs[tvs.size()/2];
	if (opt_verbose)
		std::cerr << "INFO: P_" << whoami << ": canonicalized signature" <<
			" creation time = " << csigtime << std::endl;

	// select hash algorithm for OpenPGP based on |q| (size in bit)
	tmcg_openpgp_hashalgo_t hashalgo = TMCG_OPENPGP_HASHALGO_UNKNOWN;
	if (mpz_sizeinbase(dss->q, 2L) == 256)
		hashalgo = TMCG_OPENPGP_HASHALGO_SHA256; // SHA256 (alg 8)
	else if (mpz_sizeinbase(dss->q, 2L) == 384)
		hashalgo = TMCG_OPENPGP_HASHALGO_SHA384; // SHA384 (alg 9)
	else if (mpz_sizeinbase(dss->q, 2L) == 512)
		hashalgo = TMCG_OPENPGP_HASHALGO_SHA512; // SHA512 (alg 10)
	else
	{
		std::cerr << "ERROR: P_" << whoami << ": selecting hash algorithm" <<
			" failed for |q| = " << mpz_sizeinbase(dss->q, 2L) << std::endl;
		delete rbc, delete aiou, delete aiou2;
		delete dss;
		delete ring;
		delete prv;
		exit(-1);
	}

	// prepare OpenPGP structures
	tmcg_openpgp_octets_t uat;
	tmcg_openpgp_octets_t uid, uidsig, uidsig_hashing, uidsig_left;
	tmcg_openpgp_octets_t hash, dsaflags;
	CallasDonnerhackeFinneyShawThayerRFC4880::PacketUidEncode(userid, uid);
	// key may be used to certify other keys, to sign data and has been
	// split by a secret-sharing mechanism
	dsaflags.push_back(0x01 | 0x02 | 0x10);
	CallasDonnerhackeFinneyShawThayerRFC4880::
		PacketSigPrepareSelfSignature(TMCG_OPENPGP_SIGNATURE_POSITIVE_CERTIFICATION,
			hashalgo, csigtime, prv->pub->expirationtime, dsaflags,
			prv->pub->fingerprint, uidsig_hashing); 
	CallasDonnerhackeFinneyShawThayerRFC4880::
		CertificationHash(prv->pub->pub_hashing, userid, uat, uidsig_hashing,
			hashalgo, hash, uidsig_left);

	// sign the hash
	tmcg_openpgp_byte_t buffer[1024];
	gcry_mpi_t r, s, h;
	mpz_t dsa_m, dsa_r, dsa_s;
	size_t buflen = 0;
	gcry_error_t ret;
	memset(buffer, 0, sizeof(buffer));
	for (size_t i = 0; ((i < hash.size()) && (i < sizeof(buffer)));
		i++, buflen++)
			buffer[i] = hash[i];
	r = gcry_mpi_new(2048);
	s = gcry_mpi_new(2048);
	mpz_init(dsa_m), mpz_init(dsa_r), mpz_init(dsa_s);
	ret = gcry_mpi_scan(&h, GCRYMPI_FMT_USG, buffer, buflen, NULL);
	if (ret)
	{
		std::cerr << "ERROR: P_" << whoami << ": gcry_mpi_scan() failed" <<
			" for h" << std::endl;
		gcry_mpi_release(r), gcry_mpi_release(s);
		mpz_clear(dsa_m), mpz_clear(dsa_r), mpz_clear(dsa_s);
		delete rbc, delete aiou, delete aiou2;
		delete dss;
		delete ring;
		delete prv;
		exit(-1);
	}
	if (!tmcg_mpz_set_gcry_mpi(h, dsa_m))
	{
		std::cerr << "ERROR: P_" << whoami << ": tmcg_mpz_set_gcry_mpi()" <<
			" failed for dsa_m" << std::endl;
		gcry_mpi_release(r), gcry_mpi_release(s), gcry_mpi_release(h);
		mpz_clear(dsa_m), mpz_clear(dsa_r), mpz_clear(dsa_s);
		delete rbc, delete aiou, delete aiou2;
		delete dss;
		delete ring;
		delete prv;
		exit(-1);
	}
	gcry_mpi_release(h);
	std::stringstream err_log_sign;
	if (opt_verbose)
		std::cerr << "INFO: P_" << whoami << ": dss.Sign() on" <<
			" user ID" << std::endl;
	if (!dss->Sign(peers.size(), whoami, dsa_m, dsa_r, dsa_s, prv->tdss_idx2dkg,
		prv->tdss_dkg2idx, aiou, rbc, err_log_sign))
	{
		std::cerr << "ERROR: P_" << whoami << ": " << "tDSS Sign() on" <<
			" user ID failed" << std::endl;
		std::cerr << "ERROR: P_" << whoami << ": log follows " << std::endl <<
			err_log_sign.str();
		gcry_mpi_release(r), gcry_mpi_release(s);
		mpz_clear(dsa_m), mpz_clear(dsa_r), mpz_clear(dsa_s);
		delete rbc, delete aiou, delete aiou2;
		delete dss;
		delete ring;
		delete prv;
		exit(-1);
	}
	if (opt_verbose > 1)
		std::cerr << "INFO: P_" << whoami << ": log follows " << std::endl <<
			err_log_sign.str();
	if (!tmcg_mpz_get_gcry_mpi(r, dsa_r))
	{
		std::cerr << "ERROR: P_" << whoami << ": tmcg_mpz_get_gcry_mpi()" <<
			" failed for dsa_r" << std::endl;
		gcry_mpi_release(r), gcry_mpi_release(s);
		mpz_clear(dsa_m), mpz_clear(dsa_r), mpz_clear(dsa_s);
		delete rbc, delete aiou, delete aiou2;
		delete dss;
		delete ring;
		delete prv;
		exit(-1);
	}
	if (!tmcg_mpz_get_gcry_mpi(s, dsa_s))
	{
		std::cerr << "ERROR: P_" << whoami << ": tmcg_mpz_get_gcry_mpi()" <<
			" failed for dsa_s" << std::endl;
		gcry_mpi_release(r), gcry_mpi_release(s);
		mpz_clear(dsa_m), mpz_clear(dsa_r), mpz_clear(dsa_s);
		delete rbc, delete aiou, delete aiou2;
		delete dss;
		delete ring;
		delete prv;
		exit(-1);
	}
	CallasDonnerhackeFinneyShawThayerRFC4880::
		PacketSigEncode(uidsig_hashing, uidsig_left, r, s, uidsig);
	gcry_mpi_release(r), gcry_mpi_release(s);
	mpz_clear(dsa_m), mpz_clear(dsa_r), mpz_clear(dsa_s);

	// at the end: deliver some more rounds for still waiting parties
	time_t synctime = aiounicast::aio_timeout_long;
	if (opt_verbose)
		std::cerr << "INFO: P_" << whoami << ": waiting approximately " <<
			(synctime * (T_RBC + 1)) << " seconds for stalled parties" <<
			std::endl;
	rbc->Sync(synctime);

	// release RBC
	delete rbc;
	
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

	// release
	delete dss;
	delete ring;

	// convert and append the created user ID packet (uid) and the corresponding
	// signature packet (uidsig) to existing OpenPGP structures of this key
	TMCG_OpenPGP_Signature *si = NULL;
	parse_ok = CallasDonnerhackeFinneyShawThayerRFC4880::
		SignatureParse(uidsig, opt_verbose, si);
	if (!parse_ok)
	{
		std::cerr << "ERROR: cannot use the created signature" << std::endl;
		delete prv;
		exit(-1);
	}
	if (opt_verbose)
		si->PrintInfo();
	TMCG_OpenPGP_UserID *ui = new TMCG_OpenPGP_UserID(userid, uid);
	ui->selfsigs.push_back(si);
	if (!ui->Check(prv->pub, opt_verbose))
	{
		std::cerr << "ERROR: validity check of user ID failed" << std::endl;
		delete ui;
		delete prv;
		exit(-1);
	}
	prv->pub->userids.push_back(ui); // append to private/public key

	// export updated private key in OpenPGP armor format
	std::stringstream secfilename;
	secfilename << peers[whoami] << "_dkg-sec.asc";
	std::string armor = "";
	tmcg_openpgp_octets_t sec;
	prv->Export(sec);
	CallasDonnerhackeFinneyShawThayerRFC4880::
		ArmorEncode(TMCG_OPENPGP_ARMOR_PRIVATE_KEY_BLOCK, sec, armor);
	std::ofstream secofs((secfilename.str()).c_str(),
		std::ofstream::out | std::ofstream::trunc);
	if (!secofs.good())
	{
		std::cerr << "ERROR: P_" << whoami << ": opening private key file" <<
			" failed" << std::endl;
		delete prv;
		exit(-1);
	}
	secofs << armor;
	if (!secofs.good())
	{
		std::cerr << "ERROR: P_" << whoami << ": writing private key file" <<
			" failed" << std::endl;
		delete prv;
		exit(-1);
	}
	secofs.close();

	// export public key in OpenPGP armor format
	std::stringstream pubfilename;
	pubfilename << peers[whoami] << "_dkg-pub.asc";
	armor = "";
	tmcg_openpgp_octets_t pub;
	prv->RelinkPublicSubkeys(); // relink the contained subkeys
	prv->pub->Export(pub);
	prv->RelinkPrivateSubkeys(); // undo the relinking
	CallasDonnerhackeFinneyShawThayerRFC4880::
		ArmorEncode(TMCG_OPENPGP_ARMOR_PUBLIC_KEY_BLOCK, pub, armor);
	if (opt_verbose > 1)
		std::cout << armor << std::endl;
	std::ofstream pubofs((pubfilename.str()).c_str(), std::ofstream::out);
	if (!pubofs.good())
	{
		std::cerr << "ERROR: P_" << whoami << ": opening public key file" <<
			" failed" << std::endl;
		delete prv;
		exit(-1);
	}
	pubofs << armor;
	if (!pubofs.good())
	{
		std::cerr << "ERROR: P_" << whoami << ": writing public key file" <<
			" failed" << std::endl;
		delete prv;
		exit(-1);
	}
	pubofs.close();

	// release
	delete prv;
}

#ifdef GNUNET
char *gnunet_opt_H = NULL;
char *gnunet_opt_P = NULL;
char *gnunet_opt_k = NULL;
char *gnunet_opt_u = NULL;
char *gnunet_opt_port = NULL;
unsigned int gnunet_opt_xtests = 0;
unsigned int gnunet_opt_wait = 5;
unsigned int gnunet_opt_W = opt_W;
int gnunet_opt_verbose = 0;
#endif

void fork_instance
	(const size_t whoami)
{
	if ((pid[whoami] = fork()) < 0)
		perror("ERROR: dkg-adduid (fork)");
	else
	{
		if (pid[whoami] == 0)
		{
			/* BEGIN child code: participant P_i */
			time_t sigtime = time(NULL);
#ifdef GNUNET
			run_instance(whoami, sigtime, gnunet_opt_xtests);
#else
			run_instance(whoami, sigtime, 0);
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
	static const char *usage = "dkg-adduid -u STRING [OPTIONS] PEERS";
#ifdef GNUNET
	char *loglev = NULL;
	char *logfile = NULL;
	char *cfg_fn = NULL;
	static const struct GNUNET_GETOPT_CommandLineOption options[] = {
		GNUNET_GETOPT_option_cfgfile(&cfg_fn),
		GNUNET_GETOPT_option_help(about),
		GNUNET_GETOPT_option_string('H',
			"hostname",
			"STRING",
			"hostname (e.g. onion address) of this peer within PEERS",
			&gnunet_opt_H
		),
		GNUNET_GETOPT_option_string('k',
			"keyring",
			"FILENAME",
			"use keyring FILENAME containing external revocation keys",
			&gnunet_opt_k
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
			&gnunet_opt_P
		),
		GNUNET_GETOPT_option_string('u',
			"uid",
			"STRING",
			"user ID to add",
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
			"minutes to wait until start of revocation protocol",
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
		GNUNET_GETOPT_OPTION_END
	};
//	if (GNUNET_STRINGS_get_utf8_args(argc, argv, &argc, &argv) != GNUNET_OK)
//	{
//		std::cerr << "ERROR: GNUNET_STRINGS_get_utf8_args() failed" << std::endl;
//		return -1;
//	}
	if (GNUNET_GETOPT_run(usage, options, argc, argv) == GNUNET_SYSERR)
	{
		std::cerr << "ERROR: GNUNET_GETOPT_run() failed" << std::endl;
		return -1;
	}
	if (gnunet_opt_H != NULL)
	{
		hostname = gnunet_opt_H; // get hostname from GNUnet options
		opt_H = gnunet_opt_H;
	}
	if (gnunet_opt_P != NULL)
	{
		passwords = gnunet_opt_P; // get passwords from GNUnet options
		opt_P = gnunet_opt_P;
	}
	if (gnunet_opt_u != NULL)
	{
		userid = gnunet_opt_u; // get userid from GNUnet options
		opt_u = gnunet_opt_u;
	}
	if (gnunet_opt_k != NULL)
	{
		kfilename = gnunet_opt_k; // get kfilename from GNUnet options
		opt_k = gnunet_opt_k;
	}
	if (gnunet_opt_W != opt_W)
		opt_W = gnunet_opt_W; // get aiou message timeout from GNUnet options
#endif

	// create peer list from remaining arguments
	for (size_t i = 0; i < (size_t)(argc - 1); i++)
	{
		std::string arg = argv[i+1];
		// ignore options
		if ((arg.find("-c") == 0) || (arg.find("-p") == 0) ||
			(arg.find("-u") == 0) || (arg.find("-w") == 0) ||
			(arg.find("-W") == 0) || (arg.find("-L") == 0) ||
			(arg.find("-l") == 0) || (arg.find("-x") == 0) ||
			(arg.find("-P") == 0) || (arg.find("-H") == 0) ||
			(arg.find("-k") == 0))
		{
			size_t idx = ++i;
			if ((arg.find("-H") == 0) && (idx < (size_t)(argc - 1)) &&
				(opt_H == NULL))
			{
				hostname = argv[i+1];
				opt_H = (char*)hostname.c_str();
			}
			if ((arg.find("-k") == 0) && (idx < (size_t)(argc - 1)) &&
				(opt_k == NULL))
			{
				kfilename = argv[i+1];
				opt_k = (char*)kfilename.c_str();
			}
			if ((arg.find("-P") == 0) && (idx < (size_t)(argc - 1)) &&
				(opt_P == NULL))
			{
				passwords = argv[i+1];
				opt_P = (char*)passwords.c_str();
			}
			if ((arg.find("-p") == 0) && (idx < (size_t)(argc - 1)) &&
				(port.length() == 0))
			{
				port = argv[i+1];
			}
			if ((arg.find("-u") == 0) && (idx < (size_t)(argc - 1)) &&
				(opt_u == NULL))
			{
				userid = argv[i+1];
				opt_u = (char*)userid.c_str();
			}
			if ((arg.find("-W") == 0) && (idx < (size_t)(argc - 1)) &&
				(opt_W == 5))
			{
				opt_W = strtoul(argv[i+1], NULL, 10);
			}
			continue;
		}
		else if ((arg.find("--") == 0) || (arg.find("-v") == 0) ||
				 (arg.find("-h") == 0) || (arg.find("-V") == 0))
		{
			if ((arg.find("-h") == 0) || (arg.find("--help") == 0))
			{
#ifndef GNUNET
				std::cout << usage << std::endl;
				std::cout << about << std::endl;
				std::cout << "Arguments mandatory for long options are also" <<
					" mandatory for short options." << std::endl;
				std::cout << "  -h, --help     print this help" << std::endl;
				std::cout << "  -H STRING      hostname (e.g. onion address)" <<
					" of this peer within PEERS" << std::endl;
				std::cout << "  -k FILENAME    use keyring FILENAME" <<
					" containing external revocation keys" << std::endl;
				std::cout << "  -p INTEGER     start port for built-in" <<
					" TCP/IP message exchange service" << std::endl;
				std::cout << "  -P STRING      exchanged passwords to" <<
					" protect private and broadcast channels" << std::endl;
				std::cout << "  -u STRING      user ID to add" << std::endl;
				std::cout << "  -v, --version  print the version number" <<
					std::endl;
				std::cout << "  -V, --verbose  turn on verbose output" <<
					std::endl;
				std::cout << "  -W INTEGER     timeout for point-to-point" <<
					" messages in minutes" << std::endl;
#endif
				return 0; // not continue
			}
			if ((arg.find("-v") == 0) || (arg.find("--version") == 0))
			{
#ifndef GNUNET
				std::cout << "dkg-adduid v" << version <<
					" without GNUNET support" << std::endl;
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
	userid = "additional userID";
	opt_u = (char*)userid.c_str();
	opt_verbose = 2;
#endif

	// check command line arguments
	if (opt_u == NULL)
	{
		std::cerr << "ERROR: option \"-u\" required to specify an user ID" <<
			std::endl;
		return -1;
	}
	if ((opt_H != NULL) && (opt_P == NULL))
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

	// canonicalize peer list
	std::sort(peers.begin(), peers.end());
	std::vector<std::string>::iterator it =
		std::unique(peers.begin(), peers.end());
	peers.resize(std::distance(peers.begin(), it));
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
	
	// initialize return code
	int ret = 0;
	// create underlying point-to-point channels, if built-in TCP/IP requested
	if (opt_H != NULL)
	{
		if (port.length())
			opt_p = strtoul(port.c_str(), NULL, 10); // start port from options
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

	// start interactive variant with GNUnet or otherwise a local test
#ifdef GNUNET
	static const struct GNUNET_GETOPT_CommandLineOption myoptions[] = {
		GNUNET_GETOPT_option_string('H',
			"hostname",
			"STRING",
			"hostname (e.g. onion address) of this peer within PEERS",
			&gnunet_opt_H
		),
		GNUNET_GETOPT_option_string('k',
			"keyring",
			"FILENAME",
			"use keyring FILENAME containing external revocation keys",
			&gnunet_opt_k
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
			&gnunet_opt_P
		),
		GNUNET_GETOPT_option_string('u',
			"uid",
			"STRING",
			"user ID to add",
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
			"minutes to wait until start of revocation protocol",
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
		GNUNET_GETOPT_OPTION_END
	};
	ret = GNUNET_PROGRAM_run(argc, argv, usage, about, myoptions, &gnunet_run, argv[0]);
//	GNUNET_free((void *) argv);
	if (ret == GNUNET_OK)
		return 0;
	else
		return -1;
#else
	std::cerr << "WARNING: GNUnet CADET is required for the message exchange" <<
		" of this program" << std::endl;
#endif

	std::cerr << "INFO: running local test with " << peers.size() <<
		" participants" << std::endl;
	// open pipes
	for (size_t i = 0; i < peers.size(); i++)
	{
		for (size_t j = 0; j < peers.size(); j++)
		{
			if (pipe(pipefd[i][j]) < 0)
				perror("ERROR: dkg-adduid (pipe)");
			if (pipe(broadcast_pipefd[i][j]) < 0)
				perror("ERROR: dkg-adduid (pipe)");
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
			perror("ERROR: dkg-adduid (waitpid)");
		if (!WIFEXITED(wstatus))
		{
			std::cerr << "ERROR: protocol instance ";
			if (WIFSIGNALED(wstatus))
			{
				std::cerr << pid[i] << " terminated by signal " <<
					WTERMSIG(wstatus) << std::endl;
			}
			if (WCOREDUMP(wstatus))
				std::cerr << pid[i] << " dumped core" << std::endl;
			ret = -1;
		}
		else if (WIFEXITED(wstatus))
		{
			if (opt_verbose)
			{
				std::cerr << "INFO: protocol instance " << pid[i] <<
					" terminated with exit status " << WEXITSTATUS(wstatus) <<
					std::endl;
			}
			if (WEXITSTATUS(wstatus))
				ret = -2; // error
		}
		for (size_t j = 0; j < peers.size(); j++)
		{
			if ((close(pipefd[i][j][0]) < 0) || (close(pipefd[i][j][1]) < 0))
				perror("ERROR: dkg-adduid (close)");
			if ((close(broadcast_pipefd[i][j][0]) < 0) ||
				(close(broadcast_pipefd[i][j][1]) < 0))
			{
				perror("ERROR: dkg-adduid (close)");
			}
		}
	}
	
	return ret;
}

