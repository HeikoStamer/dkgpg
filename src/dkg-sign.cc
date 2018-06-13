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

std::string					passphrase, ifilename, ofilename, kfilename;
std::string					passwords, hostname, port, URI;

int 						opt_verbose = 0;
char						*opt_ifilename = NULL;
char						*opt_ofilename = NULL;
char						*opt_passwords = NULL;
char						*opt_hostname = NULL;
char						*opt_URI = NULL;
char						*opt_k = NULL;
unsigned long int			opt_e = 0, opt_p = 55000, opt_W = 5;

void run_instance
	(size_t whoami, const time_t sigtime, const time_t sigexptime,
	 const size_t num_xtests)
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
		if (!get_passphrase("Enter passphrase to unlock private key",
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
	if (!prv->pub->valid || prv->weak(opt_verbose))
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
		if (opt_passwords != NULL)
		{
			std::string pwd;
			if (!TMCG_ParseHelper::gs(passwords, '/', pwd))
			{
				std::cerr << "ERROR: S_" << whoami << ": " << "cannot read" <<
					" password for protecting channel to S_" << i << std::endl;
				delete dss;
				delete ring;
				delete prv;
				exit(-1);
			}
			key << pwd;
			if (((i + 1) < peers.size()) &&
				!TMCG_ParseHelper::nx(passwords, '/'))
			{
				std::cerr << "ERROR: S_" << whoami << ": " << "cannot skip" <<
					" to next password for protecting channel to S_" <<
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
			key << "dkg-sign::S_" << (i + whoami);
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
	std::string myID = "dkg-sign|";
	for (size_t i = 0; i < peers.size(); i++)
		myID += peers[i] + "|";
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
		std::cerr << "INFO: S_" << whoami << ": xtest = " << xtest << " <-> ";
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
				std::cerr << "WARNING: S_" << whoami << ": no signature" <<
					" creation time stamp received from S_" << i << std::endl;
			}
		}
	}
	mpz_clear(mtv);
	std::sort(tvs.begin(), tvs.end());
	if (tvs.size() < (peers.size() - T_RBC))
	{
		std::cerr << "ERROR: S_" << whoami << ": not enough timestamps" <<
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
		std::cerr << "INFO: S_" << whoami << ": canonicalized signature" <<
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
		std::cerr << "ERROR: S_" << whoami << ": selecting hash algorithm" <<
			" failed for |q| = " << mpz_sizeinbase(dss->q, 2L) << std::endl;
		delete rbc, delete aiou, delete aiou2;
		delete dss;
		delete ring;
		delete prv;
		exit(-1);
	}

	// compute the hash of the input file
	if (opt_verbose)
		std::cerr << "INFO: hashing the input file \"" << opt_ifilename <<
			"\"" << std::endl;
	tmcg_openpgp_octets_t trailer, hash, left;
	CallasDonnerhackeFinneyShawThayerRFC4880::
		PacketSigPrepareDetachedSignature(TMCG_OPENPGP_SIGNATURE_BINARY_DOCUMENT,
			hashalgo, csigtime, sigexptime, URI, prv->pub->id, trailer);
	if (!CallasDonnerhackeFinneyShawThayerRFC4880::
		BinaryDocumentHash(opt_ifilename, trailer, hashalgo, hash, left))
	{
		std::cerr << "ERROR: S_" << whoami << ": BinaryDocumentHash()" <<
			" failed; cannot process input file \"" << opt_ifilename << "\"" <<
			std::endl;
		delete rbc, delete aiou, delete aiou2;
		delete dss;
		delete ring;
		delete prv;
		exit(-1);
	}

	// sign the hash
	tmcg_openpgp_byte_t buffer[1024];
	gcry_mpi_t r, s, h;
	mpz_t dsa_m, dsa_r, dsa_s;
	size_t buflen = 0;
	gcry_error_t ret;
	memset(buffer, 0, sizeof(buffer));
	for (size_t i = 0; ((i < hash.size()) && (i < sizeof(buffer))); i++, buflen++)
		buffer[i] = hash[i];
	r = gcry_mpi_new(2048);
	s = gcry_mpi_new(2048);
	mpz_init(dsa_m), mpz_init(dsa_r), mpz_init(dsa_s);
	ret = gcry_mpi_scan(&h, GCRYMPI_FMT_USG, buffer, buflen, NULL);
	if (ret)
	{
		std::cerr << "ERROR: S_" << whoami << ": gcry_mpi_scan() failed" <<
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
		std::cerr << "ERROR: S_" << whoami << ": tmcg_mpz_set_gcry_mpi()" <<
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
		std::cerr << "INFO: S_" << whoami << ": dss.Sign()" << std::endl;
	if (!dss->Sign(peers.size(), whoami, dsa_m, dsa_r, dsa_s, prv->tdss_idx2dkg,
		prv->tdss_dkg2idx, aiou, rbc, err_log_sign))
	{
		std::cerr << "ERROR: S_" << whoami << ": " << "tDSS Sign() failed" <<
			std::endl;
		std::cerr << "ERROR: S_" << whoami << ": log follows " << std::endl <<
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
		std::cerr << "INFO: S_" << whoami << ": log follows " << std::endl <<
			err_log_sign.str(); 
	if (!tmcg_mpz_get_gcry_mpi(r, dsa_r))
	{
		std::cerr << "ERROR: S_" << whoami << ": tmcg_mpz_get_gcry_mpi()" <<
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
		std::cerr << "ERROR: S_" << whoami << ": tmcg_mpz_get_gcry_mpi()" <<
			" failed for dsa_s" << std::endl;
		gcry_mpi_release(r), gcry_mpi_release(s);
		mpz_clear(dsa_m), mpz_clear(dsa_r), mpz_clear(dsa_s);
		delete rbc, delete aiou, delete aiou2;
		delete dss;
		delete ring;
		delete prv;
		exit(-1);
	}
	tmcg_openpgp_octets_t sig;
	CallasDonnerhackeFinneyShawThayerRFC4880::
		PacketSigEncode(trailer, left, r, s, sig);
	gcry_mpi_release(r), gcry_mpi_release(s);
	mpz_clear(dsa_m), mpz_clear(dsa_r), mpz_clear(dsa_s);

	// at the end: deliver some more rounds for still waiting parties
	time_t synctime = aiounicast::aio_timeout_long;
	if (opt_verbose)
		std::cerr << "INFO: S_" << whoami << ": waiting approximately " <<
			(synctime * (T_RBC + 1)) << " seconds for stalled parties" <<
			std::endl;
	rbc->Sync(synctime);

	// release RBC
	delete rbc;
	
	// release handles (unicast channel)
	uP_in.clear(), uP_out.clear(), uP_key.clear();
	if (opt_verbose)
	{
		std::cerr << "INFO: S_" << whoami << ": unicast channels";
		aiou->PrintStatistics(std::cerr);
		std::cerr << std::endl;
	}

	// release handles (broadcast channel)
	bP_in.clear(), bP_out.clear(), bP_key.clear();
	if (opt_verbose)
	{
		std::cerr << "INFO: S_" << whoami << ": broadcast channel";
		aiou2->PrintStatistics(std::cerr);
		std::cerr << std::endl;
	}

	// release asynchronous unicast and broadcast
	delete aiou, delete aiou2;

	// release
	delete dss;
	delete ring;
	delete prv;

	// output the result
	std::string sigstr;
	CallasDonnerhackeFinneyShawThayerRFC4880::
		ArmorEncode(TMCG_OPENPGP_ARMOR_SIGNATURE, sig, sigstr);
	if (opt_ofilename != NULL)
	{
		if (!write_message(opt_ofilename, sigstr))
			exit(-1);
	}
	else
		std::cout << sigstr << std::endl;
}

#ifdef GNUNET
char *gnunet_opt_hostname = NULL;
char *gnunet_opt_ifilename = NULL;
char *gnunet_opt_ofilename = NULL;
char *gnunet_opt_passwords = NULL;
char *gnunet_opt_port = NULL;
char *gnunet_opt_URI = NULL;
char *gnunet_opt_k = NULL;
unsigned int gnunet_opt_sigexptime = 0;
unsigned int gnunet_opt_xtests = 0;
unsigned int gnunet_opt_wait = 5;
unsigned int gnunet_opt_W = opt_W;
int gnunet_opt_verbose = 0;
#endif

void fork_instance
	(const size_t whoami)
{
	if ((pid[whoami] = fork()) < 0)
		perror("ERROR: dkg-sign (fork)");
	else
	{
		if (pid[whoami] == 0)
		{
			/* BEGIN child code: participant S_i */
			time_t sigtime = time(NULL);
#ifdef GNUNET
			run_instance(whoami, sigtime, gnunet_opt_sigexptime,
				gnunet_opt_xtests);
#else
			run_instance(whoami, sigtime, opt_e, 0);
#endif
			if (opt_verbose)
				std::cerr << "INFO: S_" << whoami << ": exit(0)" << std::endl;
			exit(0);
			/* END child code: participant S_i */
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
	static const char *usage = "dkg-sign [OPTIONS] -i INPUTFILE PEERS";
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
			"expiration time of generated signature in seconds",
			&gnunet_opt_sigexptime
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
			"create detached signature from FILENAME",
			&gnunet_opt_ifilename
		),
		GNUNET_GETOPT_option_string('k',
			"keyring",
			"FILENAME",
			"use keyring FILENAME containing external revocation keys",
			&gnunet_opt_k
		),
		GNUNET_GETOPT_option_logfile(&logfile),
		GNUNET_GETOPT_option_loglevel(&loglev),
		GNUNET_GETOPT_option_string('o',
			"output",
			"FILENAME",
			"write detached signature to FILENAME",
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
		GNUNET_GETOPT_option_string('U',
			"URI",
			"STRING",
			"policy URI tied to signature",
			&gnunet_opt_URI
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
			"minutes to wait until start of signing protocol",
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
		std::cerr << "ERROR: GNUNET_STRINGS_get_utf8_args() failed" <<
			std::endl;
   		return -1;
	}
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
	if (gnunet_opt_URI != NULL)
		opt_URI = gnunet_opt_URI;
	if (gnunet_opt_passwords != NULL)
		passwords = gnunet_opt_passwords; // get passwords from GNUnet options
	if (gnunet_opt_hostname != NULL)
		hostname = gnunet_opt_hostname; // get hostname from GNUnet options
	if (gnunet_opt_k != NULL)
		opt_k = gnunet_opt_k;
	if (gnunet_opt_W != opt_W)
		opt_W = gnunet_opt_W; // get aiou message timeout from GNUnet options
	if (gnunet_opt_URI != NULL)
		URI = gnunet_opt_URI; // get policy URI from GNUnet options
#endif

	// create peer list from remaining arguments
	for (size_t i = 0; i < (size_t)(argc - 1); i++)
	{
		std::string arg = argv[i+1];
		// ignore options
		if ((arg.find("-c") == 0) || (arg.find("-p") == 0) ||
			(arg.find("-w") == 0) || (arg.find("-W") == 0) || 
		    (arg.find("-L") == 0) || (arg.find("-l") == 0) ||
			(arg.find("-i") == 0) || (arg.find("-o") == 0) || 
		    (arg.find("-e") == 0) || (arg.find("-x") == 0) ||
			(arg.find("-P") == 0) || (arg.find("-H") == 0) ||
		    (arg.find("-U") == 0) || (arg.find("-k") == 0))
		{
			size_t idx = ++i;
			if ((arg.find("-i") == 0) && (idx < (size_t)(argc - 1)) && (opt_ifilename == NULL))
			{
				ifilename = argv[i+1];
				opt_ifilename = (char*)ifilename.c_str();
			}
			if ((arg.find("-o") == 0) && (idx < (size_t)(argc - 1)) && (opt_ofilename == NULL))
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
			if ((arg.find("-U") == 0) && (idx < (size_t)(argc - 1)) && (opt_URI == NULL))
			{
				URI = argv[i+1];
				opt_URI = (char*)URI.c_str();
			}
			if ((arg.find("-e") == 0) && (idx < (size_t)(argc - 1)) && (opt_e == 0))
				opt_e = strtoul(argv[i+1], NULL, 10);
			if ((arg.find("-p") == 0) && (idx < (size_t)(argc - 1)) && (port.length() == 0))
				port = argv[i+1];
			if ((arg.find("-W") == 0) && (idx < (size_t)(argc - 1)) && (opt_W == 5))
				opt_W = strtoul(argv[i+1], NULL, 10);
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
				std::cout << "Arguments mandatory for long options are also mandatory for short options." << std::endl;
				std::cout << "  -h, --help     print this help" << std::endl;
				std::cout << "  -e TIME        expiration time of generated signature in seconds" << std::endl;
				std::cout << "  -H STRING      hostname (e.g. onion address) of this peer within PEERS" << std::endl;
				std::cout << "  -i FILENAME    create detached signature from FILENAME" << std::endl;
				std::cout << "  -k FILENAME    use keyring FILENAME" <<
					" containing external revocation keys" << std::endl;
				std::cout << "  -o FILENAME    write detached signature to FILENAME" << std::endl;
				std::cout << "  -p INTEGER     start port for built-in TCP/IP message exchange service" << std::endl;
				std::cout << "  -P STRING      exchanged passwords to protect private and broadcast channels" << std::endl;
				std::cout << "  -U STRING      policy URI tied to generated signatures" << std::endl;
				std::cout << "  -v, --version  print the version number" << std::endl;
				std::cout << "  -V, --verbose  turn on verbose output" << std::endl;
				std::cout << "  -W TIME        timeout for point-to-point messages in minutes" << std::endl;
#endif
				return 0; // not continue
			}
			if ((arg.find("-v") == 0) || (arg.find("--version") == 0))
			{
#ifndef GNUNET
				std::cout << "dkg-sign v" << version <<
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
	peers.push_back("Test2");
	peers.push_back("Test3");
	peers.push_back("Test4");
	ifilename = "Test1_output.bin";
	opt_ifilename = (char*)ifilename.c_str();
	ofilename = "Test1_output.sig";
	opt_ofilename = (char*)ofilename.c_str();
	URI = "https://savannah.nongnu.org/projects/dkgpg/";
	opt_verbose = 1;
#endif

	// check command line arguments
	if ((opt_hostname != NULL) && (opt_passwords == NULL))
	{
		std::cerr << "ERROR: option \"-P\" is necessary due to insecure network" << std::endl;
		return -1;
	}
	if (opt_ifilename == NULL)
	{
		std::cerr << "ERROR: option -i required to specify an input file" << std::endl;
		return -1;
	}
	if (peers.size() < 1)
	{
		std::cerr << "ERROR: no peers given as argument; usage: " << usage << std::endl;
		return -1;
	}

	// canonicalize peer list
	std::sort(peers.begin(), peers.end());
	std::vector<std::string>::iterator it = std::unique(peers.begin(), peers.end());
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
	}

	// initialize LibTMCG
	if (!init_libTMCG())
	{
		std::cerr << "ERROR: initialization of LibTMCG failed" << std::endl;
		return -1;
	}
	if (opt_verbose)
		std::cerr << "INFO: using LibTMCG version " << version_libTMCG() << std::endl;
	
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
		return ret;
	}

	// start interactive variant with GNUnet or otherwise a local test
#ifdef GNUNET
	static const struct GNUNET_GETOPT_CommandLineOption myoptions[] = {
		GNUNET_GETOPT_option_uint('e',
			"expiration",
			"TIME",
			"expiration time of generated signature in seconds",
			&gnunet_opt_sigexptime
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
			"create detached signature from FILENAME",
			&gnunet_opt_ifilename
		),
		GNUNET_GETOPT_option_string('k',
			"keyring",
			"FILENAME",
			"use keyring FILENAME containing external revocation keys",
			&gnunet_opt_k
		),
		GNUNET_GETOPT_option_string('o',
			"output",
			"FILENAME",
			"write detached signature to FILENAME",
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
		GNUNET_GETOPT_option_string('U',
			"URI",
			"STRING",
			"policy URI tied to signature",
			&gnunet_opt_URI
		),
		GNUNET_GETOPT_option_flag('V',
			"verbose",
			"turn on verbose output",
			&gnunet_opt_verbose
		),
		GNUNET_GETOPT_option_uint('w',
			"wait",
			"TIME",
			"minutes to wait until start of signing protocol",
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
	ret = GNUNET_PROGRAM_run(argc, argv, usage, about, myoptions, &gnunet_run,
		argv[0]);
	GNUNET_free((void *) argv);
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
				perror("ERROR: dkg-sign (pipe)");
			if (pipe(broadcast_pipefd[i][j]) < 0)
				perror("ERROR: dkg-sign (pipe)");
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
			perror("ERROR: dkg-sign (waitpid)");
		if (!WIFEXITED(wstatus))
		{
			std::cerr << "ERROR: protocol instance ";
			if (WIFSIGNALED(wstatus))
				std::cerr << pid[i] << " terminated by signal " <<
					WTERMSIG(wstatus) << std::endl;
			if (WCOREDUMP(wstatus))
				std::cerr << pid[i] << " dumped core" << std::endl;
			ret = -1;
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
				perror("ERROR: dkg-sign (close)");
			if ((close(broadcast_pipefd[i][j][0]) < 0) ||
				(close(broadcast_pipefd[i][j][1]) < 0))
			{
				perror("ERROR: dkg-sign (close)");
			}
		}
	}
	
	return ret;
}

