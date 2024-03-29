/*******************************************************************************
   This file is part of Distributed Privacy Guard (DKGPG).

 Copyright (C) 2018, 2019, 2022  Heiko Stamer <HeikoStamer@gmx.net>

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
int							self_pipefd[2];
int							broadcast_pipefd[DKGPG_MAX_N][DKGPG_MAX_N][2];
int							broadcast_self_pipefd[2];
pid_t 						pid[DKGPG_MAX_N];
std::vector<std::string>	peers;
bool						instance_forked = false;

tmcg_openpgp_secure_string_t	passphrase;
std::string						kfilename, userid;
std::string						passwords, hostname, port, yfilename;

int 							opt_verbose = 0;
unsigned long int				opt_p = 55000, opt_W = 5;

void run_instance
	(size_t whoami, const time_t sigtime, const size_t num_xtests)
{
	// read the key file
	std::string armored_seckey, pkfname;
	if (yfilename.length() > 0)
		pkfname = yfilename;
	else
		pkfname = peers[whoami] + "_dkg-sec.asc";
	if (opt_verbose > 1)
	{
		std::cerr << "INFO: private key expected in file \"" << pkfname <<
			"\"" << std::endl;
	}
	if (!check_strict_permissions(pkfname))
	{
		std::cerr << "WARNING: weak permissions of private key file" <<
			" detected" << std::endl;
		if (!set_strict_permissions(pkfname))
			exit(-1);
	}
	if (!read_key_file(pkfname, armored_seckey))
		exit(-1);

	// read the (ASCII-armored) keyring from file
	std::string armored_pubring;
	if (kfilename.length() > 0)
	{
		if (!autodetect_file(kfilename, TMCG_OPENPGP_ARMOR_PUBLIC_KEY_BLOCK,
			armored_pubring))
		{
			exit(-1);
		}
	}

	// parse the keyring, the private key and corresponding signatures
	TMCG_OpenPGP_Prvkey *prv = NULL;
	TMCG_OpenPGP_Keyring *ring = NULL;
	bool parse_ok;
	if (kfilename.length() > 0)
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
		if (!get_passphrase("Enter passphrase to unlock private key", false,
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
	delete ring;
	if (!prv->pub->valid ||
		((yfilename.length() == 0) && prv->Weak(opt_verbose)))
	{
		std::cerr << "ERROR: primary key is invalid or weak" << std::endl;
		delete prv;
		exit(-1);
	}
	if ((prv->pkalgo != TMCG_OPENPGP_PKALGO_EXPERIMENTAL7) &&
		(yfilename.length() == 0))
	{
		std::cerr << "ERROR: primary key is not a tDSS/DSA key" << std::endl;
		delete prv;
		exit(-1);
	}

	// check whether user ID is already present
	for (size_t i = 0; i < prv->pub->userids.size(); i++)
	{
		if (userid == prv->pub->userids[i]->userid)
		{
			std::cerr << "ERROR: user ID already present" << std::endl;
			delete prv;
			exit(-2);
		}
	}

	// initialize signature scheme
	CanettiGennaroJareckiKrawczykRabinDSS *dss = NULL;
	aiounicast_select *aiou = NULL, *aiou2 = NULL;
	CachinKursawePetzoldShoupRBC *rbc = NULL;
	size_t T_RBC = 0;
	time_t csigtime = 0;
	tmcg_openpgp_hashalgo_t hashalgo = TMCG_OPENPGP_HASHALGO_UNKNOWN;
	if (yfilename.length() == 0)
	{
		// create an instance of tDSS by stored parameters from private key
		if (!init_tDSS(prv, opt_verbose, dss))
		{
			delete dss;
			delete prv;
			exit(-1);
		}
		// create one-to-one mapping based on the stored canonicalized peer list
		if (!prv->tDSS_CreateMapping(peers, opt_verbose))
		{
			std::cerr << "ERROR: creating 1-to-1 CAPL mapping failed" << std::endl;
			delete dss;
			delete prv;
			exit(-1);
		}
		// create communication handles between all players
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
					std::cerr << "ERROR: P_" << whoami << ": " <<
						"cannot read password for protecting channel to P_" <<
						i << std::endl;
					delete dss;
					delete prv;
					exit(-1);
				}
				key << pwd;
				if (((i + 1) < peers.size()) &&
					!TMCG_ParseHelper::nx(passwords, '/'))
				{
					std::cerr << "ERROR: P_" << whoami << ": " << "cannot" <<
						" skip to next password for protecting channel to P_" <<
						(i + 1) << std::endl;
					delete dss;
					delete prv;
					exit(-1);
				}
			}
			else
			{
				// simple key -- we assume that GNUnet provides secure channels
				key << "dkg-adduid::P_" << (i + whoami);
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
		// create asynchronous authenticated unicast channels
		aiou = new aiounicast_select(peers.size(), whoami, uP_in, uP_out,
			uP_key, aiounicast::aio_scheduler_roundrobin, (opt_W * 60));
		// create asynchronous authenticated unicast channels for broadcast
		aiou2 = new aiounicast_select(peers.size(), whoami, bP_in, bP_out,
			bP_key, aiounicast::aio_scheduler_roundrobin, (opt_W * 60));
		// create an instance of a reliable broadcast protocol (RBC)
		std::string myID = "dkg-adduid|" + std::string(protocol) + "|";
		for (size_t i = 0; i < peers.size(); i++)
			myID += peers[i] + "|";
		if (opt_verbose)
			std::cerr << "RBC: myID = " << myID << std::endl;
		// assume maximum asynchronous t-resilience for RBC
		T_RBC = (peers.size() - 1) / 3;
		rbc = new CachinKursawePetzoldShoupRBC(peers.size(), T_RBC, whoami,
				aiou2, aiounicast::aio_scheduler_roundrobin, (opt_W * 60));
		rbc->setID(myID);
		// perform a simple exchange test with debug output
		xtest(num_xtests, whoami, peers.size(), rbc);
		// participants must agree on a common signature creation time (OpenPGP)
		csigtime = agree_time(sigtime, whoami, peers.size(), opt_verbose, rbc);
		// select hash algorithm for OpenPGP based on |q| (size in bit)
		if (!select_hashalgo(dss, hashalgo))
		{
			std::cerr << "ERROR: P_" << whoami << ": selecting hash" <<
				" algorithm failed for |q| = " << mpz_sizeinbase(dss->q, 2L) <<
				std::endl;
			delete rbc, delete aiou, delete aiou2;
			delete dss;
			delete prv;
			exit(-1);
		}
	}
	else
	{
		csigtime = sigtime;
		hashalgo = TMCG_OPENPGP_HASHALGO_SHA512; // fixed hash algo SHA2-512
	}

	// prepare OpenPGP structures
	tmcg_openpgp_octets_t uat;
	tmcg_openpgp_octets_t uid, uidsig, uidsig_hashing, uidsig_left;
	tmcg_openpgp_octets_t hash;
	CallasDonnerhackeFinneyShawThayerRFC4880::PacketUidEncode(userid, uid);
	CallasDonnerhackeFinneyShawThayerRFC4880::
		PacketSigPrepareSelfSignature(TMCG_OPENPGP_SIGNATURE_POSITIVE_CERTIFICATION,
			hashalgo, csigtime, prv->pub->expirationtime, prv->pub->flags,
			prv->pub->fingerprint, uidsig_hashing); 
	CallasDonnerhackeFinneyShawThayerRFC4880::
		CertificationHash(prv->pub->pub_hashing, userid, uat, uidsig_hashing,
			hashalgo, hash, uidsig_left);

	// sign the hash value
	if (!sign_hash(hash, uidsig_hashing, uidsig_left, whoami, peers.size(), prv,
		hashalgo, uidsig, opt_verbose, (yfilename.length() > 0), dss, aiou, rbc))
	{
		if (yfilename.length() == 0)
		{
			delete rbc, delete aiou, delete aiou2;
			delete dss;
		}
		delete prv;
		exit(-1);
	}

	// release allocated ressources
	if ((yfilename.length() == 0) && (rbc != NULL))
	{
		// at the end: deliver some more rounds for still waiting parties
		time_t synctime = (opt_W * 6);
		if (opt_verbose)
		{
			std::cerr << "INFO: P_" << whoami << ": waiting approximately " <<
				(synctime * (T_RBC + 1)) << " seconds for stalled parties" <<
				std::endl;
		}
		rbc->Sync(synctime);
		// release RBC
		delete rbc;
		// release handles (both channels)
		if (opt_verbose)
		{
			std::cerr << "INFO: P_" << whoami << ": unicast channels";
			aiou->PrintStatistics(std::cerr);
			std::cerr << std::endl;
			std::cerr << "INFO: P_" << whoami << ": broadcast channel";
			aiou2->PrintStatistics(std::cerr);
			std::cerr << std::endl;
		}
		// release asynchronous unicast and broadcast
		delete aiou, delete aiou2;
		// release threshold signature scheme
		delete dss;
	}

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

	// export and write updated private key in OpenPGP armor format
	tmcg_openpgp_octets_t sec;
	prv->Export(sec);
	if (!write_key_file(pkfname, TMCG_OPENPGP_ARMOR_PRIVATE_KEY_BLOCK, sec))
	{
		delete prv;
		exit(-1);
	}

	// export and write updated public key in OpenPGP armor format
	tmcg_openpgp_octets_t pub;
	prv->RelinkPublicSubkeys(); // relink the contained subkeys
	prv->pub->Export(pub);
	prv->RelinkPrivateSubkeys(); // undo the relinking
	std::string armor;
	CallasDonnerhackeFinneyShawThayerRFC4880::
		ArmorEncode(TMCG_OPENPGP_ARMOR_PUBLIC_KEY_BLOCK, pub, armor);
	std::cout << armor << std::endl;
	if (yfilename.length() == 0)
	{
		std::stringstream pubfilename;
		pubfilename << peers[whoami] << "_dkg-pub.asc";
		if (!write_key_file(pubfilename.str(), armor))
		{
			delete prv;
			exit(-1);
		}
	}

	// release
	delete prv;
}

#ifdef GNUNET
char *gnunet_opt_H = NULL;
char *gnunet_opt_P = NULL;
char *gnunet_opt_k = NULL;
char *gnunet_opt_u = NULL;
char *gnunet_opt_port = NULL;
char *gnunet_opt_y = NULL;
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
			"minutes to wait until start of the protocol",
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
//		std::cerr << "ERROR: GNUNET_STRINGS_get_utf8_args() failed" << std::endl;
//		return -1;
//	}
	static const struct GNUNET_OS_ProjectData gnunet_dkgpg_pd = {
		.libname = "none",
		.project_dirname = "dkgpg",
		.binary_name = "dkg-adduid",
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
	if (gnunet_opt_H != NULL)
		hostname = gnunet_opt_H; // get hostname from GNUnet options
	if (gnunet_opt_P != NULL)
		passwords = gnunet_opt_P; // get passwords from GNUnet options
	if (gnunet_opt_u != NULL)
		userid = gnunet_opt_u; // get userid from GNUnet options
	if (gnunet_opt_k != NULL)
		kfilename = gnunet_opt_k; // get kfilename from GNUnet options
	if (gnunet_opt_W != opt_W)
		opt_W = gnunet_opt_W; // get aiou message timeout from GNUnet options
	if (gnunet_opt_y != NULL)
		yfilename = gnunet_opt_y;
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
			(arg.find("-k") == 0) || (arg.find("-y") == 0))
		{
			size_t idx = ++i;
			if ((arg.find("-H") == 0) && (idx < (size_t)(argc - 1)) &&
				(hostname.length() == 0))
			{
				hostname = argv[i+1];
			}
			if ((arg.find("-k") == 0) && (idx < (size_t)(argc - 1)) &&
				(kfilename.length() == 0))
			{
				kfilename = argv[i+1];
			}
			if ((arg.find("-P") == 0) && (idx < (size_t)(argc - 1)) &&
				(passwords.length() == 0))
			{
				passwords = argv[i+1];
			}
			if ((arg.find("-p") == 0) && (idx < (size_t)(argc - 1)) &&
				(port.length() == 0))
			{
				port = argv[i+1];
			}
			if ((arg.find("-u") == 0) && (idx < (size_t)(argc - 1)) &&
				(userid.length() == 0))
			{
				userid = argv[i+1];
			}
			if ((arg.find("-W") == 0) && (idx < (size_t)(argc - 1)) &&
				(opt_W == 5))
			{
				opt_W = strtoul(argv[i+1], NULL, 10);
			}
			if ((arg.find("-y") == 0) && (idx < (size_t)(argc - 1)) &&
				(yfilename.length() == 0))
			{
				yfilename = argv[i+1];
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
				std::cout << "  -y FILENAME    yet another OpenPGP tool with" <<
					" private key in FILENAME" << std::endl;
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
	opt_verbose = 2;
#else
#ifdef DKGPG_TESTSUITE_Y
	yfilename = "TestY-sec.asc";
	userid = "additional userID";
	opt_verbose = 2;
#endif
#endif

	// check command line arguments
	if (userid.length() == 0)
	{
		std::cerr << "ERROR: option \"-u\" required to specify an user ID" <<
			std::endl;
		return -1;
	}
	if (!valid_utf8(userid))
	{
		std::cerr << "ERROR: invalid UTF-8 encoding found in user ID" <<
			std::endl;
		return -1;
	}
	if ((hostname.length() > 0) && (passwords.length() == 0) &&
		(yfilename.length() == 0))
	{
		std::cerr << "ERROR: option \"-P\" required due to insecure network" <<
			std::endl;
		return -1;
	}
	if ((peers.size() < 1) && (yfilename.length() == 0))
	{
		std::cerr << "ERROR: no peers given as argument; usage: " <<
			usage << std::endl;
		return -1;
	}
	canonicalize(peers);
	if (((peers.size() < 3) || (peers.size() > DKGPG_MAX_N)) &&
		(yfilename.length() == 0))
	{
		std::cerr << "ERROR: too few or too many peers given" << std::endl;
		return -1;
	}
	if (opt_verbose && (yfilename.length() == 0))
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
	
	// initialize return code and do the main work
	int ret = 0;
	if ((hostname.length() > 0) && (yfilename.length() == 0))
	{
		// start interactive variant, if built-in TCP/IP requested
		ret = run_tcpip(peers.size(), opt_p, hostname, port);
	}
	else if (yfilename.length() > 0)
	{
		// run as replacement for GnuPG et al. (yet-another-openpgp-tool)
		fork_instance(0);
		ret = wait_instance(0, opt_verbose, pid);
	}
	else
	{
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
				"minutes to wait until start of the protocol",
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
		ret = GNUNET_PROGRAM_run(argc, argv, usage, about, myoptions,
			&gnunet_run, argv[0]);
		if (ret != GNUNET_OK)
			ret = -1;
#else
	ret = run_localtest(peers.size(), opt_verbose, pid, pipefd, self_pipefd,
		broadcast_pipefd, broadcast_self_pipefd, &fork_instance);
#endif
	}
	if (should_unlock)
		unlock_memory();
	return ret;
}

