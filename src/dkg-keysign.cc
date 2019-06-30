/*******************************************************************************
   This file is part of Distributed Privacy Guard (DKGPG).

 Copyright (C) 2018, 2019  Heiko Stamer <HeikoStamer@gmx.net>

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
static const char *protocol = "DKGPG-keysign-1.0";

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

int								pipefd[DKGPG_MAX_N][DKGPG_MAX_N][2];
int								self_pipefd[2];
int								broadcast_pipefd[DKGPG_MAX_N][DKGPG_MAX_N][2];
int								broadcast_self_pipefd[2];
pid_t							pid[DKGPG_MAX_N];
std::vector<std::string>		peers;
bool							instance_forked = false;

tmcg_openpgp_secure_string_t	passphrase;
std::string						ifilename, ofilename, kfilename;
std::string						Kfilename, fingerprint;
std::string						passwords, hostname, port, URI, u, yfilename;

int 							opt_verbose = 0;
char							*opt_ifilename = NULL;
char							*opt_ofilename = NULL;
char							*opt_passwords = NULL;
char							*opt_hostname = NULL;
char							*opt_URI = NULL;
char							*opt_u = NULL;
char							*opt_k = NULL;
char							*opt_K = NULL;
char							*opt_fingerprint = NULL;
char							*opt_y = NULL;
unsigned long int				opt_e = 0, opt_p = 55000, opt_W = 5;
bool							opt_1 = false, opt_2 = false, opt_3 = false;
bool							opt_a = false, opt_r = false;

void run_instance
	(size_t whoami, const time_t sigtime, const time_t sigexptime,
	 const size_t num_xtests)
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

	// read the public key
	bool parse_ok;
	std::string armored_pubkey;
	if (opt_ifilename != NULL)
	{
		if (!read_key_file(opt_ifilename, armored_pubkey))
			exit(-1);
	}
	else if (opt_K != NULL)
	{
		std::string armored_certring;
		if (!read_key_file(Kfilename, armored_certring))
			exit(-1);
		TMCG_OpenPGP_Keyring *certring = NULL;
		int opt_verbose_ring = opt_verbose;
		if (opt_verbose_ring > 0)
			opt_verbose_ring--;
		parse_ok = CallasDonnerhackeFinneyShawThayerRFC4880::
			PublicKeyringParse(armored_certring, opt_verbose_ring, certring);
		if (!parse_ok)
		{
			std::cerr << "ERROR: cannot use the given keyring" << std::endl;
			exit(-1);
		}
		if (!get_key_by_fingerprint(certring, fingerprint, opt_verbose,
			armored_pubkey))
		{
			if (!get_key_by_keyid(certring, fingerprint, opt_verbose,
				armored_pubkey))
			{
				std::cerr << "ERROR: public key not found in keyring" <<
					std::endl;
				delete certring;
				exit(-1);
			}
		}
		delete certring;
	}

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
	if (opt_k)
	{
		int opt_verbose_ring = opt_verbose;
		if (opt_verbose_ring > 0)
			opt_verbose_ring--;
		parse_ok = CallasDonnerhackeFinneyShawThayerRFC4880::
			PublicKeyringParse(armored_pubring, opt_verbose_ring, ring);
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
	if (!prv->pub->valid || prv->Weak(opt_verbose))
	{
		std::cerr << "ERROR: primary key is invalid or weak" << std::endl;
		delete ring;
		delete prv;
		exit(-1);
	}
	if ((prv->pkalgo != TMCG_OPENPGP_PKALGO_EXPERIMENTAL7) && (opt_y == NULL))
	{
		std::cerr << "ERROR: primary key is not a tDSS/DSA key" << std::endl;
		delete ring;
		delete prv;
		exit(-1);
	}

	// parse the public key block and corresponding signatures
	TMCG_OpenPGP_Pubkey *primary = NULL;
	parse_ok = CallasDonnerhackeFinneyShawThayerRFC4880::
		PublicKeyBlockParse(armored_pubkey, opt_verbose, primary);
	if (parse_ok)
	{
		primary->CheckSelfSignatures(ring, opt_verbose);
		if (!primary->valid)
		{
			std::cerr << "ERROR: primary key to sign is not valid" << std::endl;
			delete primary;
			delete ring;
			delete prv;
			exit(-1);
		}
		if (primary->Weak(opt_verbose))
		{
			std::cerr << "ERROR: weak primary key to sign is not allowed" <<
				std::endl;
			delete primary;
			delete ring;
			delete prv;
			exit(-1);
		}
		primary->Reduce(); // keep only valid user IDs and user attributes
	}
	else
	{
		std::cerr << "ERROR: cannot use the provided public key" << std::endl;
		delete ring;
		delete prv;
		exit(-1);
	}
	delete ring;

	// initialize signature scheme
	CanettiGennaroJareckiKrawczykRabinDSS *dss = NULL;
	aiounicast_select *aiou = NULL, *aiou2 = NULL;
	CachinKursawePetzoldShoupRBC *rbc = NULL;
	size_t T_RBC = 0;
	time_t csigtime = 0;
	tmcg_openpgp_hashalgo_t hashalgo = TMCG_OPENPGP_HASHALGO_UNKNOWN;
	if (opt_y == NULL)
	{
		// create an instance of tDSS by stored parameters from private key
		if (!init_tDSS(prv, opt_verbose, dss))
		{
			delete dss;
			delete primary;
			delete prv;
			exit(-1);
		}
		// create one-to-one mapping based on the stored canonicalized peer list
		if (!prv->tDSS_CreateMapping(peers, opt_verbose))
		{
			std::cerr << "ERROR: creating 1-to-1 CAPL mapping failed" <<
				std::endl;
			delete dss;
			delete primary;
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
					std::cerr << "ERROR: p_" << whoami << ": " <<
						"cannot read password for protecting channel to p_" <<
						i << std::endl;
					delete dss;
					delete primary;
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
					delete dss;
					delete primary;
					delete prv;
					exit(-1);
				}
			}
			else
			{
				// simple key -- we assume that GNUnet provides secure channels
				key << "dkg-keysign::p_" << (i + whoami);
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
		std::string myID = "dkg-keysign|" + std::string(protocol) + "|";
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
			std::cerr << "ERROR: p_" << whoami << ": selecting hash" <<
				" algorithm failed for |q| = " << mpz_sizeinbase(dss->q, 2L) <<
				std::endl;
			delete rbc, delete aiou, delete aiou2;
			delete dss;
			delete primary;
			delete prv;
			exit(-1);
		}
	}
	else
	{
		csigtime = sigtime;
		hashalgo = TMCG_OPENPGP_HASHALGO_SHA512;
	}

	// prepare the fingerprint, the trailer, and the accumulator of the
	// certification (revocation) signatures
	std::string fpr;
	tmcg_openpgp_octets_t trailer, acc;
	CallasDonnerhackeFinneyShawThayerRFC4880::
		FingerprintConvertPretty(primary->fingerprint, fpr);
	if (opt_y == NULL)
	{
		if (opt_r)
			CallasDonnerhackeFinneyShawThayerRFC4880::
				PacketSigPrepareCertificationSignature(
					TMCG_OPENPGP_SIGNATURE_CERTIFICATION_REVOCATION,
					hashalgo, csigtime, sigexptime, URI, prv->pub->fingerprint,
					trailer);
		else if (opt_1)
			CallasDonnerhackeFinneyShawThayerRFC4880::
				PacketSigPrepareCertificationSignature(
					TMCG_OPENPGP_SIGNATURE_PERSONA_CERTIFICATION,
					hashalgo, csigtime, sigexptime, URI, prv->pub->fingerprint,
					trailer);
		else if (opt_2)
			CallasDonnerhackeFinneyShawThayerRFC4880::
				PacketSigPrepareCertificationSignature(
					TMCG_OPENPGP_SIGNATURE_CASUAL_CERTIFICATION,
					hashalgo, csigtime, sigexptime, URI, prv->pub->fingerprint,
					trailer);
		else if (opt_3)
			CallasDonnerhackeFinneyShawThayerRFC4880::
				PacketSigPrepareCertificationSignature(
					TMCG_OPENPGP_SIGNATURE_POSITIVE_CERTIFICATION,
					hashalgo, csigtime, sigexptime, URI, prv->pub->fingerprint,
					trailer);
		else
			CallasDonnerhackeFinneyShawThayerRFC4880::
				PacketSigPrepareCertificationSignature(
					TMCG_OPENPGP_SIGNATURE_GENERIC_CERTIFICATION,
					hashalgo, csigtime, sigexptime, URI, prv->pub->fingerprint,
					trailer);
	}
	else
	{
		if (opt_r)
			CallasDonnerhackeFinneyShawThayerRFC4880::
				PacketSigPrepareCertificationSignature(
					TMCG_OPENPGP_SIGNATURE_CERTIFICATION_REVOCATION, prv->pkalgo,
					hashalgo, csigtime, sigexptime, URI, prv->pub->fingerprint,
					trailer);
		else if (opt_1)
			CallasDonnerhackeFinneyShawThayerRFC4880::
				PacketSigPrepareCertificationSignature(
					TMCG_OPENPGP_SIGNATURE_PERSONA_CERTIFICATION, prv->pkalgo,
					hashalgo, csigtime, sigexptime, URI, prv->pub->fingerprint,
					trailer);
		else if (opt_2)
			CallasDonnerhackeFinneyShawThayerRFC4880::
				PacketSigPrepareCertificationSignature(
					TMCG_OPENPGP_SIGNATURE_CASUAL_CERTIFICATION, prv->pkalgo,
					hashalgo, csigtime, sigexptime, URI, prv->pub->fingerprint,
					trailer);
		else if (opt_3)
			CallasDonnerhackeFinneyShawThayerRFC4880::
				PacketSigPrepareCertificationSignature(
					TMCG_OPENPGP_SIGNATURE_POSITIVE_CERTIFICATION, prv->pkalgo,
					hashalgo, csigtime, sigexptime, URI, prv->pub->fingerprint,
					trailer);
		else
			CallasDonnerhackeFinneyShawThayerRFC4880::
				PacketSigPrepareCertificationSignature(
					TMCG_OPENPGP_SIGNATURE_GENERIC_CERTIFICATION, prv->pkalgo,
					hashalgo, csigtime, sigexptime, URI, prv->pub->fingerprint,
					trailer);
	}
	acc.insert(acc.end(), primary->packet.begin(), primary->packet.end());

	// loop through all or selected valid user IDs
	bool anything_signed = false;
	for (size_t j = 0; j < primary->userids.size(); j++)
	{
		// user ID not selected?
		if (opt_u && (primary->userids[j]->userid.find(u) ==
			primary->userids[j]->userid.npos))
				continue; // skip this user ID
		// compute the hash of the certified key resp. user ID
		tmcg_openpgp_octets_t hash, left, empty;
		CallasDonnerhackeFinneyShawThayerRFC4880::
			CertificationHash(primary->pub_hashing, primary->userids[j]->userid,
				empty, trailer, hashalgo, hash, left);
		if (opt_r)
			std::cerr << "INFO: going to revoke signature on user ID \"" <<
				primary->userids[j]->userid_sanitized << "\" of key with" <<
				" fingerprint [ " << fpr << " ]" << std::endl;
		else
			std::cerr << "INFO: going to sign user ID \"" <<
				primary->userids[j]->userid_sanitized << "\" of key with" <<
				" fingerprint [ " << fpr << "]" << std::endl;
		if (opt_a)
		{
			std::string p = "Please confirm operation by entering the string";
			if (!check_confirmation(p))
			{
				std::cerr << "WARNING: operation has been cancelled" <<
					std::endl;
				continue;
			}
		}
		anything_signed = true;

		// sign the hash value
		tmcg_openpgp_octets_t sig;
		if (!sign_hash(hash, trailer, left, whoami, peers.size(), prv, hashalgo,
			sig, opt_verbose, opt_y, dss, aiou, rbc))
		{
			if (opt_y == NULL)
			{
				delete rbc, delete aiou, delete aiou2;
				delete dss;
			}
			delete primary;
			delete prv;
			exit(-1);
		}

		// attach the generated certification (revocation) signature to
		// public key, selected user IDs, and exportable self-signatures
		// of these user IDs
		acc.insert(acc.end(), primary->userids[j]->packet.begin(),
			primary->userids[j]->packet.end());
		for (size_t i = 0; i < primary->userids[j]->selfsigs.size(); i++)
		{
			if (primary->userids[j]->selfsigs[i]->exportable)
				acc.insert(acc.end(),
					primary->userids[j]->selfsigs[i]->packet.begin(),
					primary->userids[j]->selfsigs[i]->packet.end());
		}
		acc.insert(acc.end(), sig.begin(), sig.end());
	}

	// release allocated ressources
	if (opt_y == NULL)
	{
		// at the end: deliver some more rounds for still waiting parties
		time_t synctime = (opt_W * 6);
		if (opt_verbose)
			std::cerr << "INFO: p_" << whoami << ": waiting approximately " <<
				(synctime * (T_RBC + 1)) << " seconds for stalled parties" <<
				std::endl;
		if (rbc == NULL)
			exit(-2); // should never happen: only here to make scan-build happy
		rbc->Sync(synctime);
		// release RBC
		delete rbc;
		// release handles (both channels)
		if (opt_verbose)
		{
			std::cerr << "INFO: p_" << whoami << ": unicast channels";
			aiou->PrintStatistics(std::cerr);
			std::cerr << std::endl;
			std::cerr << "INFO: p_" << whoami << ": broadcast channel";
			aiou2->PrintStatistics(std::cerr);
			std::cerr << std::endl;
		}
		// release asynchronous unicast and broadcast
		delete aiou, delete aiou2;
		// release threshold signature scheme
		delete dss;
	}
	delete primary;
	delete prv;

	// check the result
	if (!anything_signed)
	{
		std::cerr << "ERROR: no user ID selected and signed" << std::endl;
		exit(-2);
	}

	// output the result
	std::string signedkey;
	CallasDonnerhackeFinneyShawThayerRFC4880::
		ArmorEncode(TMCG_OPENPGP_ARMOR_PUBLIC_KEY_BLOCK, acc, signedkey);
	if (opt_ofilename != NULL)
	{
		if (!write_message(opt_ofilename, signedkey))
			exit(-1);
	}
	else
		std::cout << signedkey << std::endl;
}

#ifdef GNUNET
char *gnunet_opt_hostname = NULL;
char *gnunet_opt_ifilename = NULL;
char *gnunet_opt_ofilename = NULL;
char *gnunet_opt_passwords = NULL;
char *gnunet_opt_port = NULL;
char *gnunet_opt_u = NULL;
char *gnunet_opt_URI = NULL;
char *gnunet_opt_K = NULL;
char *gnunet_opt_fingerprint = NULL;
char *gnunet_opt_k = NULL;
char *gnunet_opt_y = NULL;
unsigned int gnunet_opt_sigexptime = 0;
unsigned int gnunet_opt_xtests = 0;
unsigned int gnunet_opt_wait = 5;
unsigned int gnunet_opt_W = opt_W;
int gnunet_opt_verbose = 0;
int gnunet_opt_1 = 0, gnunet_opt_2 = 0, gnunet_opt_3 = 0;
int gnunet_opt_a = 0, gnunet_opt_r = 0;
#endif

void fork_instance
	(const size_t whoami)
{
	if ((pid[whoami] = fork()) < 0)
		perror("ERROR: dkg-keysign (fork)");
	else
	{
		if (pid[whoami] == 0)
		{
			/* BEGIN child code: participant p_i */
			time_t sigtime = time(NULL);
#ifdef GNUNET
			run_instance(whoami, sigtime, gnunet_opt_sigexptime,
				gnunet_opt_xtests);
#else
			run_instance(whoami, sigtime, opt_e, 0);
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
	static const char *usage = "dkg-keysign [OPTIONS] -i INPUTFILE PEERS";
#ifdef GNUNET
	char *loglev = NULL;
	char *logfile = NULL;
	char *cfg_fn = NULL;
	static const struct GNUNET_GETOPT_CommandLineOption options[] = {
		GNUNET_GETOPT_option_cfgfile(&cfg_fn),
		GNUNET_GETOPT_option_help(about),
		GNUNET_GETOPT_option_flag('1',
			"one",
			"issuer has not done any verification of the claim of identity",
			&gnunet_opt_1
		),
		GNUNET_GETOPT_option_flag('2',
			"two",
			"issuer has done some casual verification of the claim of identity",
			&gnunet_opt_2
		),
		GNUNET_GETOPT_option_flag('3',
			"three",
			"issuer has done substantial verification of the claim of identity",
			&gnunet_opt_3
		),
		GNUNET_GETOPT_option_flag('a',
			"ask",
			"require confirmation from STDIN for each signature",
			&gnunet_opt_a
		),
		GNUNET_GETOPT_option_uint('e',
			"expiration",
			"INTEGER",
			"expiration time of generated signature in seconds",
			&gnunet_opt_sigexptime
		),
		GNUNET_GETOPT_option_string('f',
			"fingerprint",
			"STRING",
			"fingerprint of the public key for certification",
			&gnunet_opt_fingerprint
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
			"create certification signature on key resp. user ID from FILENAME",
			&gnunet_opt_ifilename
		),
		GNUNET_GETOPT_option_string('K',
			"keys",
			"FILENAME",
			"select public key for certification from keyring FILENAME",
			&gnunet_opt_K
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
			"write key with certification signature attached to FILENAME",
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
		GNUNET_GETOPT_option_flag('r',
			"revocation",
			"create a certification revocation signature",
			&gnunet_opt_r
		),
		GNUNET_GETOPT_option_string('u',
			"userid",
			"STRING",
			"sign only valid user IDs containing STRING",
			&gnunet_opt_u
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
			"INTEGER",
			"minutes to wait until start of signing protocol",
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
	if (gnunet_opt_URI != NULL)
		opt_URI = gnunet_opt_URI;
	if (gnunet_opt_u != NULL)
		opt_u = gnunet_opt_u;
	if (gnunet_opt_K != NULL)
		opt_K = gnunet_opt_K;
	if (gnunet_opt_fingerprint != NULL)
		opt_fingerprint = gnunet_opt_fingerprint;
	if (gnunet_opt_k != NULL)
		opt_k = gnunet_opt_k;
	if (gnunet_opt_passwords != NULL)
		passwords = gnunet_opt_passwords; // get passwords from GNUnet options
	if (gnunet_opt_hostname != NULL)
		hostname = gnunet_opt_hostname; // get hostname from GNUnet options
	if (gnunet_opt_W != opt_W)
		opt_W = gnunet_opt_W; // get aiou message timeout from GNUnet options
	if (gnunet_opt_URI != NULL)
		URI = gnunet_opt_URI; // get policy URI from GNUnet options
	if (gnunet_opt_u != NULL)
		u = gnunet_opt_u; // get policy URI from GNUnet options
	if (gnunet_opt_K != NULL)
		Kfilename = gnunet_opt_K; // get keyring from GNUnet options
	if (gnunet_opt_fingerprint != NULL)
		fingerprint = gnunet_opt_fingerprint; // get fingerprint from GNUnet options
	if (gnunet_opt_k != NULL)
		kfilename = gnunet_opt_k; // get keyring from GNUnet options
	if (gnunet_opt_y != NULL)
		opt_y = gnunet_opt_y; // get yaot filename from GNUnet options
#endif

	// parse options and create peer list from remaining arguments
	for (size_t i = 0; i < (size_t)(argc - 1); i++)
	{
		std::string arg = argv[i+1];
		// options with one argument
		if ((arg.find("-c") == 0) || (arg.find("-p") == 0) ||
			(arg.find("-w") == 0) || (arg.find("-W") == 0) || 
		    (arg.find("-L") == 0) || (arg.find("-l") == 0) ||
			(arg.find("-i") == 0) || (arg.find("-o") == 0) || 
		    (arg.find("-e") == 0) || (arg.find("-x") == 0) ||
			(arg.find("-P") == 0) || (arg.find("-H") == 0) ||
		    (arg.find("-u") == 0) || (arg.find("-U") == 0) ||
			(arg.find("-K") == 0) || (arg.find("-k") == 0) ||
			(arg.find("-f") == 0) || (arg.find("-y") == 0))
		{
			size_t idx = ++i;
			if ((arg.find("-f") == 0) && (idx < (size_t)(argc - 1)) &&
				(opt_fingerprint == NULL))
			{
				fingerprint = argv[i+1];
				opt_fingerprint = (char*)fingerprint.c_str();
			}
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
			if ((arg.find("-u") == 0) && (idx < (size_t)(argc - 1)) &&
				(opt_u == NULL))
			{
				u = argv[i+1];
				opt_u = (char*)u.c_str();
			}
			if ((arg.find("-U") == 0) && (idx < (size_t)(argc - 1)) &&
				(opt_URI == NULL))
			{
				URI = argv[i+1];
				opt_URI = (char*)URI.c_str();
			}
			if ((arg.find("-K") == 0) && (idx < (size_t)(argc - 1)) &&
				(opt_K == NULL))
			{
				Kfilename = argv[i+1];
				opt_K = (char*)Kfilename.c_str();
			}
			if ((arg.find("-k") == 0) && (idx < (size_t)(argc - 1)) &&
				(opt_k == NULL))
			{
				kfilename = argv[i+1];
				opt_k = (char*)kfilename.c_str();
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
		else if ((arg.find("--") == 0) || (arg.find("-a") == 0) ||
			(arg.find("-r") == 0) || (arg.find("-v") == 0) ||
			(arg.find("-h") == 0) || (arg.find("-V") == 0) ||
			(arg.find("-1") == 0) || (arg.find("-2") == 0) ||
			(arg.find("-3") == 0))
		{
			if ((arg.find("-h") == 0) || (arg.find("--help") == 0))
			{
#ifndef GNUNET
				std::cout << usage << std::endl;
				std::cout << about << std::endl;
				std::cout << "Arguments mandatory for long options are also" <<
					" mandatory for short options." << std::endl;
				std::cout << "  -1, --one        issuer has not done any" <<
					" verification of claim of identity" << std::endl;
				std::cout << "  -2, --two        issuer has done some casual" <<
					" verification of claim of identity" << std::endl;
				std::cout << "  -3, --three      issuer has done substantial" <<
					" verification of claim of identity" << std::endl;
				std::cout << "  -a, --ask        require confirmation from" <<
					" STDIN for each signature" << std::endl;
				std::cout << "  -e INTEGER       expiration time of" <<
					" generated signatures in seconds" << std::endl;
				std::cout << "  -f STRING        fingerprint of the public" <<
					" key for certification" << std::endl;
				std::cout << "  -H STRING        hostname (e.g. onion" <<
					" address) of this peer within PEERS" << std::endl;
				std::cout << "  -h, --help       print this help" << std::endl;
				std::cout << "  -i FILENAME      create certification" <<
					" signatures on key from FILENAME" << std::endl;
				std::cout << "  -K FILENAME      select public key for" <<
					" certification from keyring FILENAME" << std::endl;
				std::cout << "  -k FILENAME      use keyring FILENAME" <<
					" containing external revocation keys" << std::endl;
				std::cout << "  -o FILENAME      write key with" <<
					" certification signatures attached to FILENAME" <<
					std::endl;
				std::cout << "  -p INTEGER       start port for built-in" <<
					" TCP/IP message exchange service" << std::endl;
				std::cout << "  -P STRING        exchanged passwords to" <<
					" protect private and broadcast channels" << std::endl;
				std::cout << "  -r, --revocation create certification" <<
					" revocation signatures" << std::endl;
				std::cout << "  -u STRING        sign only valid user IDs" <<
					" containing STRING" << std::endl;
				std::cout << "  -U STRING        policy URI tied to" <<
					" generated signatures" << std::endl;
				std::cout << "  -v, --version    print the version number" <<
					std::endl;
				std::cout << "  -V, --verbose    turn on verbose output" <<
					std::endl;
				std::cout << "  -W INTEGER       timeout for point-to-point" <<
					" messages in minutes" << std::endl;
				std::cout << "  -y FILENAME    yet another OpenPGP tool with" <<
					" private key in FILENAME" << std::endl;
#endif
				return 0; // not continue
			}
			if ((arg.find("-a") == 0) || (arg.find("--ask") == 0))
				opt_a = true; // require confirmation
			if ((arg.find("-r") == 0) || (arg.find("--revocation") == 0))
				opt_r = true; // create revocation signature
			if ((arg.find("-v") == 0) || (arg.find("--version") == 0))
			{
#ifndef GNUNET
				std::cout << "dkg-keysign v" << version <<
					" without GNUNET support" << std::endl;
#endif
				return 0; // not continue
			}
			if ((arg.find("-V") == 0) || (arg.find("--verbose") == 0))
				opt_verbose++; // increase verbosity
			if ((arg.find("-1") == 0) || (arg.find("--one") == 0))
				opt_1 = true, opt_2 = false, opt_3 = false;
			if ((arg.find("-2") == 0) || (arg.find("--two") == 0))
				opt_1 = false, opt_2 = true, opt_3 = false;
			if ((arg.find("-3") == 0) || (arg.find("--three") == 0))
				opt_1 = false, opt_2 = false, opt_3 = true;
			continue;
		}
		else if (arg.find("-") == 0)
		{
			std::cerr << "ERROR: unknown option \"" << arg << "\"" << std::endl;
			return -1;
		}
		// store remaining argument for peer list
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
	peers.push_back("Test4");
	ifilename = "Test1_dkg-pub.asc";
	opt_ifilename = (char*)ifilename.c_str();
	ofilename = "Test1_dkg-pub_signed.asc";
	opt_ofilename = (char*)ofilename.c_str();
	opt_e = 44203;
	URI = "https://savannah.nongnu.org/projects/dkgpg/";
	opt_verbose = 2;
#else
#ifdef DKGPG_TESTSUITE_Y
	yfilename = "TestY-sec.asc";
	opt_y = (char*)yfilename.c_str();
	ifilename = "TestY-pub.asc";
	opt_ifilename = (char*)ifilename.c_str();
	ofilename = "TestY-pub_signed.asc";
	opt_ofilename = (char*)ofilename.c_str();
	opt_e = 44203;
	URI = "https://savannah.nongnu.org/projects/dkgpg/";
	opt_verbose = 2;
#endif
#endif

	// check command line arguments
	if ((opt_ifilename == NULL) && (opt_K == NULL))
	{
		std::cerr << "ERROR: option \"-i\" or \"-K\" is required to specify" <<
			" an input file" << std::endl;
		return -1;
	}
	if ((opt_K != NULL) && (opt_fingerprint == NULL))
	{
		std::cerr << "ERROR: option \"-f\" is required to select public key" <<
			" for certification" << std::endl;
		return -1;
	}
	if ((opt_hostname != NULL) && (opt_passwords == NULL) && (opt_y == NULL))
	{
		std::cerr << "ERROR: option \"-P\" is necessary due to insecure" <<
			" network" << std::endl;
		return -1;
	}
	if ((peers.size() < 1) && (opt_y == NULL))
	{
		std::cerr << "ERROR: no peers given as argument; usage: " <<
			usage << std::endl;
		return -1;
	}
	canonicalize(peers);
	if (((peers.size() < 3)  || (peers.size() > DKGPG_MAX_N)) && (opt_y == NULL))
	{
		std::cerr << "ERROR: too few or too many peers given" << std::endl;
		return -1;
	}
	if (opt_verbose && (opt_y == NULL))
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
		std::cerr << "INFO: using LibTMCG version " << version_libTMCG() <<
			std::endl;
	
	// initialize return code and do the main work
	int ret = 0;
	if ((opt_hostname != NULL) && (opt_y == NULL))
	{
		// start interactive variant, if built-in TCP/IP requested
		ret = run_tcpip(peers.size(), opt_p, hostname, port);
	}
	else if (opt_y != NULL)
	{
		// start a single instance as replacement for GnuPG et al.
		fork_instance(0);
		ret = wait_instance(0, opt_verbose, pid);
	}
	else
	{
		// start interactive variant with GNUnet or otherwise a local test
#ifdef GNUNET
		static const struct GNUNET_GETOPT_CommandLineOption myoptions[] = {
			GNUNET_GETOPT_option_flag('1',
				"one",
				"issuer has not done any verification of the claim of identity",
				&gnunet_opt_1
			),
			GNUNET_GETOPT_option_flag('2',
				"two",
				"issuer has done some casual verification of the claim of identity",
				&gnunet_opt_2
			),
			GNUNET_GETOPT_option_flag('3',
				"three",
				"issuer has done substantial verification of the claim of identity",
				&gnunet_opt_3
			),
			GNUNET_GETOPT_option_flag('a',
				"ask",
				"require confirmation from STDIN for each signature",
				&gnunet_opt_a
			),
			GNUNET_GETOPT_option_uint('e',
				"expiration",
				"INTEGER",
				"expiration time of generated signature in seconds",
				&gnunet_opt_sigexptime
			),
			GNUNET_GETOPT_option_string('f',
				"fingerprint",
				"STRING",
				"fingerprint of the public key for certification",
				&gnunet_opt_fingerprint
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
				"create certification signature on key resp. user ID from FILENAME",
				&gnunet_opt_ifilename
			),
			GNUNET_GETOPT_option_string('K',
				"keys",
				"FILENAME",
				"select public key for certification from keyring FILENAME",
				&gnunet_opt_K
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
				"write key with certification signature attached to FILENAME",
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
			GNUNET_GETOPT_option_flag('r',
				"revocation",
				"create a certification revocation signature",
				&gnunet_opt_r
			),
			GNUNET_GETOPT_option_string('u',
				"userid",
				"STRING",
				"sign only valid user IDs containing STRING",
				&gnunet_opt_u
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
				"INTEGER",
				"minutes to wait until start of signing protocol",
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

