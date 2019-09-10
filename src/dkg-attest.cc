/*******************************************************************************
   This file is part of Distributed Privacy Guard (DKGPG).

 Copyright (C) 2019  Heiko Stamer <HeikoStamer@gmx.net>

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
static const char *protocol = "DKGPG-attest-1.0";

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
std::string						ifilename, ofilename, kfilename, yfilename;
std::string						passwords, hostname, port, URI, u;

int 							opt_verbose = 0;
unsigned long int				opt_p = 55000, opt_W = 5;
bool							opt_w = false;

bool compare_octests
	(const tmcg_openpgp_octets_t a, const tmcg_openpgp_octets_t b)
{
	if (a.size() == b.size())
	{
		for (size_t i = 0; i < a.size(); i++)
		{
			if (a[i] != b[i])
				return (a[i] < b[i]);
		}
		return false;
	}
	else
		return (a.size() < b.size());
}

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
	if (kfilename.length() > 0)
	{
		if (!read_key_file(kfilename, armored_pubring))
			exit(-1);
	}

	// read the certification signatures (i.e. public key block)
	std::string armored_pubkey;
	if (ifilename.length() > 0)
	{
		if (!read_key_file(ifilename, armored_pubkey))
			exit(-1);
	}
	else
		read_stdin("-----END PGP PUBLIC KEY BLOCK-----", armored_pubkey);

	// parse the keyring, the private key and corresponding signatures
	TMCG_OpenPGP_Prvkey *prv = NULL;
	TMCG_OpenPGP_Keyring *ring = NULL;
	bool parse_ok;
	if (kfilename.length() > 0)
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
	if (!prv->pub->valid ||
		((yfilename.length() == 0) && prv->Weak(opt_verbose)))
	{
		std::cerr << "ERROR: private key is invalid or weak" << std::endl;
		delete ring;
		delete prv;
		exit(-1);
	}
	if ((prv->pkalgo != TMCG_OPENPGP_PKALGO_EXPERIMENTAL7) &&
		(yfilename.length() == 0))
	{
		std::cerr << "ERROR: private key is not a tDSS/DSA key" << std::endl;
		delete ring;
		delete prv;
		exit(-1);
	}

	// parse the public key block and corresponding signatures
	TMCG_OpenPGP_Pubkey *pub = NULL;
	parse_ok = CallasDonnerhackeFinneyShawThayerRFC4880::
		PublicKeyBlockParse(armored_pubkey, opt_verbose, pub);
	if (parse_ok)
	{
		pub->CheckSelfSignatures(ring, opt_verbose);
		if (!pub->valid)
		{
			std::cerr << "ERROR: public key is not valid" << std::endl;
			delete pub;
			delete ring;
			delete prv;
			exit(-1);
		}
		if (!opt_w && pub->Weak(opt_verbose))
		{
			std::cerr << "ERROR: public key is weak" << std::endl;
			delete pub;
			delete ring;
			delete prv;
			exit(-1);
		}
		pub->CheckSubkeys(ring, opt_verbose);
		pub->Reduce(); // keep only valid user IDs and user attributes
	}
	else
	{
		std::cerr << "ERROR: cannot use the provided public key" << std::endl;
		delete ring;
		delete prv;
		exit(-1);
	}

	// release keyring
	delete ring;

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
			delete pub;
			delete prv;
			exit(-1);
		}
		// create one-to-one mapping based on the stored canonicalized peer list
		if (!prv->tDSS_CreateMapping(peers, opt_verbose))
		{
			std::cerr << "ERROR: creating 1-to-1 CAPL mapping failed" <<
				std::endl;
			delete dss;
			delete pub;
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
					std::cerr << "ERROR: p_" << whoami << ": " <<
						"cannot read" << " password for protecting channel" <<
						" to p_" << i << std::endl;
					delete dss;
					delete pub;
					delete prv;
					exit(-1);
				}
				key << pwd;
				if (((i + 1) < peers.size()) &&
					!TMCG_ParseHelper::nx(passwords, '/'))
				{
					std::cerr << "ERROR: p_" << whoami << ": " << "cannot" <<
						" skip to next password for protecting channel to p_" <<
						(i + 1) << std::endl;
					delete dss;
					delete pub;
					delete prv;
					exit(-1);
				}
			}
			else
			{
				// simple key -- we assume that GNUnet provides secure channels
				key << "dkg-attest::p_" << (i + whoami);
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
		std::string myID = "dkg-attest|" + std::string(protocol) + "|";
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
		if (opt_verbose)
		{
			std::cerr << "INFO: agree on a signature creation time for" <<
				" OpenPGP" << std::endl;
		}
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
					std::cerr << "WARNING: p_" << whoami << ": no signature" <<
						" creation time received from p_" << i << std::endl;
				}
			}
		}
		mpz_clear(mtv);
		std::sort(tvs.begin(), tvs.end());
		if (tvs.size() < (peers.size() - T_RBC))
		{
			std::cerr << "ERROR: p_" << whoami << ": not enough timestamps" <<
				" received" << std::endl;
			delete rbc, delete aiou, delete aiou2;
			delete dss;
			delete pub;
			delete prv;
			exit(-1);
		}
		// use a median value as some kind of gentle agreement
		csigtime = tvs[tvs.size()/2];
		if (opt_verbose)
		{
			std::cerr << "INFO: p_" << whoami << ": canonicalized signature" <<
				" creation time = " << csigtime << std::endl;
		}
		// select hash algorithm for OpenPGP based on |q| (size in bit)
		if (!select_hashalgo(dss, hashalgo))
		{
			std::cerr << "ERROR: p_" << whoami << ": selecting hash" <<
				" algorithm failed for |q| = " << mpz_sizeinbase(dss->q, 2L) <<
				std::endl;
			delete rbc, delete aiou, delete aiou2;
			delete dss;
			delete pub;
			delete prv;
			exit(-1);
		}
	}
	else
	{
		csigtime = sigtime;
		hashalgo = TMCG_OPENPGP_HASHALGO_SHA512;
	}

	// iterate through all valid user IDs
	for (size_t i = 0; i < pub->userids.size(); i++)
	{
		// user ID selected?
		if ((u.length() > 0) && (pub->userids[i]->userid.find(u) ==
			pub->userids[i]->userid.npos))
		{
			continue; // skip this user ID
		}
		// attest to all attached certification signatures
		tmcg_openpgp_multiple_octets_t certhashes;
		for (size_t j = 0; j < pub->userids[i]->certsigs.size(); j++)
		{
			TMCG_OpenPGP_Signature *sig = pub->userids[i]->certsigs[j];
			tmcg_openpgp_octets_t sigpkt, hash_input, hash;
			// The listed digests MUST be calculated over the third-party
			// certification's Signature packet as described in the "Computing
			// Signatures" section, but without a trailer: the hash data starts
			// with the octet 0x88, followed by the four-octet length of the
			// Signature, and then the body of the Signature packet. (Note that
			// this is an old-style packet header for a Signature packet with
			// the length-of-length field set to zero.) The unhashed subpacket
			// data of the Signature packet being hashed is not included in the
			// hash, and the unhashed subpacket data length value is set to
			// zero.
			sigpkt.push_back(sig->version);
			sigpkt.push_back(sig->type);
			sigpkt.push_back(sig->pkalgo);
			sigpkt.push_back(sig->hashalgo);
			sigpkt.push_back((sig->hspd.size() >> 8) & 0xFF);
			sigpkt.push_back(sig->hspd.size() & 0xFF);
			sigpkt.insert(sigpkt.end(), sig->hspd.begin(), sig->hspd.end());
			sigpkt.push_back(0x00);
			sigpkt.push_back(0x00);
			hash_input.push_back(0x88);
			hash_input.push_back((sigpkt.size() >> 24) & 0xFF);
			hash_input.push_back((sigpkt.size() >> 16) & 0xFF);
			hash_input.push_back((sigpkt.size() >> 8) & 0xFF);
			hash_input.push_back(sigpkt.size() & 0xFF);
			hash_input.insert(hash_input.end(), sigpkt.begin(), sigpkt.end());
			CallasDonnerhackeFinneyShawThayerRFC4880::
				HashCompute(hashalgo, hash_input, hash);
			certhashes.push_back(hash);
		}
		if (certhashes.size() == 0)
		{
			if (opt_verbose)
			{
				std::cerr << "INFO: nothing to attest for user ID #" << i <<
					" (" << pub->userids[i]->certsigs.size() <<
					" 3rd-party certs)" << std::endl;
			}
			continue; // skip this user ID
		}
		std::sort(certhashes.begin(), certhashes.end(), compare_octests);
		size_t jj = 0;

		while (jj < certhashes.size())
		{
			tmcg_openpgp_octets_t attestedcerts;
			for (size_t j = jj; j < certhashes.size(); j++)
			{
				jj = j;
				if (attestedcerts.size() > 60000)
					break; // create more attestation signatures later
				attestedcerts.insert(attestedcerts.end(),
					certhashes[j].begin(), certhashes[j].end());
				jj++;
			}
			// compute the trailer and the hash of the attestation signature
			if (opt_verbose)
			{
				std::cerr << "INFO: build attestation signature for user" <<
					" ID = \"" << pub->userids[i]->userid_sanitized << "\"" <<
					std::endl;
				std::cerr << "INFO: attestedcerts.size() = " <<
					attestedcerts.size() << std::endl;
			}
			tmcg_openpgp_octets_t trailer, empty, hash, left;
			tmcg_openpgp_notations_t notations;
			if (yfilename.length() == 0)
			{
				tmcg_openpgp_pkalgo_t pkalgo = TMCG_OPENPGP_PKALGO_DSA;
				CallasDonnerhackeFinneyShawThayerRFC4880::
					PacketSigPrepareAttestationSignature(pkalgo,
						hashalgo, csigtime, URI, prv->pub->fingerprint,
						attestedcerts, notations, trailer);
			}
			else
			{
				CallasDonnerhackeFinneyShawThayerRFC4880::
					PacketSigPrepareAttestationSignature(prv->pkalgo,
						hashalgo, csigtime, URI, prv->pub->fingerprint,
						attestedcerts, notations, trailer);
			}
			CallasDonnerhackeFinneyShawThayerRFC4880::
				CertificationHash(pub->pub_hashing, pub->userids[i]->userid,
					empty, trailer, hashalgo, hash, left);
			// sign the hash value
			tmcg_openpgp_octets_t attsig;
			if (!sign_hash(hash, trailer, left, whoami, peers.size(), prv,
				hashalgo, attsig, opt_verbose, (yfilename.length() > 0), dss,
				aiou, rbc))
			{
				if (yfilename.length() == 0)
				{
					delete rbc, delete aiou, delete aiou2;
					delete dss;
				}
				delete pub;
				delete prv;
				exit(-1);
			}
			// convert attestation signature and append it to the public key
			TMCG_OpenPGP_Signature *sig = NULL;
			parse_ok = CallasDonnerhackeFinneyShawThayerRFC4880::
				SignatureParse(attsig, opt_verbose, sig);
			if (!parse_ok)
			{
				std::cerr << "ERROR: cannot use the created attestation" <<
					" signature" << std::endl;
				if (yfilename.length() == 0)
				{
					delete rbc, delete aiou, delete aiou2;
					delete dss;
				}
				delete pub;
				delete prv;
				exit(-1);
			}
			if (opt_verbose)
				sig->PrintInfo();
			pub->userids[i]->attestsigs.push_back(sig);
		}
	}

	// export the modified public key including attached attestation signatures
	tmcg_openpgp_octets_t data;
	pub->Export(data);

	// release allocated ressources
	if ((yfilename.length() == 0) && (rbc != NULL))
	{
		// at the end: deliver some more rounds for still waiting parties
		time_t synctime = (opt_W * 6);
		if (opt_verbose)
		{
			std::cerr << "INFO: p_" << whoami << ": waiting approximately " <<
				(synctime * (T_RBC + 1)) << " seconds for stalled parties" <<
				std::endl;
		}
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
	delete pub;
	delete prv;

	// output the result
	std::string datastr;
	CallasDonnerhackeFinneyShawThayerRFC4880::
		ArmorEncode(TMCG_OPENPGP_ARMOR_PUBLIC_KEY_BLOCK, data, datastr);
	if (ofilename.length() > 0)
	{
		if (!write_message(ofilename, datastr))
			exit(-1);
	}
	else
		std::cout << datastr << std::endl;
}

#ifdef GNUNET
char *gnunet_opt_H = NULL;
char *gnunet_opt_i = NULL;
char *gnunet_opt_o = NULL;
char *gnunet_opt_P = NULL;
char *gnunet_opt_port = NULL;
char *gnunet_opt_U = NULL;
char *gnunet_opt_u = NULL;
char *gnunet_opt_k = NULL;
char *gnunet_opt_y = NULL;
char *gnunet_opt_s = NULL;
unsigned int gnunet_opt_xtests = 0;
unsigned int gnunet_opt_wait = 5;
unsigned int gnunet_opt_W = opt_W;
int gnunet_opt_verbose = 0;
int gnunet_opt_w = 0;
#endif

void fork_instance
	(const size_t whoami)
{
	if ((pid[whoami] = fork()) < 0)
	{
		perror("ERROR: dkg-attest (fork)");
	}
	else
	{
		if (pid[whoami] == 0)
		{
			/* BEGIN child code: participant p_i */
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
	static const char *usage = "dkg-attest [OPTIONS] PEERS";
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
		GNUNET_GETOPT_option_string('i',
			"input",
			"FILENAME",
			"read certification signatures from FILENAME",
			&gnunet_opt_i
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
			"write generated attestation signatures to FILENAME",
			&gnunet_opt_o
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
			"userid",
			"STRING",
			"attest only valid user IDs containing STRING",
			&gnunet_opt_u
		),
		GNUNET_GETOPT_option_string('U',
			"URI",
			"STRING",
			"policy URI tied to attestation signatures",
			&gnunet_opt_U
		),
		GNUNET_GETOPT_option_version(version),
		GNUNET_GETOPT_option_flag('V',
			"verbose",
			"turn on verbose output",
			&gnunet_opt_verbose
		),
		GNUNET_GETOPT_option_flag('w',
			"weak",
			"allow weak public keys",
			&gnunet_opt_w
		),
		GNUNET_GETOPT_option_uint('W',
			"aiou-timeout",
			"INTEGER",
			"timeout for point-to-point messages in minutes",
			&gnunet_opt_W
		),
		GNUNET_GETOPT_option_string('y',
			"yaot",
			"FILENAME",
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
	static const struct GNUNET_OS_ProjectData gnunet_dkgpg_pd = {
		.libname = "none",
		.project_dirname = "dkgpg",
		.binary_name = "dkg-attest",
		.env_varname = "none",
		.env_varname_alt = "none",
		.base_config_varname = "none",
		.bug_email = "heikostamer@gmx.net",
		.homepage = "https://www.nongnu.org/dkgpg/",
		.config_file = "dkgpg.conf",
		.user_config_file = "~/.config/dkgpg.conf",
		.version = PACKAGE_VERSION,
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
	if (gnunet_opt_i != NULL)
		ifilename = gnunet_opt_i;
	if (gnunet_opt_o != NULL)
		ofilename = gnunet_opt_o;
	if (gnunet_opt_k != NULL)
		kfilename = gnunet_opt_k;
	if (gnunet_opt_y != NULL)
		yfilename = gnunet_opt_y;
	if (gnunet_opt_P != NULL)
		passwords = gnunet_opt_P; // get passwords from GNUnet options
	if (gnunet_opt_H != NULL)
		hostname = gnunet_opt_H; // get hostname from GNUnet options
	if (gnunet_opt_W != opt_W)
		opt_W = gnunet_opt_W; // get aiou message timeout from GNUnet options
	if (gnunet_opt_U != NULL)
		URI = gnunet_opt_U; // get policy URI from GNUnet options
	if (gnunet_opt_u != NULL)
		u = gnunet_opt_u; // get user ID from GNUnet options
#endif

	// create peer list from remaining arguments
	for (size_t i = 0; i < (size_t)(argc - 1); i++)
	{
		std::string arg = argv[i+1];
		// ignore options
		if ((arg.find("-c") == 0) || (arg.find("-p") == 0) ||
			(arg.find("-y") == 0) || (arg.find("-W") == 0) || 
		    (arg.find("-L") == 0) || (arg.find("-l") == 0) ||
			(arg.find("-i") == 0) || (arg.find("-o") == 0) || 
		    (arg.find("-x") == 0) || (arg.find("-u") == 0) || 
			(arg.find("-P") == 0) || (arg.find("-H") == 0) ||
		    (arg.find("-U") == 0) || (arg.find("-k") == 0))
		{
			size_t idx = ++i;
			if ((arg.find("-i") == 0) && (idx < (size_t)(argc - 1)) &&
				(ifilename.length() == 0))
			{
				ifilename = argv[i+1];
			}
			if ((arg.find("-o") == 0) && (idx < (size_t)(argc - 1)) &&
				(ofilename.length() == 0))
			{
				ofilename = argv[i+1];
			}
			if ((arg.find("-k") == 0) && (idx < (size_t)(argc - 1)) &&
				(kfilename.length() == 0))
			{
				kfilename = argv[i+1];
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
			if ((arg.find("-U") == 0) && (idx < (size_t)(argc - 1)) &&
				(URI.length() == 0))
			{
				URI = argv[i+1];
			}
			if ((arg.find("-u") == 0) && (idx < (size_t)(argc - 1)) &&
				(u.length() == 0))
			{
				u = argv[i+1];
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
				(yfilename.length() == 0))
			{
				yfilename = argv[i+1];
			}
			continue;
		}
		else if ((arg.find("--") == 0) || (arg.find("-v") == 0) ||
			(arg.find("-h") == 0) || (arg.find("-V") == 0) ||
			(arg.find("-w") == 0))
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
				std::cout << "  -i FILENAME    read certification signatures" <<
					" from FILENAME" << std::endl;
				std::cout << "  -k FILENAME    use keyring FILENAME" <<
					" containing external revocation keys" << std::endl;
				std::cout << "  -o FILENAME    write generated attestation" <<
					" signatures to FILENAME" << std::endl;
				std::cout << "  -p INTEGER     start port for built-in" <<
					" TCP/IP message exchange service" << std::endl;
				std::cout << "  -P STRING      exchanged passwords to" <<
					" protect private and broadcast channels" << std::endl;
				std::cout << "  -u STRING      attest only valid user IDs" <<
					" containing STRING" << std::endl;
				std::cout << "  -U STRING      policy URI tied to generated" <<
					" attestation signatures" << std::endl;
				std::cout << "  -v, --version  print the version number" <<
					std::endl;
				std::cout << "  -V, --verbose  turn on verbose output" <<
					std::endl;
				std::cout << "  -w, --weak     allow weak public keys" <<
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
				std::cout << "dkg-attest v" << version <<
					" without GNUNET support" << std::endl;
#endif
				return 0; // not continue
			}
			if ((arg.find("-V") == 0) || (arg.find("--verbose") == 0))
				opt_verbose++; // increase verbosity
			if ((arg.find("-w") == 0) || (arg.find("--weak") == 0))
				opt_w = true;
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
	peers.push_back("Test3");
	peers.push_back("Test4");
	ifilename = "TestY-pub_signed.asc";
	ofilename = "Test1_output_attestation.asc";
	URI = "https://savannah.nongnu.org/projects/dkgpg/";
	opt_verbose = 2;
#else
#ifdef DKGPG_TESTSUITE_Y
	yfilename = "TestY-sec.asc";
	ifilename = "Test1_dkg-pub_signed.asc";
	ofilename = "TestY_output_attestation.asc";
	URI = "https://savannah.nongnu.org/projects/dkgpg/";
	opt_verbose = 2;
#endif
#endif

	// check command line arguments
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
		// start a single instance as replacement for GnuPG et al.
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
			GNUNET_GETOPT_option_string('i',
				"input",
				"FILENAME",
				"read certification signatures from FILENAME",
				&gnunet_opt_i
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
				"write generated attestation signatures to FILENAME",
				&gnunet_opt_o
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
				"userid",
				"STRING",
				"attest only valid user IDs containing STRING",
				&gnunet_opt_u
			),
			GNUNET_GETOPT_option_string('U',
				"URI",
				"STRING",
				"policy URI tied to attestation signatures",
				&gnunet_opt_U
			),
			GNUNET_GETOPT_option_flag('V',
				"verbose",
				"turn on verbose output",
				&gnunet_opt_verbose
			),
			GNUNET_GETOPT_option_flag('w',
				"weak",
				"allow weak public keys",
				&gnunet_opt_w
			),
			GNUNET_GETOPT_option_uint('W',
				"aiou-timeout",
				"INTEGER",
				"timeout for point-to-point messages in minutes",
				&gnunet_opt_W
			),
			GNUNET_GETOPT_option_string('y',
				"yaot",
				"FILENAME",
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

