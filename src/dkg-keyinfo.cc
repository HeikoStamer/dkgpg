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

#include <iostream>
#include <sstream>
#include <vector>
#include <map>
#include <string>
#include <algorithm>
#include <cstdio>
#include <ctime>

#include <libTMCG.hh>
#include "dkg-io.hh"
#include "dkg-common.hh"

int main
	(int argc, char *const *argv)
{
	static const char *usage = "dkg-keyinfo [OPTIONS] PEER";
	static const char *about = PACKAGE_STRING " " PACKAGE_URL;
	static const char *version = PACKAGE_VERSION " (" PACKAGE_NAME ")";

	std::vector<std::string>	peers;
	std::string					passphrase, kfilename;
	std::string					migrate_peer_from, migrate_peer_to;
	int 						opt_verbose = 0;
	char						*opt_k = NULL;

	// parse argument list
	for (size_t i = 0; i < (size_t)(argc - 1); i++)
	{
		std::string arg = argv[i+1];
		if (arg.find("-m") == 0)
		{
			size_t idx = ++i + 1; // Note: this option has 2 required arguments
			if (idx < (size_t)(argc - 1))
			{
				if ((migrate_peer_from.length() == 0) &&
					(migrate_peer_to.length() == 0))
				{
					migrate_peer_from = argv[i+1];
					migrate_peer_to = argv[i+2];
					if ((migrate_peer_from.length() > 255) ||
						(migrate_peer_to.length() > 255))
					{
						std::cerr << "ERROR: migration peer identity" <<
							" too long" << std::endl;
						return -1;
					}
				}
				else
					std::cerr << "WARNING: duplicate option \"" << arg <<
						"\" ignored" << std::endl;
			}
			else
			{
				std::cerr << "ERROR: missing some required arguments for" <<
					" option \"" << arg << "\"" << std::endl;
				return -1;
			}
			++i; // Note: this option has two required arguments
			continue;
		}
		else if ((arg.find("-k") == 0))
		{
			size_t idx = ++i;
			if ((idx < (size_t)(argc - 1)) && (opt_k == NULL))
			{
				kfilename = argv[i+1];
				opt_k = (char*)kfilename.c_str();
			}
			continue;
		}
		else if ((arg.find("--") == 0) || (arg.find("-v") == 0) ||
			(arg.find("-h") == 0) || (arg.find("-V") == 0))
		{
			if ((arg.find("-h") == 0) || (arg.find("--help") == 0))
			{
				std::cout << usage << std::endl;
				std::cout << about << std::endl;
				std::cout << "Arguments mandatory for long options are also" <<
					" mandatory for short options." << std::endl;
				std::cout << "  -h, --help           print this help" <<
					std::endl;
				std::cout << "  -k FILENAME          use keyring FILENAME" <<
					" containing external revocation keys" << std::endl;
				std::cout << "  -m OLDPEER NEWPEER   migrate OLDPEER" <<
					" identity to NEWPEER" << std::endl;
				std::cout << "  -v, --version        print the version" <<
					" number" << std::endl;
				std::cout << "  -V, --verbose        turn on verbose" <<
					" output" << std::endl;
				return 0; // not continue
			}
			if ((arg.find("-v") == 0) || (arg.find("--version") == 0))
			{
				std::cout << "dkg-keyinfo v" << version << std::endl;
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
	opt_verbose = 2;
#endif

	// check command line arguments
	if (peers.size() < 1)
	{
		std::cerr << "ERROR: no peer given as argument; usage: " << usage <<
			std::endl;
		return -1;
	}
	if (peers.size() != 1)
	{
		std::cerr << "ERROR: too many peers given" << std::endl;
		return -1;
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
		if (!read_key_file(kfilename, armored_pubring))
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
			return -1;
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
		return -1;
	}
	if (!prv->pub->valid || prv->weak(opt_verbose))
	{
		std::cerr << "ERROR: primary key is invalid or weak" << std::endl;
		delete ring;
		delete prv;
		return -1;
	}
	if ((prv->pkalgo != TMCG_OPENPGP_PKALGO_EXPERIMENTAL7) &&
		(prv->pkalgo != TMCG_OPENPGP_PKALGO_DSA))
	{
		std::cerr << "ERROR: primary key is not a tDSS/DSA key" << std::endl;
		delete ring;
		delete prv;
		return -1;
	}

	// create an instance of tDSS by stored parameters from private key
	CanettiGennaroJareckiKrawczykRabinDSS *dss = NULL;
	if (prv->pkalgo == TMCG_OPENPGP_PKALGO_EXPERIMENTAL7)
	{
		if (!init_tDSS(prv, opt_verbose, dss))
		{
			delete dss;
			delete ring;
			delete prv;
			return -1;
		}
	}

	GennaroJareckiKrawczykRabinDKG *dkg = NULL;
	if (prv->private_subkeys.size() &&
		(prv->private_subkeys[0]->pkalgo == TMCG_OPENPGP_PKALGO_EXPERIMENTAL9))
	{
		TMCG_OpenPGP_PrivateSubkey *sub = prv->private_subkeys[0];
		if (!sub->pub->valid || sub->weak(opt_verbose))
		{
			std::cerr << "ERROR: subkey is invalid or weak" << std::endl;
			delete dss;
			delete ring;
			delete prv;
			return -1;
		}
		// create an instance of tElG by stored parameters from private key
		if (!init_tElG(sub, opt_verbose, dkg))
		{
			delete dkg;
			if (dss != NULL)
				delete dss;
			delete ring;
			delete prv;
			return -1;
		}
	}

	// show information w.r.t. primary key
	std::string kid, fpr;
	CallasDonnerhackeFinneyShawThayerRFC4880::
		KeyidCompute(prv->pub->pub_hashing, kid);
	CallasDonnerhackeFinneyShawThayerRFC4880::
		FingerprintComputePretty(prv->pub->pub_hashing, fpr);
	std::cout << "OpenPGP V4 Key ID of primary key: " << std::endl << "\t";
	std::cout << kid << std::endl;
	std::cout << "OpenPGP V4 fingerprint of primary key: " << std::endl << "\t";
	std::cout << fpr << std::endl;
	std::cout << "OpenPGP Key Creation Time: " <<
		std::endl << "\t" << ctime(&prv->pub->creationtime);
	std::cout << "OpenPGP Key Expiration Time: " << std::endl << "\t";
	if (prv->pub->expirationtime == 0)
		std::cout << "undefined" << std::endl;
	else
	{
		// compute validity period of the primary key after key creation time
		time_t ekeytime = prv->pub->creationtime + prv->pub->expirationtime;
		if (ekeytime < time(NULL))
			std::cout << "[EXPIRED] ";
		std::cout << ctime(&ekeytime);
	}
	std::cout << "OpenPGP Revocation Keys: " << std::endl;
	for (size_t i = 0; i < prv->pub->revkeys.size(); i++)
	{
		tmcg_openpgp_revkey_t rk = prv->pub->revkeys[i];
		tmcg_openpgp_octets_t f(rk.key_fingerprint,
			 rk.key_fingerprint+sizeof(rk.key_fingerprint));
		CallasDonnerhackeFinneyShawThayerRFC4880::
			FingerprintConvertPretty(f, fpr);
		std::cout << "\t" << fpr << std::endl;
	}
	if (prv->pub->revkeys.size() == 0)
		std::cout << "\t" << "none" << std::endl;
	size_t allflags = prv->pub->AccumulateFlags();
	std::cout << "OpenPGP Key Flags: " << std::endl << "\t";
	// The key may be used to certify other keys.
	if ((allflags & 0x01) == 0x01)
		std::cout << "C";
	// The key may be used to sign data.
	if ((allflags & 0x02) == 0x02)
		std::cout << "S";
	// The key may be used encrypt communications.
	if ((allflags & 0x04) == 0x04)
		std::cout << "E";
	// The key may be used encrypt storage.
	if ((allflags & 0x08) == 0x08)
		std::cout << "e";
	// The private component of this key may have
	// been split by a secret-sharing mechanism.
	if ((allflags & 0x10) == 0x10)
		std::cout << "D";
	// The key may be used for authentication.
	if ((allflags & 0x20) == 0x20)
		std::cout << "A";
	// The private component of this key may be
	// in the possession of more than one person.
	if ((allflags & 0x80) == 0x80)
		std::cout << "G";
	if (allflags == 0x00)
		std::cout << "undefined";
	std::cout << std::endl;
	// show information w.r.t. user IDs
	for (size_t j = 0; j < prv->pub->userids.size(); j++)
	{
		std::cout << "OpenPGP User ID: " << std::endl << "\t";
		std::cout << prv->pub->userids[j]->userid_sanitized << std::endl;
	}
	if (dss != NULL)
	{
		// show information w.r.t. tDSS
		std::cout << "Security level of domain parameter set: " <<
			std::endl << "\t";
		std::cout << "|p| = " << mpz_sizeinbase(dss->p, 2L) << " bits, ";
		std::cout << "|q| = " << mpz_sizeinbase(dss->q, 2L) << " bits, ";
		std::cout << "|g| = " << mpz_sizeinbase(dss->g, 2L) << " bits, ";
		std::cout << "|h| = " << mpz_sizeinbase(dss->h, 2L) << " bits" <<
			std::endl;
		std::cout << "Threshold parameter set of primary key (tDSS): " <<
			std::endl << "\t";
		std::cout << "n = " << dss->n << ", s = " << dss->t << std::endl;
		std::cout << "Set of non-disqualified parties of primary key" <<
			" (tDSS): " << std::endl << "\t" << "QUAL = { ";
		for (size_t i = 0; i < dss->QUAL.size(); i++)
			std::cout << "P_" << dss->QUAL[i] << " ";
		std::cout << "}" << std::endl;
		std::cout << "Set of non-disqualified parties of RVSS subprotocol: " <<
			std::endl << "\t" << "QUAL = { ";
		for (size_t i = 0; i < dss->dkg->x_rvss->QUAL.size(); i++)
			std::cout << "P_" << dss->dkg->x_rvss->QUAL[i] << " ";
		std::cout << "}" << std::endl;
		std::cout << "Unique identifier of this party (tDSS): " <<
			std::endl << "\t";
		std::cout << "P_" << dss->i << std::endl;
		std::cout << "Canonicalized peer list (CAPL): " << std::endl;
		for (size_t i = 0; i < prv->tdss_capl.size(); i++)
			std::cout << "\t" << "P_" << i << "\t" <<
				prv->tdss_capl[i] << std::endl;
		std::cout << "Public commitments C_ik of RVSS subprotocol: " <<
			std::endl;
		for (size_t i = 0; i < dss->dkg->x_rvss->C_ik.size(); i++)
		{
			for (size_t k = 0; k < dss->dkg->x_rvss->C_ik[i].size(); k++)
				std::cout << "\t" << "C_ik[" << i << "][" << k << "] = " <<
					dss->dkg->x_rvss->C_ik[i][k] << std::endl;
		}
	}
	if (dkg != NULL)
	{
		// show information w.r.t. tElG
		TMCG_OpenPGP_PrivateSubkey *sub = prv->private_subkeys[0];
		std::string kid2, fpr2;
		CallasDonnerhackeFinneyShawThayerRFC4880::
			KeyidCompute(sub->pub->sub_hashing, kid2);
		CallasDonnerhackeFinneyShawThayerRFC4880::
			FingerprintComputePretty(sub->pub->sub_hashing, fpr2);
		std::cout << "OpenPGP V4 Key ID of subkey: " << std::endl << "\t";
		std::cout << kid2 << std::endl;
		std::cout << "OpenPGP V4 fingerprint of subkey: " << std::endl << "\t";
		std::cout << fpr2 << std::endl;
		std::cout << "OpenPGP Key Creation Time: " <<
			std::endl << "\t" << ctime(&sub->pub->creationtime);
		std::cout << "OpenPGP Key Expiration Time: " << std::endl << "\t";
		if (sub->pub->expirationtime == 0)
			std::cout << "undefined" << std::endl;
		else
		{
			// compute validity period of the subkey after key creation time
			time_t ekeytime = sub->pub->creationtime + sub->pub->expirationtime;
			if (ekeytime < time(NULL))
				std::cout << "[EXPIRED] ";
			std::cout << ctime(&ekeytime);
		}
		std::cout << "OpenPGP Revocation Keys: " << std::endl;
		for (size_t i = 0; i < sub->pub->revkeys.size(); i++)
		{
			tmcg_openpgp_revkey_t rk = sub->pub->revkeys[i];
			tmcg_openpgp_octets_t f(rk.key_fingerprint,
				 rk.key_fingerprint+sizeof(rk.key_fingerprint));
			CallasDonnerhackeFinneyShawThayerRFC4880::
				FingerprintConvertPretty(f, fpr2);
			std::cout << "\t" << fpr2 << std::endl;
		}
		if (sub->pub->revkeys.size() == 0)
			std::cout << "\t" << "none" << std::endl;
		size_t allflags = sub->pub->AccumulateFlags();
		std::cout << "OpenPGP Key Flags: " << std::endl << "\t";
		// The key may be used to certify other keys.
		if ((allflags & 0x01) == 0x01)
			std::cout << "C";
		// The key may be used to sign data.
		if ((allflags & 0x02) == 0x02)
			std::cout << "S";
		// The key may be used encrypt communications.
		if ((allflags & 0x04) == 0x04)
			std::cout << "E";
		// The key may be used encrypt storage.
		if ((allflags & 0x08) == 0x08)
			std::cout << "e";
		// The private component of this key may have
		// been split by a secret-sharing mechanism.
		if ((allflags & 0x10) == 0x10)
			std::cout << "D";
		// The key may be used for authentication.
		if ((allflags & 0x20) == 0x20)
			std::cout << "A";
		// The private component of this key may be
		// in the possession of more than one person.
		if ((allflags & 0x80) == 0x80)
			std::cout << "G";
		if (allflags == 0x00)
			std::cout << "undefined";
		std::cout << std::endl;
		// show information w.r.t. tElG
		std::cout << "Security level of domain parameter set (tElG): " <<
			std::endl << "\t"; 
		std::cout << "|p| = " << mpz_sizeinbase(dkg->p, 2L) << " bits, ";
		std::cout << "|q| = " << mpz_sizeinbase(dkg->q, 2L) << " bits, ";
		std::cout << "|g| = " << mpz_sizeinbase(dkg->g, 2L) << " bits, ";
		std::cout << "|h| = " << mpz_sizeinbase(dkg->h, 2L) << " bits" <<
			std::endl;
		std::cout << "Threshold parameter set of subkey (tElG): " <<
			std::endl << "\t";
		std::cout << "n = " << dkg->n << ", t = " << dkg->t << std::endl;
		std::cout << "Set of non-disqualified parties of subkey (tElG): " <<
			std::endl << "\t" << "QUAL = { ";
		for (size_t i = 0; i < dkg->QUAL.size(); i++)
			std::cout << "P_" << dkg->QUAL[i] << " ";
		std::cout << "}" << std::endl;
		std::cout << "Unique identifier of this party (tElG): " <<
			std::endl << "\t";
		std::cout << "P_" << dkg->i << std::endl;
		std::cout << "Public verification keys (tElG): " << std::endl;
		for (size_t i = 0; i < dkg->v_i.size(); i++)
			std::cout << "\t" << "v_" << i << " = " << dkg->v_i[i] << std::endl;
		std::cout << "Public commitments C_ik (tElG): " << std::endl;
		for (size_t i = 0; i < dkg->C_ik.size(); i++)
		{
			for (size_t k = 0; k < dkg->C_ik[i].size(); k++)
				std::cout << "\t" << "C_ik[" << i << "][" << k << "] = " <<
					dkg->C_ik[i][k] << std::endl;
		}
	}

	// migrate peer identity, if requested by option "-m OLDPEER NEWPEER"
	if (migrate_peer_from.length() && migrate_peer_to.length() &&
		(dss != NULL))
	{
		std::vector<std::string> CAPL, CAPL_new;
		for (size_t i = 0; i < prv->tdss_capl.size(); i++)
			CAPL.push_back(prv->tdss_capl[i]);
		size_t capl_idx = CAPL.size();
		for (size_t i = 0; i < CAPL.size(); i++)
		{
			if (CAPL[i] == migrate_peer_from)
				capl_idx = i;
			CAPL_new.push_back(CAPL[i]);
		}
		if (capl_idx == CAPL.size())
		{
			std::cerr << "ERROR: migration peer \"" << migrate_peer_from <<
				"\" not contained in CAPL" << std::endl;
			if (dkg != NULL)
				delete dkg;
			delete dss;
			delete prv;
			delete ring;	
			return -1;
		}
		else
			CAPL_new[capl_idx] = migrate_peer_to; // migration to NEWPEER
		// canonicalize new peer list and check for lexicographical order
		std::sort(CAPL_new.begin(), CAPL_new.end());
		std::vector<std::string>::iterator it = std::unique(CAPL_new.begin(),
			CAPL_new.end());
		CAPL_new.resize(std::distance(CAPL_new.begin(), it));
		if (CAPL_new.size() == CAPL.size())
		{
			for (size_t i = 0; i < CAPL_new.size(); i++)
			{
				if ((i != capl_idx) && (CAPL_new[i] != CAPL[i]))
				{
					std::cerr << "ERROR: migration from peer \"" <<
						migrate_peer_from << "\" to \"" << migrate_peer_to <<
						"\" failed (wrong order of CAPL)" << std::endl;
					if (dkg != NULL)
						delete dkg;
					delete dss;
					delete prv;
					delete ring;
					return -1;
				}
			}
		}
		else
		{
			std::cerr << "ERROR: migration from peer \"" << migrate_peer_from <<
				"\" to \"" <<  migrate_peer_to << "\" failed" <<
				" (identity occupied)" << std::endl;
			if (dkg != NULL)
				delete dkg;
			delete dss;
			delete prv;
			delete ring;
			return -1;
		}
		// create an OpenPGP private key structure with refreshed values
		tmcg_openpgp_octets_t sec, ssb;
		gcry_mpi_t n, t, i, qualsize, x_rvss_qualsize;
		std::vector<gcry_mpi_t> qual, x_rvss_qual;
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
		CallasDonnerhackeFinneyShawThayerRFC4880::
			PacketSecEncodeExperimental107(prv->pub->creationtime,
				prv->pub->dsa_p, prv->pub->dsa_q, prv->pub->dsa_g, prv->tdss_h,
				prv->pub->dsa_y, n, t, i, qualsize, qual, x_rvss_qualsize,
				x_rvss_qual, CAPL_new, prv->tdss_c_ik, prv->tdss_x_i,
				prv->tdss_xprime_i, passphrase, sec);
		gcry_mpi_release(n);
		gcry_mpi_release(t);
		gcry_mpi_release(i);
		gcry_mpi_release(qualsize);
		for (size_t j = 0; j < qual.size(); j++)
			gcry_mpi_release(qual[j]);
		qual.clear();
		gcry_mpi_release(x_rvss_qualsize);
		for (size_t j = 0; j < x_rvss_qual.size(); j++)
			gcry_mpi_release(x_rvss_qual[j]);
		x_rvss_qual.clear();
		if (dkg != NULL)
		{
			n = gcry_mpi_set_ui(NULL, dkg->n);
			t = gcry_mpi_set_ui(NULL, dkg->t);
			i = gcry_mpi_set_ui(NULL, dkg->i);
			qualsize = gcry_mpi_set_ui(NULL, dkg->QUAL.size());
			for (size_t j = 0; j < dkg->QUAL.size(); j++)
			{
				gcry_mpi_t tmp = gcry_mpi_set_ui(NULL, dkg->QUAL[j]);
				qual.push_back(tmp);
			}
			TMCG_OpenPGP_PrivateSubkey *sub = prv->private_subkeys[0];
			CallasDonnerhackeFinneyShawThayerRFC4880::
				PacketSsbEncodeExperimental109(sub->pub->creationtime,
				sub->pub->elg_p, sub->telg_q, sub->pub->elg_g, sub->telg_h,
				sub->pub->elg_y, n, t, i, qualsize, qual, sub->telg_v_i,
				sub->telg_c_ik, sub->telg_x_i, sub->telg_xprime_i,
				passphrase, ssb);
			gcry_mpi_release(n);
			gcry_mpi_release(t);
			gcry_mpi_release(i);
			gcry_mpi_release(qualsize);
			for (size_t j = 0; j < qual.size(); j++)
				gcry_mpi_release(qual[j]);
			qual.clear();
		}
		// export updated private key in OpenPGP armor format
		tmcg_openpgp_octets_t all;
		std::string armor;
		std::stringstream secfilename;
		secfilename << thispeer << "_dkg-sec.asc";
		all.insert(all.end(), sec.begin(), sec.end());
		for (size_t k = 0; k < prv->pub->selfsigs.size(); k++)
			all.insert(all.end(),
				(prv->pub->selfsigs[k]->packet).begin(),
				(prv->pub->selfsigs[k]->packet).end());
		for (size_t k = 0; k < prv->pub->keyrevsigs.size(); k++)
			all.insert(all.end(),
				(prv->pub->keyrevsigs[k]->packet).begin(),
				(prv->pub->keyrevsigs[k]->packet).end());
		for (size_t j = 0; j < prv->pub->userids.size(); j++)
		{
			TMCG_OpenPGP_UserID *uid = prv->pub->userids[j];
			if (uid->valid)
			{
				all.insert(all.end(),
					(uid->packet).begin(), (uid->packet).end());
				for (size_t k = 0; k < uid->selfsigs.size(); k++)
					all.insert(all.end(),
						(uid->selfsigs[k]->packet).begin(),
						(uid->selfsigs[k]->packet).end());
				for (size_t k = 0; k < uid->revsigs.size(); k++)
					all.insert(all.end(),
						(uid->selfsigs[k]->packet).begin(),
						(uid->selfsigs[k]->packet).end());
			}
		}
		for (size_t j = 0; j < prv->pub->userattributes.size(); j++)
		{
			TMCG_OpenPGP_UserAttribute *uat = prv->pub->userattributes[j];
			if (uat->valid)
			{
				all.insert(all.end(),
					(uat->packet).begin(), (uat->packet).end());
				for (size_t k = 0; k < uat->selfsigs.size(); k++)
					all.insert(all.end(),
						(uat->selfsigs[k]->packet).begin(),
						(uat->selfsigs[k]->packet).end());
				for (size_t k = 0; k < uat->revsigs.size(); k++)
					all.insert(all.end(),
						(uat->selfsigs[k]->packet).begin(),
						(uat->selfsigs[k]->packet).end());
			}
		}
		if (dkg != NULL)
		{
			all.insert(all.end(), ssb.begin(), ssb.end());
			TMCG_OpenPGP_Subkey *sub = prv->private_subkeys[0]->pub;
			for (size_t k = 0; k < sub->selfsigs.size(); k++)
				all.insert(all.end(),
					(sub->selfsigs[k]->packet).begin(),
					(sub->selfsigs[k]->packet).end());
			for (size_t k = 0; k < sub->bindsigs.size(); k++)
				all.insert(all.end(),
					(sub->bindsigs[k]->packet).begin(),
					(sub->bindsigs[k]->packet).end());
			for (size_t k = 0; k < sub->pbindsigs.size(); k++)
				all.insert(all.end(),
					(sub->pbindsigs[k]->packet).begin(),
					(sub->pbindsigs[k]->packet).end());
			for (size_t k = 0; k < sub->keyrevsigs.size(); k++)
				all.insert(all.end(),
					(sub->keyrevsigs[k]->packet).begin(),
					(sub->keyrevsigs[k]->packet).end());
		}
		CallasDonnerhackeFinneyShawThayerRFC4880::
			ArmorEncode(TMCG_OPENPGP_ARMOR_PRIVATE_KEY_BLOCK, all, armor);
		if (opt_verbose > 1)
			std::cout << armor << std::endl;
		std::ofstream secofs((secfilename.str()).c_str(),
			std::ofstream::out | std::ofstream::trunc);
		if (!secofs.good())
		{
			std::cerr << "ERROR: opening private key file failed" << std::endl;
			if (dkg != NULL)
				delete dkg;
			delete dss;
			delete prv;
			delete ring;
			return -1;
		}
		secofs << armor;
		if (!secofs.good())
		{
			std::cerr << "ERROR: writing private key file failed" << std::endl;
			if (dkg != NULL)
				delete dkg;
			delete dss;
			delete prv;
			delete ring;
			return -1;
		}
		secofs.close();
		if (opt_verbose)
			std::cerr << "INFO: migration from peer \"" << migrate_peer_from <<
			"\" to \"" << migrate_peer_to << "\" finished" << std::endl;
	}

	if (dkg != NULL)
		delete dkg;
	if (dss != NULL)
		delete dss;
	delete prv;
	delete ring;
	
	return 0;
}

