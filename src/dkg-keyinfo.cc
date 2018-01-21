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

#include <iomanip>
#include <sstream>
#include <vector>
#include <map>
#include <string>
#include <algorithm>
#include <cstdio>
#include <ctime>

#include <libTMCG.hh>

#include "dkg-common.hh"

std::vector<std::string>		peers;

std::string				passphrase, userid;
tmcg_octets_t				keyid, subkeyid, pub, sub, uidsig, subsig, sec, ssb, uid;
std::map<size_t, size_t>		idx2dkg, dkg2idx;
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
gcry_mpi_t				dsa_r, dsa_s, elg_r, elg_s, rsa_n, rsa_e, rsa_md;
gcry_mpi_t 				gk, myk, sig_r, sig_s;
gcry_mpi_t				revdsa_r, revdsa_s, revelg_r, revelg_s, revrsa_md;

int 					opt_verbose = 0;

int main
	(int argc, char *const *argv)
{
	static const char *usage = "dkg-keyinfo [OPTIONS] PEER";
	static const char *about = PACKAGE_STRING " " PACKAGE_URL;
	static const char *version = PACKAGE_VERSION " (" PACKAGE_NAME ")";
	std::string migrate_peer_from, migrate_peer_to;

	// parse argument list
	for (size_t i = 0; i < (size_t)(argc - 1); i++)
	{
		std::string arg = argv[i+1];
		if (arg.find("-m") == 0)
		{
			size_t idx = ++i + 1; // Note: this option has two required arguments
			if (idx < (size_t)(argc - 1))
			{
				if ((migrate_peer_from.length() == 0) && (migrate_peer_to.length() == 0))
					migrate_peer_from = argv[i+1], migrate_peer_to = argv[i+2];
				else
					std::cerr << "WARNING: duplicate option \"" << arg << "\" ignored" << std::endl;
			}
			else
			{
				std::cerr << "ERROR: missing some required arguments for option \"" << arg << "\"" << std::endl;
				return -1;
			}
			++i; // Note: this option has two required arguments
			continue;
		}
		else if ((arg.find("--") == 0) || (arg.find("-v") == 0) || (arg.find("-h") == 0) || (arg.find("-V") == 0))
		{
			if ((arg.find("-h") == 0) || (arg.find("--help") == 0))
			{
				std::cout << usage << std::endl;
				std::cout << about << std::endl;
				std::cout << "Arguments mandatory for long options are also mandatory for short options." << std::endl;
				std::cout << "  -h, --help           print this help" << std::endl;
				std::cout << "  -m OLDPEER NEWPEER   migrate OLDPEER identity to NEWPEER" << std::endl;
				std::cout << "  -v, --version        print the version number" << std::endl;
				std::cout << "  -V, --verbose        turn on verbose output" << std::endl;
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
			std::cerr << "ERROR: peer identity \"" << arg << "\" too long" << std::endl;
			return -1;
		}
	}
#ifdef DKGPG_TESTSUITE
	peers.push_back("Test1");
	opt_verbose = 1;
#endif

	// check command line arguments
	if (peers.size() < 1)
	{
		std::cerr << "ERROR: no peer given as argument; usage: " << usage << std::endl;
		return -1;
	}
	if (peers.size() != 1)
	{
		std::cerr << "ERROR: too many peers given" << std::endl;
		return -1;
	}

	// initialize LibTMCG
	if (!init_libTMCG())
	{
		std::cerr << "ERROR: initialization of LibTMCG failed" << std::endl;
		return -1;
	}
	if (opt_verbose)
		std::cout << "INFO: using LibTMCG version " << version_libTMCG() << std::endl;

	// read and parse the private key
	std::string armored_seckey, thispeer = peers[0];
	if (!read_key_file(thispeer + "_dkg-sec.asc", armored_seckey))
		return -1;
	init_mpis();
	std::vector<std::string> CAPL;
	time_t ckeytime = 0, ekeytime = 0;
	if (!parse_private_key(armored_seckey, ckeytime, ekeytime, CAPL))
	{
		release_mpis();
		keyid.clear(), subkeyid.clear(), pub.clear(), sub.clear(), uidsig.clear(), subsig.clear();
		dss_qual.clear(), dss_x_rvss_qual.clear(), dss_c_ik.clear(), dkg_qual.clear(), dkg_v_i.clear(), dkg_c_ik.clear();
		init_mpis();
		// protected with password
#ifdef DKGPG_TESTSUITE
		passphrase = "Test";
#else
		if (!get_passphrase("Please enter passphrase to unlock your private key", passphrase))
		{
			release_mpis();
			return -1;
		}
#endif
		if (!parse_private_key(armored_seckey, ckeytime, ekeytime, CAPL))
		{
			std::cerr << "ERROR: wrong passphrase to unlock private key" << std::endl;
			release_mpis();
			return -1;
		}
	}

	// create an instance of tDSS by stored parameters from private key
	std::stringstream dss_in;
	if (dss_n == 0L)
	{
		// cheat CheckGroup() with $h$ for non-tDSS individual DSA key
		mpz_set_ui(dss_h, 42L);
		mpz_powm(dss_h, dss_g, dss_h, dss_p);
	}
	dss_in << dss_p << std::endl << dss_q << std::endl << dss_g << std::endl << dss_h << std::endl;
	dss_in << dss_n << std::endl << dss_t << std::endl << dss_i << std::endl;
	dss_in << dss_x_i << std::endl << dss_xprime_i << std::endl << dss_y << std::endl;
	dss_in << dss_qual.size() << std::endl;
	for (size_t i = 0; i < dss_qual.size(); i++)
		dss_in << dss_qual[i] << std::endl;
	dss_in << dss_p << std::endl << dss_q << std::endl << dss_g << std::endl << dss_h << std::endl;
	dss_in << dss_n << std::endl << dss_t << std::endl << dss_i << std::endl;
	dss_in << dss_x_i << std::endl << dss_xprime_i << std::endl << dss_y << std::endl;
	dss_in << dss_qual.size() << std::endl;
	for (size_t i = 0; i < dss_qual.size(); i++)
		dss_in << dss_qual[i] << std::endl;
	dss_in << dss_p << std::endl << dss_q << std::endl << dss_g << std::endl << dss_h << std::endl;
	dss_in << dss_n << std::endl << dss_t << std::endl << dss_i << std::endl << dss_t << std::endl;
	dss_in << dss_x_i << std::endl << dss_xprime_i << std::endl;
	dss_in << "0" << std::endl << "0" << std::endl;
	dss_in << dss_x_rvss_qual.size() << std::endl;
	for (size_t i = 0; i < dss_x_rvss_qual.size(); i++)
		dss_in << dss_x_rvss_qual[i] << std::endl;
	assert((dss_c_ik.size() == dss_n));
	for (size_t i = 0; i < dss_c_ik.size(); i++)
	{
		for (size_t j = 0; j < dss_c_ik.size(); j++)
			dss_in << "0" << std::endl << "0" << std::endl;
		assert((dss_c_ik[i].size() == (dss_t + 1)));
		for (size_t k = 0; k < dss_c_ik[i].size(); k++)
			dss_in << dss_c_ik[i][k] << std::endl;
	}
	if (opt_verbose)
		std::cout << "CanettiGennaroJareckiKrawczykRabinDSS(in, ...)" << std::endl;
	CanettiGennaroJareckiKrawczykRabinDSS *dss = new CanettiGennaroJareckiKrawczykRabinDSS(dss_in);
	if (!dss->CheckGroup())
	{
		std::cerr << "ERROR: tDSS domain parameters are not correctly generated!" << std::endl;
		delete dss;
		release_mpis();
		return -1;
	}
	if (dss_n == 0)
	{
		mpz_set_ui(dss_h, 0L); // restore $h$ for non-tDSS individual DSA key
		mpz_set_ui(dss->h, 0L);
	}

	GennaroJareckiKrawczykRabinDKG *dkg = NULL;
	if (sub.size())
	{
		// create an instance of DKG by stored parameters from private key
		std::stringstream dkg_in;
		dkg_in << dkg_p << std::endl << dkg_q << std::endl << dkg_g << std::endl << dkg_h << std::endl;
		dkg_in << dkg_n << std::endl << dkg_t << std::endl << dkg_i << std::endl;
		dkg_in << dkg_x_i << std::endl << dkg_xprime_i << std::endl << dkg_y << std::endl;
		dkg_in << dkg_qual.size() << std::endl;
		for (size_t i = 0; i < dkg_qual.size(); i++)
			dkg_in << dkg_qual[i] << std::endl;
		for (size_t i = 0; i < dkg_n; i++)
			dkg_in << "1" << std::endl; // y_i not yet stored
		for (size_t i = 0; i < dkg_n; i++)
			dkg_in << "0" << std::endl; // z_i not yet stored
		assert((dkg_v_i.size() == dkg_n));
		for (size_t i = 0; i < dkg_v_i.size(); i++)
			dkg_in << dkg_v_i[i] << std::endl;
		assert((dkg_c_ik.size() == dkg_n));
		for (size_t i = 0; i < dkg_n; i++)
		{
			for (size_t j = 0; j < dkg_n; j++)
				dkg_in << "0" << std::endl << "0" << std::endl; // s_ij and sprime_ij not yet stored
			assert((dkg_c_ik[i].size() == (dkg_t + 1)));
			for (size_t k = 0; k < dkg_c_ik[i].size(); k++)
				dkg_in << dkg_c_ik[i][k] << std::endl;
		}
		if (opt_verbose)
			std::cout << "GennaroJareckiKrawczykRabinDKG(in, ...)" << std::endl;
		dkg = new GennaroJareckiKrawczykRabinDKG(dkg_in);
		if (!dkg->CheckGroup())
		{
			std::cerr << "ERROR: DKG domain parameters are not correctly generated!" << std::endl;
			delete dss, delete dkg;
			release_mpis();
			return -1;
		}
		if (!dkg->CheckKey())
		{
			std::cerr << "ERROR: DKG CheckKey() failed!" << std::endl;
			delete dss, delete dkg;
			release_mpis();
			return -1;
		}
	}

	// show information
	std::ios oldcoutstate(NULL);
	oldcoutstate.copyfmt(std::cout);
	std::cout << "OpenPGP V4 Key ID of primary key: " << std::endl << std::hex << std::uppercase << "\t";
	for (size_t i = 0; i < keyid.size(); i++)
		std::cout << std::setfill('0') << std::setw(2) << std::right << (int)keyid[i] << " ";
	std::cout << std::dec << std::endl;
	tmcg_octets_t pub_hashing, fpr;
	for (size_t i = 6; i < pub.size(); i++)
		pub_hashing.push_back(pub[i]);
	CallasDonnerhackeFinneyShawThayerRFC4880::FingerprintCompute(pub_hashing, fpr);
	std::cout << "OpenPGP V4 fingerprint of primary key: " << std::endl << std::hex << std::uppercase << "\t";
	for (size_t i = 0; i < fpr.size(); i++)
		std::cout << std::setfill('0') << std::setw(2) << std::right << (int)fpr[i] << " ";
	std::cout << std::dec << std::endl;
	std::cout << "OpenPGP Key Creation Time: " << std::endl << "\t" << ctime(&ckeytime);
	std::cout << "OpenPGP Key Expiration Time: " << std::endl << "\t";
	if (ekeytime == 0)
		std::cout << "undefined" << std::endl;
	else
	{
		ekeytime += ckeytime; // validity period of the key after key creation time
		std::cout << ctime(&ekeytime);
	}
	std::cout << "OpenPGP User ID: " << std::endl << "\t";
	std::cout << userid << std::endl;
	std::cout << "Security level of domain parameter set: " << std::endl << "\t";
	std::cout << "|p| = " << mpz_sizeinbase(dss->p, 2L) << " bit, ";
	std::cout << "|q| = " << mpz_sizeinbase(dss->q, 2L) << " bit, ";
	std::cout << "|g| = " << mpz_sizeinbase(dss->g, 2L) << " bit";
	if (dss_n != 0)
		std::cout << ", |h| = " << mpz_sizeinbase(dss->h, 2L) << " bit";
	std::cout << std::endl;
	if (dss_n != 0)
	{
		std::cout << "Threshold parameter set of primary key (tDSS): " << std::endl << "\t";
		std::cout << "n = " << dss->n << ", s = " << dss->t << std::endl;
		std::cout << "Set of non-disqualified parties of primary key (tDSS): " << std::endl << "\t" << "QUAL = { ";
		for (size_t i = 0; i < dss->QUAL.size(); i++)
			std::cout << "P_" << dss->QUAL[i] << " ";
		std::cout << "}" << std::endl;
		if (dss->dkg->x_rvss->QUAL.size())
		{
			std::cout << "Set of non-disqualified parties of x_rvss subprotocol: " << std::endl << "\t" << "QUAL = { ";
			for (size_t i = 0; i < dss->dkg->x_rvss->QUAL.size(); i++)
				std::cout << "P_" << dss->dkg->x_rvss->QUAL[i] << " ";
			std::cout << "}" << std::endl;
		}
		std::cout << "Unique identifier of this party (tDSS): " << std::endl << "\t";
		std::cout << "P_" << dss->i << std::endl;
		std::cout << "Canonicalized peer list (CAPL): " << std::endl;
		for (size_t i = 0; i < CAPL.size(); i++)
			std::cout << "\t" << "P_" << ((dss->dkg->x_rvss->QUAL.size())?(i):(dss->QUAL[i])) << "\t" << CAPL[i] << std::endl;
		std::cout << "Public commitments C_ik of x_rvss subprotocol: " << std::endl;
		for (size_t i = 0; i < dss->dkg->x_rvss->C_ik.size(); i++)
		{
			for (size_t k = 0; k < dss->dkg->x_rvss->C_ik[i].size(); k++)
				std::cout << "\t" << "C_ik[" << i << "][" << k << "] = " << dss->dkg->x_rvss->C_ik[i][k] << std::endl;
		}
	}
	if (sub.size() && (dkg != NULL))
	{
		std::cout << "OpenPGP V4 Key ID of subkey: " << std::endl << std::hex << std::uppercase << "\t";
		for (size_t i = 0; i < subkeyid.size(); i++)
			std::cout << std::setfill('0') << std::setw(2) << std::right << (int)subkeyid[i] << " ";
		std::cout << std::dec << std::endl;
		tmcg_octets_t sub_hashing, sub_fpr;
		for (size_t i = 6; i < sub.size(); i++)
			sub_hashing.push_back(sub[i]);
		CallasDonnerhackeFinneyShawThayerRFC4880::FingerprintCompute(sub_hashing, sub_fpr);
		std::cout << "OpenPGP V4 fingerprint of subkey: " << std::endl << std::hex << std::uppercase << "\t";
		for (size_t i = 0; i < sub_fpr.size(); i++)
			std::cout << std::setfill('0') << std::setw(2) << std::right << (int)sub_fpr[i] << " ";
		std::cout << std::dec << std::endl;
		std::cout << "Security level of domain parameter set: " << std::endl << "\t"; 
		std::cout << "|p| = " << mpz_sizeinbase(dkg->p, 2L) << " bit, ";
		std::cout << "|q| = " << mpz_sizeinbase(dkg->q, 2L) << " bit, ";
		std::cout << "|g| = " << mpz_sizeinbase(dkg->g, 2L) << " bit, ";
		std::cout << "|h| = " << mpz_sizeinbase(dkg->h, 2L) << " bit" << std::endl;
		std::cout << "Threshold parameter set of subkey (DKG): " << std::endl << "\t";
		std::cout << "n = " << dkg->n << ", t = " << dkg->t << std::endl;
		std::cout << "Set of non-disqualified parties of subkey (DKG): " << std::endl << "\t" << "QUAL = { ";
		for (size_t i = 0; i < dkg->QUAL.size(); i++)
			std::cout << "P_" << dkg->QUAL[i] << " ";
		std::cout << "}" << std::endl;
		std::cout << "Unique identifier of this party (DKG): " << std::endl << "\t";
		std::cout << "P_" << dkg->i << std::endl;
		std::cout << "Public verification keys (DKG): " << std::endl;
		for (size_t i = 0; i < dkg->v_i.size(); i++)
			std::cout << "\t" << "v_" << i << " = " << dkg->v_i[i] << std::endl;
		std::cout << "Public commitments C_ik (DKG): " << std::endl;
		for (size_t i = 0; i < dkg->C_ik.size(); i++)
		{
			for (size_t k = 0; k < dkg->C_ik[i].size(); k++)
				std::cout << "\t" << "C_ik[" << i << "][" << k << "] = " << dkg->C_ik[i][k] << std::endl;
		}
	}

	// restore default formatting
	std::cout.copyfmt(oldcoutstate);

	// migrate peer identity, if requested by option "-m OLDPEER NEWPEER"
	if (migrate_peer_from.length() && migrate_peer_to.length())
	{
		if ((dss_n != 0) && (CAPL.size() > 0))
		{
			std::vector<std::string> CAPL_new;
			size_t capl_idx = CAPL.size();
			for (size_t i = 0; i < CAPL.size(); i++)
			{
				if (migrate_peer_from == CAPL[i])
					capl_idx = i;
				CAPL_new.push_back(CAPL[i]);
			}
			if (capl_idx == CAPL.size())
			{
				std::cerr << "ERROR: migration peer \"" << migrate_peer_from << "\" not contained in CAPL" << std::endl;
				if (sub.size() && (dkg != NULL))
					delete dkg;
				delete dss;
				release_mpis();
				return -1;
			}
			else
				CAPL_new[capl_idx] = migrate_peer_to; // migration to NEWPEER
			// canonicalize new peer list and check for persitent lexicographical order
			std::sort(CAPL_new.begin(), CAPL_new.end());
			std::vector<std::string>::iterator it = std::unique(CAPL_new.begin(), CAPL_new.end());
			CAPL_new.resize(std::distance(CAPL_new.begin(), it));
			if (CAPL_new.size() == CAPL.size())
			{
				for (size_t i = 0; i < CAPL_new.size(); i++)
				{
					if ((i != capl_idx) && (CAPL_new[i] != CAPL[i]))
					{
						std::cerr << "ERROR: migration from peer \"" << migrate_peer_from << "\" to \"" <<
							migrate_peer_to << "\" failed (wrong order of CAPL)" << std::endl;
						if (sub.size() && (dkg != NULL))
							delete dkg;
						delete dss;
						release_mpis();
						return -1;
					}
				}
			}
			else
			{
				std::cerr << "ERROR: migration from peer \"" << migrate_peer_from << "\" to \"" << 
					migrate_peer_to << "\" failed (identity occupied)" << std::endl;
				if (sub.size() && (dkg != NULL))
					delete dkg;
				delete dss;
				release_mpis();
				return -1;
			}
			// create an OpenPGP DSA-based primary key using refreshed values from tDSS
			gcry_mpi_t p, q, g, h, y, n, t, i, qualsize, x_rvss_qualsize, x_i, xprime_i;
			std::vector<gcry_mpi_t> qual, x_rvss_qual;
			std::vector< std::vector<gcry_mpi_t> > c_ik;
			p = gcry_mpi_new(2048);
			if (!mpz_get_gcry_mpi(p, dss->p))
			{
				std::cerr << "ERROR: migrate -- mpz_get_gcry_mpi() failed for p" << std::endl;
				gcry_mpi_release(p);
				if (sub.size() && (dkg != NULL))
					delete dkg;
				delete dss;
				release_mpis();
				return -1;
			}
			q = gcry_mpi_new(2048);
			if (!mpz_get_gcry_mpi(q, dss->q))
			{
				std::cerr << "ERROR: migrate -- mpz_get_gcry_mpi() failed for q" << std::endl;
				gcry_mpi_release(p);
				gcry_mpi_release(q);
				if (sub.size() && (dkg != NULL))
					delete dkg;
				delete dss;
				release_mpis();
				return -1;	
			}
			g = gcry_mpi_new(2048);
			if (!mpz_get_gcry_mpi(g, dss->g))
			{
				std::cerr << "ERROR: migrate -- mpz_get_gcry_mpi() failed for g" << std::endl;
				gcry_mpi_release(p);
				gcry_mpi_release(q);
				gcry_mpi_release(g);
				if (sub.size() && (dkg != NULL))
					delete dkg;
				delete dss;
				release_mpis();
				return -1;
			}
			h = gcry_mpi_new(2048);
			if (!mpz_get_gcry_mpi(h, dss->h))
			{
				std::cerr << "ERROR: migrate -- mpz_get_gcry_mpi() failed for h" << std::endl;
				gcry_mpi_release(p);
				gcry_mpi_release(q);
				gcry_mpi_release(g);
				gcry_mpi_release(h);
				if (sub.size() && (dkg != NULL))
					delete dkg;
				delete dss;
				release_mpis();
				return -1;
			}
			y = gcry_mpi_new(2048);
			if (!mpz_get_gcry_mpi(y, dss->y))
			{
				std::cerr << "ERROR: migrate -- mpz_get_gcry_mpi() failed for y" << std::endl;
				gcry_mpi_release(p);
				gcry_mpi_release(q);
				gcry_mpi_release(g);
				gcry_mpi_release(h);
				gcry_mpi_release(y);
				if (sub.size() && (dkg != NULL))
					delete dkg;
				delete dss;
				release_mpis();
				return -1;
			}
			x_i = gcry_mpi_new(2048);
			if (!mpz_get_gcry_mpi(x_i, dss->x_i))
			{
				std::cerr << "ERROR: migrate -- mpz_get_gcry_mpi() failed for x_i" << std::endl;
				gcry_mpi_release(p);
				gcry_mpi_release(q);
				gcry_mpi_release(g);
				gcry_mpi_release(h);
				gcry_mpi_release(y);
				gcry_mpi_release(x_i);
				if (sub.size() && (dkg != NULL))
					delete dkg;
				delete dss;
				release_mpis();
				return -1;
			}
			xprime_i = gcry_mpi_new(2048);
			if (!mpz_get_gcry_mpi(xprime_i, dss->xprime_i))
			{
				std::cerr << "ERROR: migrate -- mpz_get_gcry_mpi() failed for xprime_i" << std::endl;
				gcry_mpi_release(p);
				gcry_mpi_release(q);
				gcry_mpi_release(g);
				gcry_mpi_release(h);
				gcry_mpi_release(y);
				gcry_mpi_release(x_i);
				gcry_mpi_release(xprime_i);
				if (sub.size() && (dkg != NULL))
					delete dkg;
				delete dss;
				release_mpis();
				return -1;
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
			c_ik.resize(dss->n);
			for (size_t j = 0; j < c_ik.size(); j++)
			{
				for (size_t k = 0; k <= dss->t; k++)
				{
					gcry_mpi_t tmp;
					tmp = gcry_mpi_new(2048);
					if (!mpz_get_gcry_mpi(tmp, dss->dkg->x_rvss->C_ik[j][k]))
					{
						std::cerr << "ERROR: migrate -- mpz_get_gcry_mpi() failed for dss->dkg->x_rvss->C_ik[j][k]" << std::endl;
						gcry_mpi_release(p);
						gcry_mpi_release(q);
						gcry_mpi_release(g);
						gcry_mpi_release(h);
						gcry_mpi_release(y);
						gcry_mpi_release(x_i);
						gcry_mpi_release(xprime_i);
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
						if (sub.size() && (dkg != NULL))
							delete dkg;
						delete dss;
						release_mpis();
						return -1;
					}
					c_ik[j].push_back(tmp);
				}
			}
			sec.clear(); // clear old private key (tDSS)
			CallasDonnerhackeFinneyShawThayerRFC4880::PacketSecEncodeExperimental107(ckeytime, p, q, g, h, y, 
				n, t, i, qualsize, qual, x_rvss_qualsize, x_rvss_qual, CAPL_new, c_ik, x_i, xprime_i, passphrase, sec);
			gcry_mpi_release(p);
			gcry_mpi_release(q);
			gcry_mpi_release(g);
			gcry_mpi_release(h);
			gcry_mpi_release(y);
			gcry_mpi_release(x_i);
			gcry_mpi_release(xprime_i);
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
			// export updated private key in OpenPGP armor format
			tmcg_octets_t all;
			std::string armor;
			std::stringstream secfilename;
			secfilename << thispeer << "_dkg-sec.asc";
			all.insert(all.end(), sec.begin(), sec.end());
			all.insert(all.end(), uid.begin(), uid.end());
			all.insert(all.end(), uidsig.begin(), uidsig.end());
			if (sub.size())
			{
				all.insert(all.end(), ssb.begin(), ssb.end());
				all.insert(all.end(), subsig.begin(), subsig.end());
			}
			CallasDonnerhackeFinneyShawThayerRFC4880::ArmorEncode(5, all, armor);
			if (opt_verbose > 1)
				std::cout << armor << std::endl;
			std::ofstream secofs((secfilename.str()).c_str(), std::ofstream::out | std::ofstream::trunc);
			if (!secofs.good())
			{
				std::cerr << "ERROR: opening private key file failed" << std::endl;
				if (sub.size() && (dkg != NULL))
					delete dkg;
				delete dss;
				release_mpis();
				return -1;
			}
			secofs << armor;
			if (!secofs.good())
			{
				std::cerr << "ERROR: writing private key file failed" << std::endl;
				if (sub.size() && (dkg != NULL))
					delete dkg;
				delete dss;
				release_mpis();
				return -1;
			}
			secofs.close();
			if (opt_verbose)
				std::cout << "INFO: migration from peer \"" << migrate_peer_from << "\" to \"" << migrate_peer_to << "\" finished" << std::endl;
		}
		else
			std::cerr << "WARNING: migration not possible due to missing or bad tDSS key" << std::endl;
	}

	// release
	if (sub.size() && (dkg != NULL))
		delete dkg;
	delete dss;
	release_mpis();
	
	return 0;
}

