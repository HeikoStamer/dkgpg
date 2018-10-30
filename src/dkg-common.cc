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
#include "dkg-common.hh"

bool init_tDSS
	(const TMCG_OpenPGP_Prvkey *prv, const int opt_verbose,
	 CanettiGennaroJareckiKrawczykRabinDSS* &dss)
{
//	tmcg_openpgp_secure_stringstream_t dss_in; // TODO
	std::stringstream dss_in;
	dss_in << prv->pub->dsa_p << std::endl << prv->pub->dsa_q << std::endl <<
		prv->pub->dsa_g << std::endl << prv->tdss_h << std::endl;
	dss_in << prv->tdss_n << std::endl << prv->tdss_t << std::endl <<
		prv->tdss_i << std::endl;
	dss_in << prv->tdss_x_i << std::endl << prv->tdss_xprime_i << std::endl <<
		prv->pub->dsa_y << std::endl;
	dss_in << prv->tdss_qual.size() << std::endl;
	for (size_t i = 0; i < prv->tdss_qual.size(); i++)
		dss_in << prv->tdss_qual[i] << std::endl;
	// tdss->dkg
	dss_in << prv->pub->dsa_p << std::endl << prv->pub->dsa_q << std::endl <<
		prv->pub->dsa_g << std::endl << prv->tdss_h << std::endl;
	dss_in << prv->tdss_n << std::endl << prv->tdss_t << std::endl <<
		prv->tdss_i << std::endl;
	dss_in << prv->tdss_x_i << std::endl << prv->tdss_xprime_i << std::endl <<
		prv->pub->dsa_y << std::endl;
	dss_in << prv->tdss_qual.size() << std::endl;
	for (size_t i = 0; i < prv->tdss_qual.size(); i++)
		dss_in << prv->tdss_qual[i] << std::endl;
	// tdss->dkg->x_rvss
	dss_in << prv->pub->dsa_p << std::endl << prv->pub->dsa_q << std::endl <<
		prv->pub->dsa_g << std::endl << prv->tdss_h << std::endl;
	dss_in << prv->tdss_n << std::endl << prv->tdss_t << std::endl <<
		prv->tdss_i << std::endl << prv->tdss_t << std::endl;
	dss_in << prv->tdss_x_i << std::endl << prv->tdss_xprime_i << std::endl;
	dss_in << "0" << std::endl << "0" << std::endl;
	dss_in << prv->tdss_x_rvss_qual.size() << std::endl;
	for (size_t i = 0; i < prv->tdss_x_rvss_qual.size(); i++)
		dss_in << prv->tdss_x_rvss_qual[i] << std::endl;
	assert((prv->tdss_c_ik.size() == prv->tdss_n));
	for (size_t i = 0; i < prv->tdss_c_ik.size(); i++)
	{
		for (size_t j = 0; j < prv->tdss_c_ik.size(); j++)
			dss_in << "0" << std::endl << "0" << std::endl;
		assert((prv->tdss_c_ik[i].size() == (prv->tdss_t + 1)));
		for (size_t k = 0; k < prv->tdss_c_ik[i].size(); k++)
			dss_in << prv->tdss_c_ik[i][k] << std::endl;
	}
	if (opt_verbose)
		std::cerr << "INFO: CanettiGennaroJareckiKrawczykRabinDSS(in, ...)" <<
			std::endl;
	dss = new CanettiGennaroJareckiKrawczykRabinDSS(dss_in);
	if (!dss->CheckGroup())
	{
		std::cerr << "ERROR: bad tDSS domain parameters" << std::endl;
		return false;
	}
	return true;
}

bool init_tElG
	(const TMCG_OpenPGP_PrivateSubkey *sub, const int opt_verbose,
	 GennaroJareckiKrawczykRabinDKG* &dkg)
{
//	tmcg_openpgp_secure_stringstream_t dkg_in; // TODO
	std::stringstream dkg_in;
	dkg_in << sub->pub->elg_p << std::endl << sub->telg_q << std::endl <<
		sub->pub->elg_g << std::endl << sub->telg_h << std::endl;
	dkg_in << sub->telg_n << std::endl << sub->telg_t << std::endl <<
		sub->telg_i << std::endl;
	dkg_in << sub->telg_x_i << std::endl << sub->telg_xprime_i <<
		std::endl << sub->pub->elg_y << std::endl;
	dkg_in << sub->telg_qual.size() << std::endl;
	for (size_t i = 0; i < sub->telg_qual.size(); i++)
		dkg_in << sub->telg_qual[i] << std::endl;
	for (size_t i = 0; i < sub->telg_n; i++)
		dkg_in << "1" << std::endl; // y_i not yet stored
	for (size_t i = 0; i < sub->telg_n; i++)
		dkg_in << "0" << std::endl; // z_i not yet stored
	assert((sub->telg_v_i.size() == sub->telg_n));
	for (size_t i = 0; i < sub->telg_v_i.size(); i++)
		dkg_in << sub->telg_v_i[i] << std::endl;
	assert((sub->telg_c_ik.size() == sub->telg_n));
	for (size_t i = 0; i < sub->telg_n; i++)
	{
		// s_ij and sprime_ij not yet stored
		for (size_t j = 0; j < sub->telg_n; j++)
			dkg_in << "0" << std::endl << "0" << std::endl;
		assert((sub->telg_c_ik[i].size() == (sub->telg_t + 1)));
		for (size_t k = 0; k < sub->telg_c_ik[i].size(); k++)
			dkg_in << sub->telg_c_ik[i][k] << std::endl;
	}
	if (opt_verbose)
		std::cerr << "INFO: GennaroJareckiKrawczykRabinDKG(in, ...)" <<
			std::endl;
	dkg = new GennaroJareckiKrawczykRabinDKG(dkg_in);
	if (!dkg->CheckGroup())
	{
		std::cerr << "ERROR: bad tElG domain parameters" << std::endl;
		return false;
	}
	if (!dkg->CheckKey())
	{
		std::cerr << "ERROR: bad tElG key" << std::endl;
		return false;
	}
	return true;
}

bool verify_signature
	(const tmcg_openpgp_octets_t &data,
	 const std::string &armored_pubkey,
	 const TMCG_OpenPGP_Signature *signature,
	 const TMCG_OpenPGP_Keyring *ring,
	 const int opt_verbose,
	 const bool opt_weak)
{
	TMCG_OpenPGP_Pubkey *primary = NULL;
	bool parse_ok = CallasDonnerhackeFinneyShawThayerRFC4880::
		PublicKeyBlockParse(armored_pubkey, opt_verbose, primary);
	if (parse_ok)
	{
		primary->CheckSelfSignatures(ring, opt_verbose);
		if (!primary->valid && !opt_weak)
		{
			std::cerr << "ERROR: primary key is not valid" << std::endl;
			delete primary;
			return false;
		}
		primary->CheckSubkeys(ring, opt_verbose);
		if (!opt_weak)
			primary->Reduce(); // keep only valid subkeys
		if (primary->Weak(opt_verbose) && !opt_weak)
		{
			std::cerr << "ERROR: weak primary key is not allowed" << std::endl;
			delete primary;
			return false;
		}
	}
	else
	{
		std::cerr << "ERROR: cannot use the provided public key" << std::endl;
		return false;
	}

	// select corresponding public key of the issuer from subkeys
	bool subkey_selected = false;
	size_t subkey_idx = 0, keyusage = 0;
	time_t ckeytime = 0, ekeytime = 0;
	for (size_t j = 0; j < primary->subkeys.size(); j++)
	{
		if (((primary->subkeys[j]->AccumulateFlags() & 0x02) == 0x02) ||
		    (!primary->subkeys[j]->AccumulateFlags() &&
			((primary->subkeys[j]->pkalgo == TMCG_OPENPGP_PKALGO_RSA) || 
			(primary->subkeys[j]->pkalgo == TMCG_OPENPGP_PKALGO_RSA_SIGN_ONLY) ||
			(primary->subkeys[j]->pkalgo == TMCG_OPENPGP_PKALGO_DSA) ||
			(primary->subkeys[j]->pkalgo == TMCG_OPENPGP_PKALGO_ECDSA))))
		{
			if (CallasDonnerhackeFinneyShawThayerRFC4880::
				OctetsCompare(signature->issuer, primary->subkeys[j]->id))
			{
				subkey_selected = true;
				subkey_idx = j;
				keyusage = primary->subkeys[j]->AccumulateFlags();
				ckeytime = primary->subkeys[j]->creationtime;
				ekeytime = primary->subkeys[j]->expirationtime;
				break;
			}
		}
	}

	// check the primary key, if no admissible subkey has been selected
	if (!subkey_selected)
	{
		if (((primary->AccumulateFlags() & 0x02) != 0x02) &&
		    (!primary->AccumulateFlags() &&
			(primary->pkalgo != TMCG_OPENPGP_PKALGO_RSA) &&
			(primary->pkalgo != TMCG_OPENPGP_PKALGO_RSA_SIGN_ONLY) &&
			(primary->pkalgo != TMCG_OPENPGP_PKALGO_DSA) &&
			(primary->pkalgo != TMCG_OPENPGP_PKALGO_ECDSA)))
		{
			std::cerr << "ERROR: no admissible public key found" << std::endl;
			delete primary;
			return false;
		}
		if (!CallasDonnerhackeFinneyShawThayerRFC4880::
			OctetsCompare(signature->issuer, primary->id))
		{
			std::cerr << "ERROR: no admissible public key found" << std::endl;
			delete primary;
			return false;
		}
		keyusage = primary->AccumulateFlags();
		ckeytime = primary->creationtime;
		ekeytime = primary->expirationtime;
	}
	else
	{
		if (primary->subkeys[subkey_idx]->Weak(opt_verbose) && !opt_weak)
		{
			std::cerr << "ERROR: weak subkey is not allowed" << std::endl;
			delete primary;
			return false;
		}
	}

	// additional validity checks on key and signature
	time_t current_time = time(NULL);
	// 1. key validity time (signatures made before key creation or
	//    after key expiry are not valid)
	if (signature->creationtime < ckeytime)
	{
		std::cerr << "ERROR: signature was made before key creation" <<
			std::endl;
		delete primary;
		return false;
	}
	if (ekeytime && (signature->creationtime > (ckeytime + ekeytime)))
	{
		std::cerr << "ERROR: signature was made after key expiry" << std::endl;
		delete primary;
		return false;
	}
	// 2. signature validity time (expired signatures are not valid)
	if (signature->expirationtime &&
		(current_time > (signature->creationtime + signature->expirationtime)))
	{
		std::cerr << "ERROR: signature is expired" << std::endl;
		delete primary;
		return false;
	}
	// 3. key usage flags (signatures made by keys not with the "signing"
	//    capability are not valid)
	if (!opt_weak && ((keyusage & 0x02) != 0x02))
	{
		std::cerr << "ERROR: corresponding key was not intented for signing" <<
			std::endl;
		delete primary;
		return false;
	}
	// 4. key validity time (expired keys are not valid)
	if (!opt_weak && ekeytime && (current_time > (ckeytime + ekeytime)))
	{
		std::cerr << "ERROR: corresponding key is expired" << std::endl;
		delete primary;
		return false;
	}

	// verify signature cryptographically
	bool verify_ok = false;
	if (subkey_selected)
		verify_ok = signature->VerifyData(primary->subkeys[subkey_idx]->key,
			data, opt_verbose);
	else
		verify_ok = signature->VerifyData(primary->key, data, opt_verbose);

	// release primary key
	delete primary;

	if (!verify_ok)
	{
		if (opt_verbose)
			std::cerr << "INFO: Bad signature included" << std::endl;
		return false;
	}
	else
	{
		if (opt_verbose)
			std::cerr << "INFO: Good signature included" << std::endl;
	}
	return true;
}

