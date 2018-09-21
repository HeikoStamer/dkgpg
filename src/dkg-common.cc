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

