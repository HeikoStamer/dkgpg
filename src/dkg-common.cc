/*******************************************************************************
   This file is part of Distributed Privacy Guard (DKGPG).

 Copyright (C) 2017, 2018, 2019  Heiko Stamer <HeikoStamer@gmx.net>

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
	std::string fpr;
	CallasDonnerhackeFinneyShawThayerRFC4880::
		FingerprintConvertPlain(primary->fingerprint, fpr);
	if (!verify_ok)
	{
		if (opt_verbose)
		{
			std::cerr << "INFO: Bad signature by key " << fpr <<
				" included" << std::endl;
		}
	}
	else
	{
		if (opt_verbose)
		{
			std::cerr << "INFO: Good signature by key " << fpr <<
				" included" << std::endl;
		}
	}

	// release primary key
	delete primary;

	return verify_ok;
}

void xtest
	(const size_t num_xtests,
	 const size_t whoami,
	 const size_t peers,
	 CachinKursawePetzoldShoupRBC *rbc)
{
	for (size_t i = 0; i < num_xtests; i++)
	{
		mpz_t xtest;
		mpz_init_set_ui(xtest, i);
		std::cerr << "INFO: p_" << whoami << ": xtest = " << xtest << " <-> ";
		rbc->Broadcast(xtest);
		for (size_t ii = 0; ii < peers; ii++)
		{
			if (!rbc->DeliverFrom(xtest, ii))
				std::cerr << "<X> ";
			else
				std::cerr << xtest << " ";
		}
		std::cerr << std::endl;
		mpz_clear(xtest);
	}
}

time_t agree_time
	(const time_t mytime,
	 const size_t whoami,
	 const size_t peers,
	 const int opt_verbose,
	 CachinKursawePetzoldShoupRBC *rbc)
{
	if (opt_verbose)
		std::cerr << "INFO: agree on a creation time for OpenPGP" << std::endl;
	std::vector<time_t> tvs;
	mpz_t mtv;
	mpz_init_set_ui(mtv, mytime);
	rbc->Broadcast(mtv);
	tvs.push_back(mytime);
	for (size_t i = 0; i < peers; i++)
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
				std::cerr << "WARNING: p_" << whoami << ": no creation" <<
					" timestamp received from p_" << i << std::endl;
			}
		}
	}
	mpz_clear(mtv);
	std::sort(tvs.begin(), tvs.end()); // sort the received values
	if (tvs.size() < peers)
	{
		std::cerr << "WARNING: p_" << whoami << ": not enough timestamps" <<
			" received" << std::endl;
	}
	if (tvs.size() == 0)
	{
		std::cerr << "ERROR: p_" << whoami << ": no timestamps received" <<
			std::endl;
		tvs.push_back(0); // add at least one dummy return value
	}
	// use a median value as some kind of gentle agreement
	time_t coctime = tvs[tvs.size()/2];
	if (opt_verbose)
	{
		std::cerr << "INFO: p_" << whoami << ": canonicalized OpenPGP" <<
			" creation time = " << coctime << std::endl;
	}
	return coctime;
}

bool select_hashalgo
	(CanettiGennaroJareckiKrawczykRabinDSS *dss,
	 tmcg_openpgp_hashalgo_t &hashalgo)
{
	if (dss == NULL)
		return false;
	// select hash algorithm for OpenPGP based on |q| (size in bit)
	if (mpz_sizeinbase(dss->q, 2L) == 256)
		hashalgo = TMCG_OPENPGP_HASHALGO_SHA256; // SHA256 (alg 8)
	else if (mpz_sizeinbase(dss->q, 2L) == 384)
		hashalgo = TMCG_OPENPGP_HASHALGO_SHA384; // SHA384 (alg 9)
	else if (mpz_sizeinbase(dss->q, 2L) == 512)
		hashalgo = TMCG_OPENPGP_HASHALGO_SHA512; // SHA512 (alg 10)
	else
		return false;
	return true;
}

bool sign_hash
	(const tmcg_openpgp_octets_t &hash,
	 const tmcg_openpgp_octets_t &trailer,
	 const tmcg_openpgp_octets_t &left,
	 const size_t whoami,
	 const size_t peers,
	 TMCG_OpenPGP_Prvkey *prv,
	 const tmcg_openpgp_hashalgo_t hashalgo,
	 tmcg_openpgp_octets_t &sig,
	 const int opt_verbose,
	 const char *opt_y,
	 CanettiGennaroJareckiKrawczykRabinDSS *dss,
	 aiounicast_select *aiou,
	 CachinKursawePetzoldShoupRBC *rbc)
{
	// prepare the hash value
	tmcg_openpgp_byte_t buffer[1024];
	size_t buflen = 0;
	memset(buffer, 0, sizeof(buffer));
	if (opt_verbose > 1)
		std::cerr << std::hex << "INFO: hash = ";
	for (size_t i = 0; i < hash.size(); i++, buflen++)
	{
		if (i < sizeof(buffer))
			buffer[i] = hash[i];
		if (opt_verbose > 1)
			std::cerr << (int)hash[i] << " ";
	}
	if (opt_verbose > 1)
		std::cerr << std::dec << std::endl;

	// sign the hash value
	gcry_error_t ret;
	gcry_mpi_t r, s;
	r = gcry_mpi_new(2048);
	s = gcry_mpi_new(2048);
	if (opt_y == NULL)
	{
		gcry_mpi_t h;
		ret = gcry_mpi_scan(&h, GCRYMPI_FMT_USG, buffer, buflen, NULL);
		if (ret)
		{
			std::cerr << "ERROR: p_" << whoami << ": gcry_mpi_scan() failed" <<
				" for h" << std::endl;
			return false;
		}
		if (opt_verbose > 1)
			std::cerr << "INFO: p_" << whoami << ": h = " << h << std::endl;
		mpz_t dsa_m, dsa_r, dsa_s;
		mpz_init(dsa_m), mpz_init(dsa_r), mpz_init(dsa_s);
		if (!tmcg_mpz_set_gcry_mpi(h, dsa_m))
		{
			std::cerr << "ERROR: p_" << whoami << ": tmcg_mpz_set_gcry_mpi()" <<
				" failed for dsa_m" << std::endl;
			gcry_mpi_release(r), gcry_mpi_release(s), gcry_mpi_release(h);
			mpz_clear(dsa_m), mpz_clear(dsa_r), mpz_clear(dsa_s);
			return false;
		}
		gcry_mpi_release(h);
		std::stringstream err_log_sign;
		if (opt_verbose)
			std::cerr << "INFO: p_" << whoami << ": dss.Sign()" << std::endl;
		if (dss == NULL)
			return false; // should never happen: only to make scan-build happy
		if (!dss->Sign(peers, whoami, dsa_m, dsa_r, dsa_s,
			prv->tdss_idx2dkg, prv->tdss_dkg2idx, aiou, rbc, err_log_sign))
		{
			std::cerr << "ERROR: p_" << whoami << ": " <<
				"tDSS Sign() failed" << std::endl;
			std::cerr << "ERROR: p_" << whoami << ": log follows " <<
				std::endl << err_log_sign.str();
			gcry_mpi_release(r), gcry_mpi_release(s);
			mpz_clear(dsa_m), mpz_clear(dsa_r), mpz_clear(dsa_s);
			return false;
		}
		if (opt_verbose > 1)
			std::cerr << "INFO: p_" << whoami << ": log follows " <<
				std::endl << err_log_sign.str();
		if (!tmcg_mpz_get_gcry_mpi(r, dsa_r))
		{
			std::cerr << "ERROR: p_" << whoami << ": tmcg_mpz_get_gcry_mpi()" <<
				" failed for dsa_r" << std::endl;
			gcry_mpi_release(r), gcry_mpi_release(s);
			mpz_clear(dsa_m), mpz_clear(dsa_r), mpz_clear(dsa_s);
			return false;
		}
		if (!tmcg_mpz_get_gcry_mpi(s, dsa_s))
		{
			std::cerr << "ERROR: p_" << whoami << ": tmcg_mpz_get_gcry_mpi()" <<
				" failed for dsa_s" << std::endl;
			gcry_mpi_release(r), gcry_mpi_release(s);
			mpz_clear(dsa_m), mpz_clear(dsa_r), mpz_clear(dsa_s);
			return false;
		}
		mpz_clear(dsa_m), mpz_clear(dsa_r), mpz_clear(dsa_s);
	}
	else
	{
		switch (prv->pkalgo)
		{
			case TMCG_OPENPGP_PKALGO_RSA:
			case TMCG_OPENPGP_PKALGO_RSA_SIGN_ONLY:
				ret = CallasDonnerhackeFinneyShawThayerRFC4880::
					AsymmetricSignRSA(hash, prv->private_key, hashalgo, s);
				break;
			case TMCG_OPENPGP_PKALGO_DSA:
				ret = CallasDonnerhackeFinneyShawThayerRFC4880::
					AsymmetricSignDSA(hash, prv->private_key, r, s);
				break;
			case TMCG_OPENPGP_PKALGO_ECDSA:
				ret = CallasDonnerhackeFinneyShawThayerRFC4880::
					AsymmetricSignECDSA(hash, prv->private_key, r, s);
				break;
			case TMCG_OPENPGP_PKALGO_EDDSA:
				ret = CallasDonnerhackeFinneyShawThayerRFC4880::
					AsymmetricSignEdDSA(hash, prv->private_key, r, s);
				break;
			default:
				std::cerr << "ERROR: public-key algorithm " <<
					(int)prv->pkalgo << " not supported" << std::endl;
				gcry_mpi_release(r), gcry_mpi_release(s);
				return false;
		}
		if (ret)
		{
			std::cerr << "ERROR: signing of hash value failed " <<
				"(rc = " << gcry_err_code(ret) << ", str = " <<
				gcry_strerror(ret) << ")" << std::endl;
			gcry_mpi_release(r), gcry_mpi_release(s);
			return false;
		}
	}
	switch (prv->pkalgo)
	{
		case TMCG_OPENPGP_PKALGO_RSA:
		case TMCG_OPENPGP_PKALGO_RSA_SIGN_ONLY:
			CallasDonnerhackeFinneyShawThayerRFC4880::
				PacketSigEncode(trailer, left, s, sig);
			break;
		case TMCG_OPENPGP_PKALGO_DSA:
		case TMCG_OPENPGP_PKALGO_ECDSA:
		case TMCG_OPENPGP_PKALGO_EDDSA:
		case TMCG_OPENPGP_PKALGO_EXPERIMENTAL7:
			CallasDonnerhackeFinneyShawThayerRFC4880::
				PacketSigEncode(trailer, left, r, s, sig);
			break;
		default:
			std::cerr << "ERROR: public-key algorithm " << (int)prv->pkalgo <<
				" not supported" << std::endl;
			gcry_mpi_release(r), gcry_mpi_release(s);
			return false;
	}
	gcry_mpi_release(r), gcry_mpi_release(s);
	return true;
}

void canonicalize
	(std::vector<std::string> &p)
{
	std::sort(p.begin(), p.end());
	std::vector<std::string>::iterator it = std::unique(p.begin(), p.end());
	p.resize(std::distance(p.begin(), it));
}

int run_localtest
	(const size_t peers_size, const int opt_verbose,
	 pid_t pid[DKGPG_MAX_N],
	 int pipefd[DKGPG_MAX_N][DKGPG_MAX_N][2],
	 int bpipefd[DKGPG_MAX_N][DKGPG_MAX_N][2],
	 void (*fork_instance)(const size_t))
{
	assert(peers_size <= DKGPG_MAX_N);
	int ret = 0;
	std::cerr << "INFO: running local test with " << peers_size <<
		" participants" << std::endl;
	// open pipes
	for (size_t i = 0; i < peers_size; i++)
	{
		for (size_t j = 0; j < peers_size; j++)
		{
			if (pipe(pipefd[i][j]) < 0)
				perror("ERROR: dkg-common:run_localtest (pipe)");
			if (pipe(bpipefd[i][j]) < 0)
				perror("ERROR: dkg-common:run_localtest (pipe)");
		}
	}
	
	// start childs
	for (size_t i = 0; i < peers_size; i++)
		fork_instance(i);

	// sleep for five seconds
	sleep(5);
	
	// wait for childs and close pipes
	for (size_t i = 0; i < peers_size; i++)
	{
		int wstatus = 0;
		if (opt_verbose)
			std::cerr << "INFO: waitpid(" << pid[i] << ")" << std::endl;
		if (waitpid(pid[i], &wstatus, 0) != pid[i])
			perror("ERROR: dkg-common:run_localtest (waitpid)");
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
			ret = -1; // fatal error
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
		for (size_t j = 0; j < peers_size; j++)
		{
			if ((close(pipefd[i][j][0]) < 0) || (close(pipefd[i][j][1]) < 0))
				perror("ERROR: dkg-common:run_localtest (close)");
			if ((close(bpipefd[i][j][0]) < 0) || (close(bpipefd[i][j][1]) < 0))
				perror("ERROR: dkg-common:run_localtest (close)");
		}
	}
	return ret;
}

