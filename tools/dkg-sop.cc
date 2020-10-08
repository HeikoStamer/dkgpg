/*******************************************************************************
   This file is part of Distributed Privacy Guard (DKGPG).

 Copyright (C) 2019, 2020  Heiko Stamer <HeikoStamer@gmx.net>

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

// [DKG20] https://datatracker.ietf.org/doc/draft-dkg-openpgp-stateless-cli/

// include headers
#ifdef HAVE_CONFIG_H
	#include "dkgpg_config.h"
#endif

#include <string>
#include <vector>
#include <ctime>
#include <cstdio>

#include <libTMCG.hh>

#include "dkg-io.hh"
#include "dkg-common.hh"

int opt_verbose = 0;
bool opt_rfc4880bis = true;
bool opt_armor = true;
bool opt_as_binary = true;
bool opt_as_text = false;
time_t opt_not_before = 0;
time_t opt_not_after = 0;
std::vector<std::string> opt_with_password;
std::vector<std::string> opt_sign_with;

bool generate
	(const std::vector<std::string> &args,
	 const tmcg_openpgp_secure_string_t &passphrase) 
{
	time_t keytime = time(NULL); // current time
	time_t keyexptime = 0; // no expiration
	std::stringstream crss;
	mpz_t cache[TMCG_MAX_SSRANDOMM_CACHE], cache_mod;
	size_t cache_avail = 0;
	// check magic bytes of CRS (common reference string)
	if (TMCG_ParseHelper::cm(crs, "fips-crs", '|'))
	{
		if (opt_verbose)
		{
			std::cerr << "INFO: verifying domain parameters (according" <<
				" to FIPS 186-4 section A.1.1.2)" << std::endl;
		}
	}
	else
	{
		std::cerr << "ERROR: wrong type of CRS detected" << std::endl;
		return false;
	}
	// extract p, q, g from CRS
	mpz_t fips_p, fips_q, fips_g;
	mpz_init(fips_p), mpz_init(fips_q), mpz_init(fips_g);
	if (!pqg_extract(crs, true, opt_verbose, fips_p, fips_q, fips_g, crss))
	{
		mpz_clear(fips_p), mpz_clear(fips_q), mpz_clear(fips_g);
		return false;
	}
	// initialize cache
	if (opt_verbose)
	{
		std::cerr << "INFO: We need a lot of entropy for key generation." <<
			std::endl;
		std::cerr << "Please use other programs, move the mouse, and" <<
			" type on your keyboard: " << std::endl;
	}
	tmcg_mpz_ssrandomm_cache_init(cache, cache_mod, cache_avail, 2, fips_q);
	if (opt_verbose)
		std::cerr << "Thank you!" << std::endl;
	mpz_clear(fips_p), mpz_clear(fips_q), mpz_clear(fips_g);
	// create a VTMF instance from CRS
	BarnettSmartVTMF_dlog *vtmf = new BarnettSmartVTMF_dlog(crss,
		TMCG_DDH_SIZE, TMCG_DLSE_SIZE, false); // without VTMF-verifiable g
	// check the VTMF instance
	if (!vtmf->CheckGroup())
	{
		std::cerr << "ERROR: group G from CRS is bad" << std::endl;
		delete vtmf;
		return false;
	}
	// select hash algorithm for OpenPGP based on |q| (size in bit)
	tmcg_openpgp_hashalgo_t hashalgo = TMCG_OPENPGP_HASHALGO_UNKNOWN;
	if (mpz_sizeinbase(vtmf->q, 2L) == 256)
		hashalgo = TMCG_OPENPGP_HASHALGO_SHA256; // SHA256 (alg 8)
	else if (mpz_sizeinbase(vtmf->q, 2L) == 384)
		hashalgo = TMCG_OPENPGP_HASHALGO_SHA384; // SHA384 (alg 9)
	else if (mpz_sizeinbase(vtmf->q, 2L) == 512)
		hashalgo = TMCG_OPENPGP_HASHALGO_SHA512; // SHA512 (alg 10)
	else
	{
		std::cerr << "ERROR: selecting hash algorithm failed for |q| = " <<
			mpz_sizeinbase(vtmf->q, 2L) << std::endl;
		delete vtmf;
		return false;
	}
	// generate a non-shared DSA primary key
	mpz_t dsa_y, dsa_x;
	mpz_init(dsa_y), mpz_init(dsa_x);
	tmcg_mpz_ssrandomm_cache(cache, cache_mod, cache_avail, dsa_x, vtmf->q);
	tmcg_mpz_spowm(dsa_y, vtmf->g, dsa_x, vtmf->p);
	// extract parameters for OpenPGP key structures
	tmcg_openpgp_octets_t pub, sec, dirsig;
	tmcg_openpgp_octets_t sub, ssb, subsig, dsaflags, elgflags, issuer;
	tmcg_openpgp_octets_t pub_hashing, sub_hashing;
	tmcg_openpgp_octets_t dirsig_hashing, dirsig_left;
	tmcg_openpgp_octets_t subsig_hashing, subsig_left;
	tmcg_openpgp_octets_t hash, empty;
	time_t sigtime;
	gcry_sexp_t key;
	gcry_mpi_t p, q, g, y, x, r, s;
	gcry_error_t ret;
	p = gcry_mpi_new(2048);
	if (!tmcg_mpz_get_gcry_mpi(p, vtmf->p))
	{
		std::cerr << "ERROR: tmcg_mpz_get_gcry_mpi() failed" << std::endl;
		mpz_clear(dsa_y), mpz_clear(dsa_x);
		gcry_mpi_release(p);
		delete vtmf;
		return false;
	}
	q = gcry_mpi_new(2048);
	if (!tmcg_mpz_get_gcry_mpi(q, vtmf->q))
	{
		std::cerr << "ERROR: tmcg_mpz_get_gcry_mpi() failed" << std::endl;
		mpz_clear(dsa_y), mpz_clear(dsa_x);
		gcry_mpi_release(p);
		gcry_mpi_release(q);
		delete vtmf;
		return false;
	}
	g = gcry_mpi_new(2048);
	if (!tmcg_mpz_get_gcry_mpi(g, vtmf->g))
	{
		std::cerr << "ERROR: tmcg_mpz_get_gcry_mpi() failed" << std::endl;
		mpz_clear(dsa_y), mpz_clear(dsa_x);
		gcry_mpi_release(p);
		gcry_mpi_release(q);
		gcry_mpi_release(g);
		delete vtmf;
		return false;
	}
	y = gcry_mpi_new(2048);
	if (!tmcg_mpz_get_gcry_mpi(y, dsa_y))
	{
		std::cerr << "ERROR: tmcg_mpz_get_gcry_mpi() failed" << std::endl;
		mpz_clear(dsa_y), mpz_clear(dsa_x);
		gcry_mpi_release(p);
		gcry_mpi_release(q);
		gcry_mpi_release(g);
		gcry_mpi_release(y);
		delete vtmf;
		return false;
	}
	x = gcry_mpi_snew(2048);
	if (!tmcg_mpz_get_gcry_mpi(x, dsa_x))
	{
		std::cerr << "ERROR: tmcg_mpz_get_gcry_mpi() failed" << std::endl;
		mpz_clear(dsa_y), mpz_clear(dsa_x);
		gcry_mpi_release(p);
		gcry_mpi_release(q);
		gcry_mpi_release(g);
		gcry_mpi_release(y);
		gcry_mpi_release(x);
		delete vtmf;
		return false;
	}
	mpz_clear(dsa_y), mpz_clear(dsa_x);
	size_t erroff;
	ret = gcry_sexp_build(&key, &erroff,
		"(key-data (public-key (dsa (p %M) (q %M) (g %M) (y %M)))"
		" (private-key (dsa (p %M) (q %M) (g %M) (y %M) (x %M))))",
		p, q, g, y, p, q, g, y, x);
	if (ret)
	{
		std::cerr << "ERROR: gcry_sexp_build() failed" << std::endl;
		gcry_mpi_release(p);
		gcry_mpi_release(q);
		gcry_mpi_release(g);
		gcry_mpi_release(y);
		gcry_mpi_release(x);
		delete vtmf;
		return false;
	}
	CallasDonnerhackeFinneyShawThayerRFC4880::
		PacketPubEncode(keytime, TMCG_OPENPGP_PKALGO_DSA, p, q, g, y, pub);
	CallasDonnerhackeFinneyShawThayerRFC4880::
		PacketSecEncode(keytime, TMCG_OPENPGP_PKALGO_DSA, p, q, g, y, x,
			passphrase, sec);
	CallasDonnerhackeFinneyShawThayerRFC4880::
		PacketBodyExtract(pub, 0, pub_hashing);
	CallasDonnerhackeFinneyShawThayerRFC4880::
		FingerprintCompute(pub_hashing, issuer);
	std::vector<tmcg_openpgp_octets_t> uid, uidsig;
	uid.resize(args.size());
	uidsig.resize(args.size());
	for (size_t i = 0; i < args.size(); i++)
	{
		CallasDonnerhackeFinneyShawThayerRFC4880::
			PacketUidEncode(args[i], uid[i]);
	}
	dsaflags.push_back(0x01 | 0x02);
	sigtime = time(NULL); // current time
	CallasDonnerhackeFinneyShawThayerRFC4880::
		PacketSigPrepareDesignatedRevoker(TMCG_OPENPGP_PKALGO_DSA, hashalgo,
			sigtime, dsaflags, issuer, (tmcg_openpgp_pkalgo_t)0, empty,
			opt_rfc4880bis, dirsig_hashing);
	hash.clear();
	CallasDonnerhackeFinneyShawThayerRFC4880::
		KeyHash(pub_hashing, dirsig_hashing, hashalgo, hash, dirsig_left);
	r = gcry_mpi_new(2048);
	s = gcry_mpi_new(2048);
	ret = CallasDonnerhackeFinneyShawThayerRFC4880::
		AsymmetricSignDSA(hash, key, r, s);
	if (ret)
	{
		std::cerr << "ERROR: AsymmetricSignDSA() failed" << std::endl;
		gcry_mpi_release(p);
		gcry_mpi_release(q);
		gcry_mpi_release(g);
		gcry_mpi_release(y);
		gcry_mpi_release(x);
		gcry_mpi_release(r);
		gcry_mpi_release(s);
		gcry_sexp_release(key);
		delete vtmf;
		return false;
	}
	CallasDonnerhackeFinneyShawThayerRFC4880::
		PacketSigEncode(dirsig_hashing, dirsig_left, r, s, dirsig);
	gcry_mpi_release(r);
	gcry_mpi_release(s);
	for (size_t i = 0; i < uid.size(); i++)
	{
		tmcg_openpgp_octets_t uidsig_hashing, uidsig_left;
		CallasDonnerhackeFinneyShawThayerRFC4880::
			PacketSigPrepareSelfSignature(
				TMCG_OPENPGP_SIGNATURE_POSITIVE_CERTIFICATION, 
				TMCG_OPENPGP_PKALGO_DSA, hashalgo, sigtime, keyexptime,
				dsaflags, issuer, opt_rfc4880bis, uidsig_hashing); 
		hash.clear();
		CallasDonnerhackeFinneyShawThayerRFC4880::
			CertificationHash(pub_hashing, args[i], empty, uidsig_hashing,
			hashalgo, hash, uidsig_left);
		r = gcry_mpi_new(2048);
		s = gcry_mpi_new(2048);
		ret = CallasDonnerhackeFinneyShawThayerRFC4880::
			AsymmetricSignDSA(hash, key, r, s);
		if (ret)
		{
			std::cerr << "ERROR: AsymmetricSignDSA() failed" << std::endl;
			gcry_mpi_release(p);
			gcry_mpi_release(q);
			gcry_mpi_release(g);
			gcry_mpi_release(y);
			gcry_mpi_release(x);
			gcry_mpi_release(r);
			gcry_mpi_release(s);
			gcry_sexp_release(key);
			delete vtmf;
			return false;
		}
		CallasDonnerhackeFinneyShawThayerRFC4880::
			PacketSigEncode(uidsig_hashing, uidsig_left, r, s, uidsig[i]);
		gcry_mpi_release(r);
		gcry_mpi_release(s);
	}
	gcry_mpi_release(x);
	gcry_mpi_release(y);
	// generate a non-shared ElGamal subkey with same domain parameter set
	mpz_t elg_y, elg_x;
	mpz_init(elg_y), mpz_init(elg_x);
	tmcg_mpz_ssrandomm_cache(cache, cache_mod, cache_avail, elg_x, vtmf->q);
	tmcg_mpz_spowm(elg_y, vtmf->g, elg_x, vtmf->p);
	// extract further parameters for OpenPGP key structures
	y = gcry_mpi_new(2048);
	if (!tmcg_mpz_get_gcry_mpi(y, elg_y))
	{
		std::cerr << "ERROR: tmcg_mpz_get_gcry_mpi() failed" << std::endl;
		mpz_clear(elg_y), mpz_clear(elg_x);
		gcry_mpi_release(p);
		gcry_mpi_release(q);
		gcry_mpi_release(g);
		gcry_mpi_release(y);
		gcry_sexp_release(key);
		delete vtmf;
		return false;
	}
	x = gcry_mpi_snew(2048);
	if (!tmcg_mpz_get_gcry_mpi(x, elg_x))
	{
		std::cerr << "ERROR: tmcg_mpz_get_gcry_mpi() failed" << std::endl;
		mpz_clear(elg_y), mpz_clear(elg_x);
		gcry_mpi_release(p);
		gcry_mpi_release(q);
		gcry_mpi_release(g);
		gcry_mpi_release(y);
		gcry_mpi_release(x);
		delete vtmf;
		return false;
	}
	mpz_clear(elg_y), mpz_clear(elg_x);
	CallasDonnerhackeFinneyShawThayerRFC4880::
		PacketSubEncode(keytime, TMCG_OPENPGP_PKALGO_ELGAMAL, p, q, g, y, sub);
	CallasDonnerhackeFinneyShawThayerRFC4880::
		PacketSsbEncode(keytime, TMCG_OPENPGP_PKALGO_ELGAMAL, p, q, g, y,
			x, passphrase, ssb);
	gcry_mpi_release(x);
	gcry_mpi_release(y);
	elgflags.push_back(0x04 | 0x08);
	sigtime = time(NULL); // current time
	// Subkey Binding Signature (0x18) of sub
	CallasDonnerhackeFinneyShawThayerRFC4880::
		PacketSigPrepareSelfSignature(TMCG_OPENPGP_SIGNATURE_SUBKEY_BINDING,
			TMCG_OPENPGP_PKALGO_DSA, hashalgo, sigtime, keyexptime, elgflags,
			issuer, opt_rfc4880bis, subsig_hashing);
	CallasDonnerhackeFinneyShawThayerRFC4880::
		PacketBodyExtract(sub, 0, sub_hashing);
	hash.clear();
	CallasDonnerhackeFinneyShawThayerRFC4880::
		KeyHash(pub_hashing, sub_hashing, subsig_hashing, hashalgo, hash,
			subsig_left);
	r = gcry_mpi_new(2048);
	s = gcry_mpi_new(2048);
	ret = CallasDonnerhackeFinneyShawThayerRFC4880::
		AsymmetricSignDSA(hash, key, r, s);
	if (ret)
	{
		std::cerr << "ERROR: AsymmetricSignDSA() failed" << std::endl;
		gcry_mpi_release(p);
		gcry_mpi_release(q);
		gcry_mpi_release(g);
		gcry_mpi_release(r);
		gcry_mpi_release(s);
		gcry_sexp_release(key);
		delete vtmf;
		return false;
	}
	CallasDonnerhackeFinneyShawThayerRFC4880::
		PacketSigEncode(subsig_hashing, subsig_left, r, s, subsig);
	gcry_mpi_release(r);
	gcry_mpi_release(s);
	// release
	gcry_mpi_release(p);
	gcry_mpi_release(q);
	gcry_mpi_release(g);
	gcry_sexp_release(key);
	// release the VTMF instance
	delete vtmf;
	// release cache
	tmcg_mpz_ssrandomm_cache_done(cache, cache_mod, cache_avail);
	// produce the output
	tmcg_openpgp_octets_t all;
	all.insert(all.end(), sec.begin(), sec.end());
	all.insert(all.end(), dirsig.begin(), dirsig.end());
	for (size_t i = 0; i < uid.size(); i++)
	{
		all.insert(all.end(), uid[i].begin(), uid[i].end());
		all.insert(all.end(), uidsig[i].begin(), uidsig[i].end());
	}
	all.insert(all.end(), ssb.begin(), ssb.end());
	all.insert(all.end(), subsig.begin(), subsig.end());
	if (opt_armor)
	{
		std::string armor;
		CallasDonnerhackeFinneyShawThayerRFC4880::
			ArmorEncode(TMCG_OPENPGP_ARMOR_PRIVATE_KEY_BLOCK, all, armor);
		std::cout << armor << std::endl;
	}
	else
	{
		for (size_t i = 0; i < all.size(); i++)
			std::cout << all[i];
	}
	return true;
}

bool extract
	(const tmcg_openpgp_secure_string_t &passphrase)
{
	// read and parse the private key
	TMCG_OpenPGP_Prvkey *prv = NULL;
	if (opt_armor)
	{
		std::string armored_key;
		read_stdin("-----END PGP PRIVATE KEY BLOCK-----" , armored_key, false);
		if (!CallasDonnerhackeFinneyShawThayerRFC4880::
			PrivateKeyBlockParse(armored_key, opt_verbose, passphrase, prv))
		{
			return false;
		}
	}
	else
	{
		tmcg_openpgp_octets_t key;
		char c;
		while (std::cin.get(c))
			key.push_back(c);
		if (!CallasDonnerhackeFinneyShawThayerRFC4880::
			PrivateKeyBlockParse(key, opt_verbose, passphrase, prv))
		{
			return false;
		}
	}
	// export the public key
	tmcg_openpgp_octets_t all;
	prv->pub->Export(all);
	delete prv;
	// output the result
	if (opt_armor)
	{
		std::string armor;
		CallasDonnerhackeFinneyShawThayerRFC4880::
			ArmorEncode(TMCG_OPENPGP_ARMOR_PUBLIC_KEY_BLOCK, all, armor);
		std::cout << armor << std::endl;
	}
	else
	{
		for (size_t i = 0; i < all.size(); i++)
			std::cout << all[i];
	}
	return true;
}

bool sign
	(const std::vector<std::string> &args,
	 const tmcg_openpgp_secure_string_t &passphrase,
	 const tmcg_openpgp_octets_t &data)
{
	tmcg_openpgp_octets_t sig;
	for (size_t i = 0; i < args.size(); i++)
	{
		std::string armored_key;
		if (!autodetect_file(args[i], TMCG_OPENPGP_ARMOR_PRIVATE_KEY_BLOCK,
			armored_key))
		{
			return false;
		}
		TMCG_OpenPGP_Prvkey *prv = NULL;
		if (!CallasDonnerhackeFinneyShawThayerRFC4880::
			PrivateKeyBlockParse(armored_key, opt_verbose, passphrase, prv))
		{
			return false;
		}
		time_t sigtime = time(NULL); // current time, fixed hash algo SHA2-512
		tmcg_openpgp_hashalgo_t hashalgo = TMCG_OPENPGP_HASHALGO_SHA512;
		tmcg_openpgp_octets_t trailer, hash, left;
		bool hret = false;
		if (opt_as_text)
		{
			CallasDonnerhackeFinneyShawThayerRFC4880::
				PacketSigPrepareDetachedSignature(
					TMCG_OPENPGP_SIGNATURE_CANONICAL_TEXT_DOCUMENT,
					prv->pub->pkalgo, hashalgo, sigtime, 0, "",
					prv->pub->fingerprint, trailer);
			hret = CallasDonnerhackeFinneyShawThayerRFC4880::
				TextDocumentHash(data, trailer, hashalgo, hash, left);
		}
		else
		{
			CallasDonnerhackeFinneyShawThayerRFC4880::
				PacketSigPrepareDetachedSignature(
					TMCG_OPENPGP_SIGNATURE_BINARY_DOCUMENT, prv->pub->pkalgo,
					hashalgo, sigtime, 0, "", prv->pub->fingerprint, trailer);
			hret = CallasDonnerhackeFinneyShawThayerRFC4880::
				BinaryDocumentHash(data, trailer, hashalgo, hash, left);
		}
		if (!hret)
		{
			std::cerr << "ERROR: [Text|Binary]DocumentHash() failed" <<
				std::endl;
			delete prv;
			return false;
		}

		gcry_error_t ret;
		gcry_mpi_t r, s;
		r = gcry_mpi_new(2048);
		s = gcry_mpi_new(2048);
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
				delete prv;
				return false;
		}
		if (ret)
		{
			std::cerr << "ERROR: signing of hash value failed " <<
				"(rc = " << gcry_err_code(ret) << ", str = " <<
				gcry_strerror(ret) << ")" << std::endl;
			gcry_mpi_release(r), gcry_mpi_release(s);
			delete prv;
			return false;
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
				CallasDonnerhackeFinneyShawThayerRFC4880::
					PacketSigEncode(trailer, left, r, s, sig);
				break;
			default:
				std::cerr << "ERROR: public-key algorithm " <<
					(int)prv->pkalgo << " not supported" << std::endl;
				gcry_mpi_release(r), gcry_mpi_release(s);
				delete prv;
				return false;
		}
		gcry_mpi_release(r), gcry_mpi_release(s);
		delete prv;
	}
	// output the result
	if (opt_armor)
	{
		std::string armor;
		CallasDonnerhackeFinneyShawThayerRFC4880::
			ArmorEncode(TMCG_OPENPGP_ARMOR_SIGNATURE, sig, armor);
		std::cout << armor << std::endl;
	}
	else
	{
		for (size_t i = 0; i < sig.size(); i++)
			std::cout << sig[i];
	}
	return true;
}

bool verify
	(const std::vector<std::string> &args,
	 const tmcg_openpgp_octets_t &data,
	 std::vector<std::string> &verifications)
{
	// read the signature(s) 
	std::string armored_signatures;
	if (!autodetect_file(args[0], TMCG_OPENPGP_ARMOR_SIGNATURE,
		armored_signatures))
	{
		return false;
	}
	// parse the signature(s)
	TMCG_OpenPGP_Signatures sigs;
	bool parse_ok = CallasDonnerhackeFinneyShawThayerRFC4880::
		SignaturesParse(armored_signatures, opt_verbose, sigs);
	if (!parse_ok)
	{
		std::cerr << "ERROR: cannot parse resp. use the" <<
			" provided signature(s)" << std::endl;
		return false;
	}
	// verify the signature(s)
	for (size_t i = 0; i < sigs.size(); i++)
	{
		if (opt_verbose)
			sigs[i]->PrintInfo();
		for (size_t j = 1; j < args.size(); j++)
		{
			std::string armored_pubkey;
			if (!autodetect_file(args[j], TMCG_OPENPGP_ARMOR_PUBLIC_KEY_BLOCK,
				armored_pubkey))
			{
				for (size_t k = 0; k < sigs.size(); k++)
					delete sigs[k];
				return false;
			}
			TMCG_OpenPGP_Keyring *ring = new TMCG_OpenPGP_Keyring();
			TMCG_OpenPGP_Pubkey *primary = NULL;
			parse_ok = CallasDonnerhackeFinneyShawThayerRFC4880::
				PublicKeyBlockParse(armored_pubkey, opt_verbose, primary);
			if (parse_ok)
			{
				primary->CheckSelfSignatures(ring, opt_verbose);
				if (!primary->valid)
				{
					std::cerr << "WARNING: primary key is not valid" << std::endl;
					delete primary;
					delete ring;
					continue;
				}
				primary->CheckSubkeys(ring, opt_verbose);
				primary->Reduce(); // keep only valid subkeys
				if (primary->Weak(opt_verbose))
				{
					std::cerr << "WARNING: primary key is weak" << std::endl;
					delete primary;
					delete ring;
					continue;
				}
			}
			else
			{
				std::cerr << "WARNING: cannot parse primary key" << std::endl;
				delete ring;
				continue;
			}
			// select corresponding public key of the issuer from subkeys
			bool subkey_selected = false;
			size_t subkey_idx = 0, keyusage = 0;
			time_t ckeytime = 0, ekeytime = 0;
// TODO
			// verify signature cryptographically
			bool verify_ok = false;
			if (subkey_selected)
			{
				verify_ok = sigs[i]->Verify(primary->subkeys[subkey_idx]->key,
					data, opt_verbose);
			}
			else
				verify_ok = sigs[i]->Verify(primary->key, data, opt_verbose);
			if (verify_ok)
			{
				std::string v;
// TODO
				verifications.push_back(v);
			}
			delete primary;
			delete ring;
		}
	}
	for (size_t i = 0; i < sigs.size(); i++)
		delete sigs[i];
	return true;
}

bool timestamp
	(const std::string &s, time_t &ts)
{
	if (s == "-")
	{
		ts = 0; // beginning or end of time	
	}
	else if (s == "now")
	{
		ts = time(NULL); // now
	}
	else
	{
		struct tm t = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
		if ((s.find("Z") != s.npos) && (s.find("-") != s.npos))
		{
			char *p = strptime(s.c_str(),
				"%Y-%m-%dT%H:%M:%SZ", &t);
			if (p == NULL)
				return false;
		}
		else if ((s.find("Z") != s.npos) && (s.find("-") == s.npos))
		{
			char *p = strptime(s.c_str(),
				"%Y%m%dT%H%M%SZ", &t); // FIXME: may not work
			if (p == NULL)
				return false;
		}
		else if (s.find("+") != s.npos)
		{
			int tz_hour = 0, tz_min = 0, n = 0;
			n = sscanf(s.c_str(), "%d-%d-%dT%d:%d:%d+%d:%d",
				&t.tm_year, &t.tm_mon, &t.tm_mday,
				&t.tm_hour, &t.tm_min, &t.tm_sec,
				&tz_hour, &tz_min);
			if (n < 7)
				return false;
			t.tm_year -= 1900;
			t.tm_mon -= 1;
			if (tz_hour <= 23)
			{
				t.tm_hour += tz_hour;
				t.tm_min += tz_min;
			}
			else
			{
// TODO
			}
		}
		else if (s.find("+") == s.npos)
		{
			int tz_hour = 0, tz_min = 0, n = 0;
			n = sscanf(s.c_str(), "%d-%d-%dT%d:%d:%d-%d:%d",
				&t.tm_year, &t.tm_mon, &t.tm_mday,
				&t.tm_hour, &t.tm_min, &t.tm_sec,
				&tz_hour, &tz_min);
			if (n < 7)
				return false;
			t.tm_hour -= tz_hour;
			t.tm_min -= tz_min;
		}
		ts = mktime(&t);
		if (ts == ((time_t) -1))
			return false;
	}
	return true;
}

int main
	(int argc, char **argv)
{
	static const char *usage = "dkg-sop [OPTIONS] SUBCOMMAND [ARGS]";
	static const char *about = PACKAGE_STRING " " PACKAGE_URL;
	static const char *version = "dkg-sop " PACKAGE_VERSION;
	std::string subcmd;
	std::vector<std::string> args;
	bool opt_passphrase = false;
	bool end_of_options = false;
	opt_not_before = 0;
	opt_not_after = time(NULL);

	for (size_t i = 0; i < (size_t)(argc - 1); i++)
	{
		std::string arg = argv[i+1];
		if (!end_of_options && ((arg.find("--") == 0) || (arg.find("-") == 0)))
		{
			if (arg == "--")
			{
				end_of_options = true;
				continue;
			}
			// read options
			if ((arg.find("-h") == 0) || (arg.find("--help") == 0))
			{
				std::cout << usage << std::endl;
				std::cout << about << std::endl;
				std::cout << "Arguments mandatory for long options are also" <<
					" mandatory for short options." << std::endl;
				std::cout << "  -h, --help           print this help" <<
					std::endl;
				std::cout << "  -n, --no-rfc4880bis  disable features of RFC" <<
					" 4880bis" << std::endl;
				std::cout << "  -P, --passphrase     ask user for passphrase" <<
					std::endl;
				std::cout << "  -V, --verbose        increase verbosity" <<
					std::endl;
				return 0; // not continue
			}
			if ((arg.find("-n") == 0) || (arg.find("--no-rfc4880bis") == 0))
			{
				opt_rfc4880bis = false; // disable some features of RFC 4880bis
				continue;
			}
			if ((arg.find("-P") == 0) || (arg.find("--passphrase") == 0))
			{
				opt_passphrase = true; // ask user for passphrase
				continue;
			}
			if ((arg.find("-V") == 0) || (arg.find("--verbose") == 0))
			{
				opt_verbose++; // increase verbosity
				continue;
			}
			// The following options are from [DKG20].
			if (arg.find("--no-armor") == 0)
			{
				opt_armor = false; // disable ASCII-armored output
				continue;
			}
			if (arg.find("--as=binary") == 0)
			{
				opt_as_binary = true; // choose format "binary"
				opt_as_text = false;
				continue;
			}
			if (arg.find("--as=text") == 0)
			{
				opt_as_binary = false; // choose format "text"
				opt_as_text = true;
				continue;
			}
			if (arg.find("--not-before=") == 0)
			{
				std::string s = arg.substr(13);
				if (!timestamp(s, opt_not_before))
				{
					std::cerr << "ERROR: wrong timestamp" <<
						" format" << std::endl;
					return -1;
				}
				continue;
			}
			if (arg.find("--not-after=") == 0)
			{
				std::string s = arg.substr(12);
				if (!timestamp(s, opt_not_after))
				{
					std::cerr << "ERROR: wrong timestamp" <<
						" format" << std::endl;
					return -1;
				}
				continue;
			}
			if (arg.find("--with-password=") == 0)
			{
				std::string s = arg.substr(16);
				opt_with_password.push_back(s);
				continue;
			}
			if (arg.find("--sign-with=") == 0)
			{
				std::string s = arg.substr(12);
				opt_sign_with.push_back(s);
				continue;
			}
			std::cerr << "ERROR: SOP option \"" << arg << "\" not" <<
				" supported" << std::endl;
			return 37;
		}
		else
		{
			// read arguments
			if (subcmd.length() == 0)
			{
				subcmd = arg; // 1st argument is the SOP subcommand
			}
			else
			{
				if (!valid_utf8(arg))
				{
					std::cerr << "ERROR: invalid UTF-8 encoding found at" <<
						" argument #" << (i+1) << std::endl;
					return 53;
				}
				args.push_back(arg);
			}
		}
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

	// read passphrase
	tmcg_openpgp_secure_string_t passphrase;
	if (opt_passphrase)
	{
		tmcg_openpgp_secure_string_t passphrase_check;
		std::string ps1 = "Please enter the passphrase for the private key";
		std::string ps2 = "Please repeat the passphrase to continue";
		do
		{
			passphrase = "", passphrase_check = "";
			if (!get_passphrase(ps1, false, passphrase))
			{
				if (should_unlock)
					unlock_memory();
				return -1;
			}
			if (!get_passphrase(ps2, false, passphrase_check))
			{
				if (should_unlock)
					unlock_memory();
				return -1;
			}
			if (passphrase != passphrase_check)
			{
				std::cerr << "WARNING: passphrase does not match;" <<
					" please try again" << std::endl;
			}
			else if (passphrase == "")
			{
				std::cerr << "WARNING: private key protection disabled" <<
					" due to given empty passphrase" << std::endl;
			}
		}
		while (passphrase != passphrase_check);
	}

	// execute each supported subcommand
	int ret = 0;
	if (subcmd == "version")
	{
		// Version Information
		// The version string emitted should contain the name of the "sop"
		// implementation, followed by a single space, followed by the version
		// number. A "sop" implementation should use a version number that
		// respects an established standard that is easily comparable and
		// parsable, like [SEMVER]. [DKG20]
		std::cout << version << std::endl;
	}
	else if (subcmd == "generate-key")
	{
		// Generate a Secret Key
		//   Standard Input: ignored
		//   Standard Output: "KEY"
		// Generate a single default OpenPGP key with zero or more User IDs.
		// The generared secret key SHOULD be usable for as much of the "sop"
		// functionality as possible. [DKG20]
		if (!generate(args, passphrase))
			ret = -1;
	}
	else if (subcmd == "extract-cert")
	{
		// Extract a Certificate from a Secret Key
		//   Standard Input: "KEY"
		//   Standard Output: "CERTS"
		// Note that the resultant "CERTS" object will only ever contain one
   		// OpenPGP certificate, since "KEY" contains exactly one OpenPGP
		// Transferable Secret Key. [DKG20]
		if (!extract(passphrase))
			ret = -1;
	}
	else if (subcmd == "sign")
	{
		// Create Detached Signatures
		//   Standard Input: "DATA"
		//   Standard Output: "SIGNATURES"
		// Exactly one signature will be made by each supplied "KEY".
		// "--as" defaults to "binary". If "--as=text" and the input "DATA" is
		// not valid "UTF-8", "sop sign" fails with "EXPECTED_TEXT". [DKG20]
		tmcg_openpgp_octets_t data;
		char c;
		while (std::cin.get(c))
			data.push_back(c);
		if (opt_as_text)
		{
			if (!valid_utf8(data))
			{
				std::cerr << "ERROR: invalid UTF-8 encoding found" << std::endl;
				ret = 53;
			}
		}
		if ((ret == 0) && !sign(args, passphrase, data))
			ret = -1;
	}
	else if (subcmd == "verify")
	{
		// Verify Detached Signatures
		//  Standard Input: "DATA"
		//  Standard Output: "VERIFICATIONS"
		// "--not-before" and "--not-after" indicate that signatures
		// with dates outside certain range MUST NOT be considered
		// valid.
		// "--not-before" defaults to the beginning of time. Accepts
		// the special value "-" to indicate the beginning of time
		// (i.e. no lower boundary).
		// "--not-after" defaults to the current system time ("now").
		// Accepts the special value "-" to indicate the end of time
		// (i.e. no upper boundary).
		// "sop verify" only returns "OK" if at least one certificate
		// included in any "CERTS" object made a valid signature in
		// the range over the "DATA" supplied.
		// For details about the valid signatures, the user MUST
		// inspect the "VERIFICATIONS" output. [DKG20]
		tmcg_openpgp_octets_t data;
		std::vector<std::string> verifications;
		char c;
		while (std::cin.get(c))
			data.push_back(c);
		// If no "CERTS" are supplied, "sop verify" fails with
		// "MISSING_ARG". [DKG20]
		if (args.size() < 2)
		{
			std::cerr << "ERROR: Missing required argument" <<
				std::endl;
			ret = 19;
		}
		if ((ret == 0) && !verify(args, data, verifications))
			ret = -1;
		// If no valid signatures are found, "sop verify" fails with
		// "NO_SIGNATURE". [DKG20]
		if ((ret == 0) && (verifications.size() < 1))
		{
			std::cerr << "ERROR: No acceptable signatures found" <<
				std::endl;
			ret = 3;
		}
		for (size_t i = 0; i < verifications.size(); i++)
			std::cout << verifications[i] << std::endl;
	}
	else if (subcmd == "encrypt")
	{
		// Encrypt a Message
		//   Standard Input: "DATA"
		//   Standard Output: "CIPHERTEXT"
		// "--as" defaults to "binary". The setting of "--as"
		// corresponds to the one octet format field found in
		// the Literal Data packet at the core of the output
		// "CIPHERTEXT". If "--as" is set to "binary", the
		// octet is "b" ("0x62"). If it is "text", the format
		// octet is "u" ("0x75").  If it is "mime", the format
		// octet is "m" ("0x6d").
		// "--with-password" enables symmetric encryption (and
		// can be used multiple times if multiple passwords are
		// desired).  If "sop encrypt" encounters a "PASSWORD"
		// which is not a valid "UTF-8" string, or is otherwise
		// not robust in its representation to humans, it fails
		// with "PASSWORD_NOT_HUMAN_READABLE". If "sop encrypt"
		// sees trailing whitespace at the end of a "PASSWORD",
		// it will trim the trailing whitespace before using the
		// password.
		// "--sign-with" creates exactly one signature by the
		// identified secret key (and can be used multiple times
		// if signatures from multiple keys are desired).
		// If "--as" is set to "binary", then "--sign-with" will
		// sign as a binary document (OpenPGP signature type "0x00").
		// If "--as" is set to "text", then "--sign-with" will
		// sign as a canonical text document (OpenPGP signature
		// type "0x01"). In this case, if the input "DATA" is not
		// valid "UTF-8", "sop encrypt" fails with "EXPECTED_TEXT".
		// [DKG20]
		tmcg_openpgp_octets_t data;
		char c;
		while (std::cin.get(c))
			data.push_back(c);
		if (opt_as_text)
		{
			if (!valid_utf8(data))
			{
				std::cerr << "ERROR: invalid UTF-8 encoding found" << std::endl;
				ret = 53;
			}
		}

// TODO

	}
	else
	{
		std::cerr << "ERROR: SOP subcommand \"" << subcmd << "\" not" <<
			" supported" << std::endl;
		ret = 69;
	}

	// finish
	if (should_unlock)
		unlock_memory();	
	return ret;
}

