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

// [DKG19] https://datatracker.ietf.org/doc/draft-dkg-openpgp-stateless-cli/

// include headers
#ifdef HAVE_CONFIG_H
	#include "dkgpg_config.h"
#endif

#include <string>
#include <vector>

#include <libTMCG.hh>

#include "dkg-io.hh"
#include "dkg-common.hh"

int opt_verbose = 0;
bool opt_armor = true;
bool opt_as_binary = true;
bool opt_as_text = false;

bool valid_utf8
	(const tmcg_openpgp_octets_t &data)
{
	// check for valid UTF-8 encoding
	size_t len = 0;
	for (size_t i = 0; i < data.size(); i++)
	{
		tmcg_openpgp_byte_t b1 = data[i];
		if (len > 0)
		{
			if ((b1 & 0xC0) != 0x80)
				return false; // non-continuation byte detected inside character
			len--;
		}
		else
		{
			if ((b1 == 0xC0) || (b1 == 0xC1))
				return false; // non-minimal encoding detected
			if ((b1 & 0x80) == 0x80)
			{
				if ((b1 & 0x40) != 0x40)
					return false; // unexpected continuation byte detected
				if ((b1 & 0x20) == 0x20)
				{
					if ((b1 & 0x10) == 0x10)
						len = 3;
					else
						len = 2;
				}
				else
					len = 1;
				if ((i + len) >= data.size())
					return false;
				if ((len == 2) && (b1 == 0xE0) && (data[i+1] <= 0x9F))
					return false; // non-minimal encoding detected
				if ((len == 2) && (b1 == 0xED) && (data[i+1] > 0x9F))
					return false; // invalid code points U+D800 through U+DFFF
				if ((len == 3) && (b1 == 0xF0) && (data[i+1] <= 0x8F))
					return false; // non-minimal encoding detected
				if ((len == 3) && (b1 == 0xF4) && (data[i+1] > 0x8F))
					return false; // invalid code points after U+10FFFF
				if ((len == 3) && (b1 >= 0xF5))
					return false; // invalid code points after U+10FFFF
			}
		}
	}
	if (len > 0)
		return false; // string ending detected before the end of character
	return true;
}

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
			dirsig_hashing);
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
				TMCG_OPENPGP_SIGNATURE_POSITIVE_CERTIFICATION, hashalgo,
				sigtime, keyexptime, dsaflags, issuer, uidsig_hashing); 
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
			hashalgo, sigtime, keyexptime, elgflags, issuer, subsig_hashing);
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
				std::cout << "  -h, --help          print this help" <<
					std::endl;
				std::cout << "  -P, --passphrase    ask user for passphrase" <<
					std::endl;
				std::cout << "  -V, --verbose       increase verbosity" <<
					std::endl;
				return 0; // not continue
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
			if (arg.find("--no-armor") == 0)
			{
				opt_armor = false; // disable ASCII-armored output
				continue;
			}
			if (arg.find("--as=binary") == 0)
			{
				opt_as_binary = true; // choose signature type "binary"
				opt_as_text = false;
				continue;
			}
			if (arg.find("--as=text") == 0)
			{
				opt_as_binary = false; // choose signature type "text"
				opt_as_text = true;
				continue;
			}
			std::cerr << "ERROR: unknown SOP option \"" << arg << "\"" <<
				std::endl;
			return 37;
		}
		else
		{
			// read arguments
			if (subcmd.length() == 0)
				subcmd = arg; // 1st argument is the SOP subcommand
			else
				args.push_back(arg);
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
		// The version string emitted should contain the name of the "sop"
		// implementation, followed by a single space, followed by the version
		// number. [DKG19]
		std::cout << version << std::endl;
	}
	else if (subcmd == "generate-key")
	{
		// Generate a single default OpenPGP certificate with zero or more
		// User IDs. [DKG19]
		if (!generate(args, passphrase))
			ret = -1;
	}
	else if (subcmd == "extract-cert")
	{
		// Extract a Certificate from a Secret Key
		//   Standard Input: "KEY"
		//   Standard Output: "CERTS"
		// Note that the resultant "CERTS" object will only ever contain one
   		// OpenPGP certificate. [DKG19]
		if (!extract(passphrase))
			ret = -1;
	}
	else if (subcmd == "sign")
	{
		// Create a Detached Signature
		//   Standard Input: "DATA"
		//   Standard Output: "SIGNATURE"
		// "--as" defaults to "binary".  If "--as=text" and the input "DATA" is
		// not valid "UTF-8", "sop sign" fails with a return code of 53. [DKG19]
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

