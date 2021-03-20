/*******************************************************************************
   This file is part of Distributed Privacy Guard (DKGPG).

 Copyright (C) 2018, 2019, 2020, 2021  Heiko Stamer <HeikoStamer@gmx.net>

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
#include "dkg-openpgp.hh"
#include "dkg-io.hh"

bool verify_signature
	(const tmcg_openpgp_octets_t &data,
	 const std::string &armored_pubkey,
	 const TMCG_OpenPGP_Signature *signature,
	 const TMCG_OpenPGP_Keyring *ring,
	 const int opt_verbose,
	 const bool opt_weak,
	 const bool opt_broken)
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
	time_t ckeytime = 0, ekeytime = 0, bkeytime = 0;
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
				bkeytime = primary->subkeys[j]->bindingtime;
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
		bkeytime = primary->creationtime; // because no subkey selected
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
	// 1a. signature was made before subkey was bound to primary key
	if (signature->creationtime < bkeytime)
	{
		std::cerr << "ERROR: signature was made before key binding" <<
			std::endl;
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
	// 5. hash algorithm (reject broken hash algorithms)
	if ((signature->hashalgo == TMCG_OPENPGP_HASHALGO_MD5) ||
	    (signature->hashalgo == TMCG_OPENPGP_HASHALGO_SHA1) ||
		(signature->hashalgo == TMCG_OPENPGP_HASHALGO_RMD160))
	{
		std::string hashname;
		CallasDonnerhackeFinneyShawThayerRFC4880::
			AlgorithmHashTextName(signature->hashalgo, hashname);
		if (opt_broken)
		{
			std::cerr << "WARNING: broken hash algorithm " << hashname <<
				" used for signature" << std::endl;
		}
		else
		{
			std::cerr << "ERROR: broken hash algorithm " << hashname <<
				" used for signature" << std::endl;
			delete primary;
			return false;
		}
	}

	// verify signature cryptographically
	bool verify_ok = false;
	if (subkey_selected)
	{
		verify_ok = signature->VerifyData(primary->subkeys[subkey_idx]->key,
			data, opt_verbose);
	}
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

bool encrypt_session_key
	(const TMCG_OpenPGP_Subkey* sub,
	 const tmcg_openpgp_secure_octets_t &seskey,
	 const tmcg_openpgp_octets_t &subkeyid,
	 tmcg_openpgp_octets_t &out)
{
	gcry_error_t ret;
	if ((sub->pkalgo == TMCG_OPENPGP_PKALGO_RSA) ||
	    (sub->pkalgo == TMCG_OPENPGP_PKALGO_RSA_ENCRYPT_ONLY))
	{
		gcry_mpi_t me;
		me = gcry_mpi_new(2048);
		ret = CallasDonnerhackeFinneyShawThayerRFC4880::
			AsymmetricEncryptRSA(seskey, sub->key, me);
		if (ret)
		{
			std::cerr << "ERROR: AsymmetricEncryptRSA() failed (rc = " <<
				gcry_err_code(ret) << ")" << std::endl;
			gcry_mpi_release(me);
			return false;
		}
		CallasDonnerhackeFinneyShawThayerRFC4880::
			PacketPkeskEncode(subkeyid, me, out);
		gcry_mpi_release(me);
	}
	else if (sub->pkalgo == TMCG_OPENPGP_PKALGO_ELGAMAL)
	{	
		// Note that OpenPGP ElGamal encryption in $Z^*_p$ provides only
		// OW-CPA security under the CDH assumption. In order to achieve
		// at least IND-CPA (aka semantic) security under DDH assumption
		// the encoded message $m$ must be an element of the prime-order
		// subgroup $G_q$ generated by $g$ (algebraic structure of tElG).
		// Unfortunately, the probability that this happens is negligible,
		// if the size of prime $q$ is much smaller than the size of $p$.
		// We cannot enforce $m\in G_q$ since $m$ is padded according to
		// OpenPGP (PKCS#1). Thus, one bit of the session key is leaked.
		gcry_mpi_t gk, myk;
		gk = gcry_mpi_new(2048);
		myk = gcry_mpi_new(2048);
		ret = CallasDonnerhackeFinneyShawThayerRFC4880::
			AsymmetricEncryptElgamal(seskey, sub->key, gk, myk);
		if (ret)
		{
			std::cerr << "ERROR: AsymmetricEncryptElgamal() failed" <<
				" (rc = " << gcry_err_code(ret) << ")" << std::endl;
			gcry_mpi_release(gk);
			gcry_mpi_release(myk);
			return false;
		}
		CallasDonnerhackeFinneyShawThayerRFC4880::
			PacketPkeskEncode(subkeyid, gk, myk, out);
		gcry_mpi_release(gk);
		gcry_mpi_release(myk);
	}
	else if (sub->pkalgo == TMCG_OPENPGP_PKALGO_ECDH)
	{
		gcry_mpi_t ecepk;
		size_t rkwlen = 0;
		tmcg_openpgp_byte_t rkw[256];
		ecepk = gcry_mpi_new(1024);
		memset(rkw, 0, sizeof(rkw));
		ret = CallasDonnerhackeFinneyShawThayerRFC4880::
			AsymmetricEncryptECDH(seskey, sub->key, sub->kdf_hashalgo,
				sub->kdf_skalgo, sub->ec_curve, sub->fingerprint, ecepk,
				rkwlen, rkw);
		if (ret)
		{
			std::cerr << "ERROR: AsymmetricEncryptECDH() failed" <<
				" (rc = " << gcry_err_code(ret) << ")" << std::endl;
			gcry_mpi_release(ecepk);
			return false;
		}
		CallasDonnerhackeFinneyShawThayerRFC4880::
			PacketPkeskEncode(subkeyid, ecepk, rkwlen, rkw, out);
		gcry_mpi_release(ecepk);
	}
	else
	{
		std::cerr << "ERROR: public-key algorithm " << (int)sub->pkalgo <<
			" not supported" << std::endl;
		return false;
	}
	return true;
}

bool encrypt_session_key
	(const TMCG_OpenPGP_Pubkey* pub,
	 const tmcg_openpgp_secure_octets_t &seskey,
	 const tmcg_openpgp_octets_t &keyid,
	 tmcg_openpgp_octets_t &out)
{
	bool ret;
	if (pub->pkalgo != TMCG_OPENPGP_PKALGO_RSA)
	{
		return false; // only RSA is an encryption-capable primary key algo
	}
	TMCG_OpenPGP_Subkey *sub = new TMCG_OpenPGP_Subkey(pub->pkalgo,
		pub->creationtime, pub->expirationtime, pub->rsa_n, pub->rsa_e,
		pub->packet);
	ret = encrypt_session_key(sub, seskey, keyid, out);
	delete sub;
	return ret;
}

gcry_error_t encrypt_kek
	(const tmcg_openpgp_octets_t &kek,
	 const tmcg_openpgp_skalgo_t algo,
	 const tmcg_openpgp_secure_octets_t &key,
	 tmcg_openpgp_octets_t &out)
{
	gcry_error_t ret = 0;
	size_t bs = CallasDonnerhackeFinneyShawThayerRFC4880::
		AlgorithmIVLength(algo); // get block size of algorithm
	size_t ks = CallasDonnerhackeFinneyShawThayerRFC4880::
		AlgorithmKeyLength(algo); // get key size of algorithm
	if ((bs == 0) || (ks == 0))
		return gcry_error(GPG_ERR_CIPHER_ALGO); // error: bad algorithm
	size_t buflen = (kek.size() >= key.size()) ? kek.size() : key.size();
	unsigned char *buf = (unsigned char*)gcry_malloc_secure(buflen);
	if (buf == NULL)
		return gcry_error(GPG_ERR_RESOURCE_LIMIT); // cannot alloc secure memory
	gcry_cipher_hd_t hd;
	ret = gcry_cipher_open(&hd, CallasDonnerhackeFinneyShawThayerRFC4880::
		AlgorithmSymGCRY(algo), GCRY_CIPHER_MODE_CFB, GCRY_CIPHER_SECURE);
	if (ret)
	{
		gcry_free(buf);
		return ret;
	}
	for (size_t i = 0; i < key.size(); i++)
		buf[i] = key[i];
	ret = gcry_cipher_setkey(hd, buf, key.size());
	if (ret)
	{
		gcry_free(buf);
		gcry_cipher_close(hd);
		return ret;
	}
	// set "an IV of all zeros" [RFC 4880]
	ret = gcry_cipher_setiv(hd, NULL, 0);
	if (ret)
	{
		gcry_free(buf);
		gcry_cipher_close(hd);
		return ret;
	}
	for (size_t i = 0; i < kek.size(); i++)
		buf[i] = kek[i];
	ret = gcry_cipher_encrypt(hd, buf, kek.size(), NULL, 0);
	if (ret)
	{
		gcry_free(buf);
		gcry_cipher_close(hd);
		return ret;
	}
	for (size_t i = 0; i < kek.size(); i++)
		out.push_back(buf[i]);
	gcry_free(buf);
	gcry_cipher_close(hd);
	return ret;
}

bool decrypt_session_key
	(const gcry_mpi_t p,
	 const gcry_mpi_t g,
	 const gcry_mpi_t y,
	 const gcry_mpi_t gk,
	 const gcry_mpi_t myk,
	 tmcg_openpgp_secure_octets_t &out)
{
	gcry_mpi_t elg_x;
	gcry_sexp_t elgkey;
	size_t erroff;
	// cheat libgcrypt (decryption key shares have been already applied to gk)
	elg_x = gcry_mpi_new(2048);
	gcry_mpi_set_ui(elg_x, 1);
	gcry_error_t ret = gcry_sexp_build(&elgkey, &erroff,
		"(private-key (elg (p %M) (g %M) (y %M) (x %M)))", p, g, y, elg_x);
	gcry_mpi_release(elg_x);
	if (ret)
	{
		std::cerr << "ERROR: processing ElGamal key material failed" <<
			std::endl;
		return false;
	}
	ret = CallasDonnerhackeFinneyShawThayerRFC4880::
		AsymmetricDecryptElgamal(gk, myk, elgkey, out);
	gcry_sexp_release(elgkey);
	if (ret)
	{
		std::cerr << "ERROR: AsymmetricDecryptElgamal() failed" <<
			" with rc = " << gcry_err_code(ret) << std::endl;
		return false;
	}
	return true;
}

bool check_esk
	(const TMCG_OpenPGP_PKESK* esk,
	 const TMCG_OpenPGP_PrivateSubkey* ssb,
	 const int opt_verbose)
{
	if ((esk->pkalgo == TMCG_OPENPGP_PKALGO_ELGAMAL) &&
		(ssb->pkalgo == TMCG_OPENPGP_PKALGO_EXPERIMENTAL9))
	{
		// check whether $0 < g^k < p$.
		if ((gcry_mpi_cmp_ui(esk->gk, 0L) <= 0) ||
			(gcry_mpi_cmp(esk->gk, ssb->pub->elg_p) >= 0))
		{
			if (opt_verbose > 1)
				std::cerr << "ERROR: 0 < g^k < p not satisfied" << std::endl;
			return false;
		}
		// check whether $0 < my^k < p$.
		if ((gcry_mpi_cmp_ui(esk->myk, 0L) <= 0) ||
			(gcry_mpi_cmp(esk->myk, ssb->pub->elg_p) >= 0))
		{
			if (opt_verbose > 1)
				std::cerr << "ERROR: 0 < my^k < p not satisfied" << std::endl;
			return false;
		}
		// check whether $(g^k)^q \equiv 1 \pmod{p}$.
		gcry_mpi_t tmp;
		tmp = gcry_mpi_new(2048);
		gcry_mpi_powm(tmp, esk->gk, ssb->telg_q, ssb->pub->elg_p);
		if (gcry_mpi_cmp_ui(tmp, 1L))
		{
			if (opt_verbose > 1)
			{
				std::cerr << "ERROR: (g^k)^q equiv 1 mod p not satisfied" <<
					std::endl;
			}
			gcry_mpi_release(tmp);
			return false;
		}
		gcry_mpi_release(tmp);
	}
	else if ((esk->pkalgo == TMCG_OPENPGP_PKALGO_ELGAMAL) &&
		(ssb->pkalgo == TMCG_OPENPGP_PKALGO_ELGAMAL))
	{
		// check whether $0 < g^k < p$.
		if ((gcry_mpi_cmp_ui(esk->gk, 0L) <= 0) ||
			(gcry_mpi_cmp(esk->gk, ssb->pub->elg_p) >= 0))
		{
			if (opt_verbose > 1)
				std::cerr << "ERROR: 0 < g^k < p not satisfied" << std::endl;
			return false;
		}
		// check whether $0 < my^k < p$.
		if ((gcry_mpi_cmp_ui(esk->myk, 0L) <= 0) ||
			(gcry_mpi_cmp(esk->myk, ssb->pub->elg_p) >= 0))
		{
			if (opt_verbose > 1)
				std::cerr << "ERROR: 0 < my^k < p not satisfied" << std::endl;
			return false;
		}
	}
	else if ((esk->pkalgo == TMCG_OPENPGP_PKALGO_RSA) &&
		(ssb->pkalgo == TMCG_OPENPGP_PKALGO_RSA))
	{
		// check whether $0 < m^e < n$.
		if ((gcry_mpi_cmp_ui(esk->me, 0L) <= 0) ||
			(gcry_mpi_cmp(esk->me, ssb->pub->rsa_n) >= 0))
		{
			if (opt_verbose > 1)
				std::cerr << "ERROR: 0 < m^e < n not satisfied" << std::endl;
			return false;
		}
	}
	return true;
}

gcry_error_t decrypt_kek
	(const tmcg_openpgp_octets_t &kek,
	 const tmcg_openpgp_skalgo_t algo,
	 const tmcg_openpgp_secure_octets_t &key,
	 tmcg_openpgp_secure_octets_t &out)
{
	gcry_error_t ret = 0;
	size_t bs = CallasDonnerhackeFinneyShawThayerRFC4880::
		AlgorithmIVLength(algo); // get block size of algorithm
	size_t ks = CallasDonnerhackeFinneyShawThayerRFC4880::
		AlgorithmKeyLength(algo); // get key size of algorithm
	if ((bs == 0) || (ks == 0))
		return gcry_error(GPG_ERR_CIPHER_ALGO); // error: bad algorithm
	size_t buflen = (kek.size() >= key.size()) ? kek.size() : key.size();
	unsigned char *buf = (unsigned char*)gcry_malloc_secure(buflen);
	if (buf == NULL)
		return gcry_error(GPG_ERR_RESOURCE_LIMIT); // cannot alloc secure memory
	gcry_cipher_hd_t hd;
	ret = gcry_cipher_open(&hd, CallasDonnerhackeFinneyShawThayerRFC4880::
		AlgorithmSymGCRY(algo), GCRY_CIPHER_MODE_CFB, GCRY_CIPHER_SECURE);
	if (ret)
	{
		gcry_free(buf);
		return ret;
	}
	for (size_t i = 0; i < key.size(); i++)
		buf[i] = key[i];
	ret = gcry_cipher_setkey(hd, buf, key.size());
	if (ret)
	{
		gcry_free(buf);
		gcry_cipher_close(hd);
		return ret;
	}
	// set "an IV of all zeros" [RFC 4880]
	ret = gcry_cipher_setiv(hd, NULL, 0);
	if (ret)
	{
		gcry_free(buf);
		gcry_cipher_close(hd);
		return ret;
	}
	for (size_t i = 0; i < kek.size(); i++)
		buf[i] = kek[i];
	ret = gcry_cipher_decrypt(hd, buf, kek.size(), NULL, 0);
	if (ret)
	{
		gcry_free(buf);
		gcry_cipher_close(hd);
		return ret;
	}
	for (size_t i = 0; i < kek.size(); i++)
		out.push_back(buf[i]);
	gcry_free(buf);
	gcry_cipher_close(hd);
	return ret;
}

bool decrypt_session_key
	(const TMCG_OpenPGP_Message* msg,
	 tmcg_openpgp_secure_octets_t &seskey,
	 const int opt_verbose,
	 const tmcg_openpgp_secure_string_t &p)
{
	for (size_t i = 0; i < msg->SKESKs.size(); i++)
	{
		const TMCG_OpenPGP_SKESK *esk = msg->SKESKs[i];
		tmcg_openpgp_secure_octets_t kek;
		size_t klen = CallasDonnerhackeFinneyShawThayerRFC4880::
			AlgorithmKeyLength(esk->skalgo);
		if (opt_verbose > 2)
		{
			std::cerr << "INFO: s2k_salt = " << std::hex;
			for (size_t j = 0; j < (esk->s2k_salt).size(); j++)
				std::cerr << (int)esk->s2k_salt[j] << " ";
			std::cerr << std::dec << std::endl;
		}
		switch (esk->s2k_type)
		{
			case TMCG_OPENPGP_STRINGTOKEY_SIMPLE:
				if (opt_verbose)
				{
					std::cerr << "WARNING: S2K specifier not" <<
						" supported; skip SKESK" << std::endl;
				}
				break;
			case TMCG_OPENPGP_STRINGTOKEY_SALTED:
				CallasDonnerhackeFinneyShawThayerRFC4880::
					S2KCompute(esk->s2k_hashalgo, klen, p,
						esk->s2k_salt, false, esk->s2k_count, kek);
				break;
			case TMCG_OPENPGP_STRINGTOKEY_ITERATED:
				CallasDonnerhackeFinneyShawThayerRFC4880::
					S2KCompute(esk->s2k_hashalgo, klen, p,
						esk->s2k_salt, true, esk->s2k_count, kek);
				break;
			default:
				if (opt_verbose)
				{
					std::cerr << "WARNING: S2K specifier not" <<
						" supported; skip SKESK" << std::endl;
				}
				break;
		}
		if (opt_verbose > 2)
		{
			std::cerr << "INFO: kek.size() = " << kek.size() << std::endl;
			std::cerr << "INFO: kek = " << std::hex;
			for (size_t j = 0; j < kek.size(); j++)
				std::cerr << (int)kek[j] << " ";
			std::cerr << std::dec << std::endl;
		}
		seskey.clear();
		if (esk->encrypted_key.size() > 0)
		{
			gcry_error_t ret = 0;
			if (esk->aeadalgo == 0)
			{
				ret = decrypt_kek(esk->encrypted_key, esk->skalgo, kek, seskey);
			}
			else
			{
				tmcg_openpgp_octets_t decrypted_key;
				tmcg_openpgp_octets_t ad; // additional data
				ad.push_back(0xC3); // packet tag in new format
				ad.push_back(esk->version); // packet version number
				ad.push_back(esk->skalgo); // cipher algorithm octet
				ad.push_back(esk->aeadalgo); // AEAD algorithm octet
				ret = CallasDonnerhackeFinneyShawThayerRFC4880::
					SymmetricDecryptAEAD(esk->encrypted_key, kek,
						esk->skalgo, esk->aeadalgo, 0, esk->iv, ad,
						opt_verbose, decrypted_key);
				for (size_t j = 0; j < decrypted_key.size(); j++)
					seskey.push_back(decrypted_key[j]);
			}
			if (ret)
			{
				if (opt_verbose)
				{
					std::cerr << "WARNING: SymmetricDecrypt[AEAD]() failed" <<
						" with rc = " << gcry_err_code(ret) <<
						" str = " << gcry_strerror(ret) << std::endl;
				}
				return false;
			}
		}
		else
		{
			seskey.push_back(esk->skalgo);
			for (size_t j = 0; j < kek.size(); j++)
				seskey.push_back(kek[j]);
		}
		// quick check, whether decryption of session key was successful
		tmcg_openpgp_octets_t tmpmsg;				
		if (msg->Decrypt(seskey, 0, tmpmsg))
			return true;
	}
	return false;
}

bool decrypt_session_key
	(const TMCG_OpenPGP_Message* msg,
	 tmcg_openpgp_secure_octets_t &seskey,
	 const int opt_verbose,
	 const std::vector<std::string> &opt_with_password)
{
	if (msg->SKESKs.size() == 0)
		return false;
	if (opt_verbose > 1)
	{
		std::cerr << "INFO: every PKESK decryption failed;" <<
			" now try each SKESK" << std::endl;
	}
	for (size_t k = 0; k < opt_with_password.size(); k++)
	{
		tmcg_openpgp_secure_string_t p;
		for (size_t i = 0; i < opt_with_password[k].length(); i++)
			p += opt_with_password[k][i];
		if (decrypt_session_key(msg, seskey, opt_verbose, p))
			return true;
	}
	return false;
}

bool decrypt_session_key
	(const TMCG_OpenPGP_Message* msg,
	 tmcg_openpgp_secure_octets_t &seskey,
	 const int opt_verbose,
	 const bool opt_E)
{
	if (msg->SKESKs.size() == 0)
		return false;
	if (opt_verbose > 1)
	{
		std::cerr << "INFO: every PKESK decryption failed;" <<
			" now try each SKESK" << std::endl;
	}
	tmcg_openpgp_secure_string_t p;
	if (!get_passphrase("Enter passphrase for this message", opt_E, p))
	{
		std::cerr << "ERROR: cannot read passphrase" << std::endl;
		return false;
	}
	if (decrypt_session_key(msg, seskey, opt_verbose, p))
			return true;
	return false;
}

bool decompress_libz
	(const TMCG_OpenPGP_Message* msg,
	 tmcg_openpgp_octets_t &infmsg,
	 const int opt_verbose)
{
	int rc = 0;
	z_stream zs;
	unsigned char zin[4096];
	unsigned char zout[4096];
	zs.zalloc = Z_NULL;
	zs.zfree = Z_NULL;
	zs.opaque = Z_NULL;
	zs.avail_in = 0;
	zs.next_in = Z_NULL;
	static const char* myZlibVersion = ZLIB_VERSION;
	if (zlibVersion()[0] != myZlibVersion[0])
	{
		if (opt_verbose > 1)
			std::cerr << "ERROR: incompatible zlib versions found" << std::endl;
		return false;
	}
	else if (std::strcmp(zlibVersion(), ZLIB_VERSION) != 0)
	{
		if (opt_verbose > 1)
			std::cerr << "WARNING: different zlib versions found" << std::endl;
	}
	switch (msg->compalgo)
	{
		case TMCG_OPENPGP_COMPALGO_ZIP:
			rc = inflateInit2(&zs, -15);
			break;
		case TMCG_OPENPGP_COMPALGO_ZLIB:
			rc = inflateInit(&zs);
			break;
		default:
			if (opt_verbose)
			{
				std::cerr << "ERROR: compression algorithm " <<
					(int)msg->compalgo << " is not supported" << std::endl;
			}
			return false;
			break;
	}
	if (rc != Z_OK)
	{
		if (opt_verbose)
		{
			std::cerr << "ZLIB ERROR: " << (int)rc;
			if (zs.msg != NULL)
				std::cerr << " " << zs.msg;
			std::cerr << std::endl;
		}
		return false;
	}
	size_t cnt = 0;
	memset(zin, 0, sizeof(zin));
	do
	{
		if (zs.avail_in == 0)
		{
			size_t zlen = 0;
			for (size_t i = 0; i < sizeof(zin); i++)
			{
				if (cnt >= (msg->compressed_data).size())
					break;
				zin[i] = (msg->compressed_data)[cnt];
				zlen++, cnt++;
			}
			zs.avail_in = zlen;
			zs.next_in = zin;
		}
		memset(zout, 0, sizeof(zout));
		zs.avail_out = sizeof(zout);
		zs.next_out = zout;
		rc = inflate(&zs, Z_SYNC_FLUSH);
		if ((rc == Z_NEED_DICT) || (rc == Z_DATA_ERROR) ||
			(rc == Z_MEM_ERROR) || (rc == Z_STREAM_ERROR))
		{
			if (opt_verbose)
			{
				std::cerr << "ZLIB ERROR: " << rc;
				if (zs.msg != NULL)
					std::cerr << " " << zs.msg;
				std::cerr << std::endl;
			}
			(void)inflateEnd(&zs);
			return false;
		}
		for (size_t i = 0; i < (sizeof(zout) - zs.avail_out); i++)
			infmsg.push_back(zout[i]);
	}
	while ((rc != Z_STREAM_END) && (rc != Z_BUF_ERROR));
	(void)inflateEnd(&zs);
	return (rc == Z_STREAM_END);
}

#ifdef LIBBZ
bool decompress_libbz
	(const TMCG_OpenPGP_Message* msg,
	 tmcg_openpgp_octets_t &infmsg,
	 const int opt_verbose)
{
	int rc = 0;
	bz_stream zs;
	char zin[4096];
	char zout[4096];
	zs.bzalloc = NULL;
	zs.bzfree = NULL;
	zs.opaque = NULL;
	zs.avail_in = 0;
	zs.next_in = NULL;
	rc = BZ2_bzDecompressInit(&zs, 0, 0);
	if (rc != BZ_OK)
	{
		if (opt_verbose)
			std::cerr << "BZLIB ERROR: " << (int)rc << std::endl;
		return false;
	}
	size_t cnt = 0;
	memset(zin, 0, sizeof(zin));
	do
	{
		if (zs.avail_in == 0)
		{
			size_t zlen = 0;
			for (size_t i = 0; i < sizeof(zin); i++)
			{
				if (cnt >= (msg->compressed_data).size())
					break;
				zin[i] = (msg->compressed_data)[cnt];
				zlen++, cnt++;
			}
			zs.avail_in = zlen;
			zs.next_in = zin;
		}
		memset(zout, 0, sizeof(zout));
		zs.avail_out = sizeof(zout);
		zs.next_out = zout;
		rc = BZ2_bzDecompress(&zs);
		if ((rc == BZ_DATA_ERROR) || (rc == BZ_DATA_ERROR_MAGIC) ||
			(rc == BZ_MEM_ERROR))
		{
			if (opt_verbose)
				std::cerr << "BZLIB ERROR: " << rc << std::endl;
			BZ2_bzDecompressEnd(&zs);
			return false;
		}
		for (size_t i = 0; i < (sizeof(zout) - zs.avail_out); i++)
			infmsg.push_back(zout[i]);
	}
	while ((rc != BZ_STREAM_END) && (rc != BZ_PARAM_ERROR));
	BZ2_bzDecompressEnd(&zs);
	return (rc == BZ_STREAM_END);
}
#endif

