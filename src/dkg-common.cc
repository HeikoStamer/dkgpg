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

extern std::vector<std::string>			peers;

extern std::string						passphrase, userid;
extern tmcg_openpgp_octets_t			keyid, subkeyid;
extern tmcg_openpgp_octets_t			pub, sub, sec, ssb, uid;
extern tmcg_openpgp_octets_t			uidsig, subsig;
extern std::map<size_t, size_t>			idx2dkg, dkg2idx;
extern mpz_t							dss_p, dss_q, dss_g, dss_h, dss_y;
extern mpz_t							dss_x_i, dss_xprime_i; // secret key
extern size_t							dss_n, dss_t, dss_i;
extern std::vector<size_t>				dss_qual, dss_x_rvss_qual;
extern tmcg_mpz_matrix_t				dss_c_ik;
extern mpz_t							dkg_p, dkg_q, dkg_g, dkg_h, dkg_y;
extern mpz_t							dkg_x_i, dkg_xprime_i; // secret key
extern size_t							dkg_n, dkg_t, dkg_i;
extern std::vector<size_t>				dkg_qual;
extern tmcg_mpz_vector_t				dkg_v_i;
extern tmcg_mpz_matrix_t				dkg_c_ik;
extern gcry_mpi_t 						dsa_p, dsa_q, dsa_g, dsa_y, dsa_x;
extern gcry_mpi_t						elg_p, elg_q, elg_g, elg_y, elg_x;
extern gcry_mpi_t						dsa_r, dsa_s, elg_r, elg_s;
extern gcry_mpi_t						rsa_n, rsa_e, rsa_md;
extern gcry_mpi_t						gk, myk, sig_r, sig_s;
extern gcry_mpi_t						revdsa_r, revdsa_s, revelg_r, revelg_s;
extern gcry_mpi_t						revrsa_md;

extern int								opt_verbose;
extern bool								libgcrypt_secmem;

void init_mpis
	()
{
	mpz_init(dss_p);
	mpz_init(dss_q);
	mpz_init(dss_g);
	mpz_init(dss_h);
	mpz_init(dss_x_i);
	mpz_init(dss_xprime_i);
	mpz_init(dss_y);
	dsa_p = gcry_mpi_new(2048);
	dsa_q = gcry_mpi_new(2048);
	dsa_g = gcry_mpi_new(2048);
	dsa_y = gcry_mpi_new(2048);
	if (libgcrypt_secmem)
		dsa_x = gcry_mpi_snew(2048);
	else
		dsa_x = gcry_mpi_new(2048);
	mpz_init(dkg_p);
	mpz_init(dkg_q);
	mpz_init(dkg_g);
	mpz_init(dkg_h);
	mpz_init(dkg_x_i);
	mpz_init(dkg_xprime_i);
	mpz_init(dkg_y);
	elg_p = gcry_mpi_new(2048);
	elg_q = gcry_mpi_new(2048);
	elg_g = gcry_mpi_new(2048);
	elg_y = gcry_mpi_new(2048);
	if (libgcrypt_secmem)
		elg_x = gcry_mpi_snew(2048);
	else
		elg_x = gcry_mpi_new(2048);
	dsa_r = gcry_mpi_new(2048);
	dsa_s = gcry_mpi_new(2048);
	elg_r = gcry_mpi_new(2048);
	elg_s = gcry_mpi_new(2048);
	rsa_n = gcry_mpi_new(2048);
	rsa_e = gcry_mpi_new(2048);
	rsa_md = gcry_mpi_new(2048);
	gk = gcry_mpi_new(2048);
	myk = gcry_mpi_new(2048);
	sig_r = gcry_mpi_new(2048);
	sig_s = gcry_mpi_new(2048);
	revdsa_r = gcry_mpi_new(2048);
	revdsa_s = gcry_mpi_new(2048);
	revelg_r = gcry_mpi_new(2048);
	revelg_s = gcry_mpi_new(2048);
	revrsa_md = gcry_mpi_new(2048);
}

void cleanup_containers
	(tmcg_mpi_vector_t &qual, tmcg_mpi_vector_t &v_i, tmcg_mpi_matrix_t &c_ik)
{
	for (size_t i = 0; i < qual.size(); i++)
		gcry_mpi_release(qual[i]);
	qual.clear();
	for (size_t i = 0; i < v_i.size(); i++)
		gcry_mpi_release(v_i[i]);
	v_i.clear();
	for (size_t i = 0; i < c_ik.size(); i++)
	{
		for (size_t k = 0; k < c_ik[i].size(); k++)
			gcry_mpi_release(c_ik[i][k]);
		c_ik[i].clear();
	}
	c_ik.clear();
}

void cleanup_containers
	(tmcg_mpi_vector_t &qual, tmcg_mpi_vector_t &v_i,
	 tmcg_mpi_vector_t &x_rvss_qual, tmcg_mpi_matrix_t &c_ik)
{
	cleanup_containers(qual, v_i, c_ik);
	for (size_t i = 0; i < x_rvss_qual.size(); i++)
		gcry_mpi_release(x_rvss_qual[i]);
	x_rvss_qual.clear();
}

bool parse_message
	(const std::string &in,
	 tmcg_openpgp_octets_t &enc_out, bool &have_seipd_out)
{
	// decode ASCII armor and parse encrypted message
	tmcg_openpgp_armor_t atype = TMCG_OPENPGP_ARMOR_UNKNOWN;
	tmcg_openpgp_octets_t pkts;
	atype = CallasDonnerhackeFinneyShawThayerRFC4880::ArmorDecode(in, pkts);
	if (opt_verbose)
		std::cerr << "INFO: ArmorDecode() = " << (int)atype << " with " <<
			pkts.size() << " bytes" << std::endl;
	if (atype != TMCG_OPENPGP_ARMOR_MESSAGE)
	{
		std::cerr << "ERROR: wrong type of ASCII Armor found (type = " <<
			(int)atype << ")" << std::endl;
		return false;
	}
	bool have_pkesk = false, have_sed = false;
	tmcg_openpgp_byte_t ptag = 0xFF;
	size_t pnum = 0;
	while (pkts.size() && ptag)
	{
		tmcg_openpgp_octets_t pkesk_keyid;
		tmcg_openpgp_packet_ctx_t ctx;
		tmcg_openpgp_octets_t current_packet;
		ptag = CallasDonnerhackeFinneyShawThayerRFC4880::
			PacketDecode(pkts, opt_verbose, ctx, current_packet);
		++pnum;
		if (opt_verbose)
			std::cerr << "INFO: PacketDecode() = " << (int)ptag <<
				" version = " << (int)ctx.version << std::endl;
		if (ptag == 0x00)
		{
			std::cerr << "ERROR: parsing OpenPGP packets failed at #" <<
				pnum << " and position " << pkts.size() << std::endl;
			CallasDonnerhackeFinneyShawThayerRFC4880::PacketContextRelease(ctx);
			return false; // parsing error detected
		}
		else if (ptag == 0xFE)
		{
			std::cerr << "WARNING: unrecognized OpenPGP packet found at #" <<
				pnum << " and position " << pkts.size() << std::endl;
			CallasDonnerhackeFinneyShawThayerRFC4880::PacketContextRelease(ctx);
			continue; // ignore packet
		}
		switch (ptag)
		{
			case 1: // Public-Key Encrypted Session Key
				if (opt_verbose)
					std::cerr << "INFO: pkalgo = " << (int)ctx.pkalgo <<
						std::endl;
				if (ctx.pkalgo != TMCG_OPENPGP_PKALGO_ELGAMAL)
				{
					std::cerr << "WARNING: public-key algorithm not sup" <<
						"ported; packet #" << pnum << " ignored" << std::endl;
					break;
				}
				if (opt_verbose)
					std::cerr << "INFO: keyid = " << std::hex;
				pkesk_keyid.clear();
				for (size_t i = 0; i < sizeof(ctx.keyid); i++)
				{
					if (opt_verbose)
						std::cerr << (int)ctx.keyid[i] << " ";
					pkesk_keyid.push_back(ctx.keyid[i]);
				}
				if (opt_verbose)
					std::cerr << std::dec << std::endl;
				if (CallasDonnerhackeFinneyShawThayerRFC4880::
					OctetsCompareZero(pkesk_keyid))
				{
					std::cerr << "WARNING: PKESK wildcard keyid found; " <<
						"try to decrypt anyway" << std::endl;
				}
				else if (!CallasDonnerhackeFinneyShawThayerRFC4880::
					OctetsCompare(pkesk_keyid, subkeyid))
				{
					if (opt_verbose)
						std::cerr << "WARNING: PKESK keyid does not match " <<
							"subkey ID" << std::endl;
					break;
				}
				if (have_pkesk)
					std::cerr << "WARNING: matching PKESK packet already " <<
						"found; g^k and my^k overwritten" << std::endl;
				gcry_mpi_set(gk, ctx.gk);
				gcry_mpi_set(myk, ctx.myk);
				have_pkesk = true;
				break;
			case 9: // Symmetrically Encrypted Data
				if (!have_pkesk)
					std::cerr << "WARNING: no preceding PKESK packet found; " <<
						"decryption may fail" << std::endl;
				if ((!have_sed) && (!have_seipd_out))
				{
					have_sed = true;
					enc_out.clear();
					for (size_t i = 0; i < ctx.encdatalen; i++)
						enc_out.push_back(ctx.encdata[i]);
				}
				else
				{
					std::cerr << "ERROR: duplicate SED/SEIPD packet found" <<
						std::endl;
					CallasDonnerhackeFinneyShawThayerRFC4880::
						PacketContextRelease(ctx);
					return false;
				}
				break;
			case 18: // Symmetrically Encrypted Integrity Protected Data
				if (!have_pkesk)
					std::cerr << "WARNING: no preceding PKESK packet found; " <<
						"decryption may fail" << std::endl;
				if ((!have_sed) && (!have_seipd_out))
				{
					have_seipd_out = true;
					enc_out.clear();
					for (size_t i = 0; i < ctx.encdatalen; i++)
						enc_out.push_back(ctx.encdata[i]);
				}
				else
				{
					std::cerr << "ERROR: duplicate SED/SEIPD packet found" <<
						std::endl;
					CallasDonnerhackeFinneyShawThayerRFC4880::
						PacketContextRelease(ctx);
					return false;
				}
				break;
			default:
				std::cerr << "ERROR: unexpected OpenPGP packet " << (int)ptag <<
					" found at #" << pnum << std::endl;
				CallasDonnerhackeFinneyShawThayerRFC4880::
					PacketContextRelease(ctx);
				return false;
		}
		// cleanup allocated buffers and mpi's
		CallasDonnerhackeFinneyShawThayerRFC4880::PacketContextRelease(ctx);
	}
	if (!have_pkesk)
	{
		std::cerr << "ERROR: no public-key encrypted session key found" <<
			std::endl;
		return false;
	}
	if (!have_sed && !have_seipd_out)
	{
		std::cerr << "ERROR: no symmetrically encrypted (and integrity" <<
			" protected) data found" << std::endl;
		return false;
	}
	if (have_sed && have_seipd_out)
	{
		std::cerr << "ERROR: multiple types of symmetrically encrypted data" <<
			" found" << std::endl;
		return false;
	}
	// check whether $0 < g^k < p$.
	if ((gcry_mpi_cmp_ui(gk, 0L) <= 0) || (gcry_mpi_cmp(gk, elg_p) >= 0))
	{
		std::cerr << "ERROR: 0 < g^k < p not satisfied" << std::endl;
		return false;
	}
	// check whether $0 < my^k < p$.
	if ((gcry_mpi_cmp_ui(myk, 0L) <= 0) || (gcry_mpi_cmp(myk, elg_p) >= 0))
	{
		std::cerr << "ERROR: 0 < my^k < p not satisfied" << std::endl;
		return false;
	}
	// check whether $(g^k)^q \equiv 1 \pmod{p}$.
	gcry_mpi_t tmp;
	tmp = gcry_mpi_new(2048);
	gcry_mpi_powm(tmp, gk, elg_q, elg_p);
	if (gcry_mpi_cmp_ui(tmp, 1L))
	{
		std::cerr << "ERROR: (g^k)^q equiv 1 mod p not satisfied" << std::endl;
		gcry_mpi_release(tmp);
		return false;
	}
	gcry_mpi_release(tmp);
	return true;
}

bool decrypt_message
	(const bool have_seipd, const tmcg_openpgp_octets_t &in,
	 tmcg_openpgp_octets_t &key, tmcg_openpgp_octets_t &out)
{
	// decrypt the given message
	tmcg_openpgp_skalgo_t symalgo = TMCG_OPENPGP_SKALGO_PLAINTEXT;
	if (opt_verbose)
		std::cerr << "INFO: symmetric decryption of message ..." << std::endl;
	if (key.size() > 0)
	{
		symalgo = (tmcg_openpgp_skalgo_t)key[0];
		if (opt_verbose)
			std::cerr << "INFO: symalgo = " << (int)symalgo << std::endl;
	}
	else
	{
		std::cerr << "ERROR: no session key provided" << std::endl;
		return false;
	}
	gcry_error_t ret;
	tmcg_openpgp_octets_t prefix, pkts;
	if (have_seipd)
		ret = CallasDonnerhackeFinneyShawThayerRFC4880::
			SymmetricDecrypt(in, key, prefix, false, symalgo, pkts);
	else
	{
		std::cerr << "ERROR: encrypted message was not integrity" <<
			" protected" << std::endl;
		return false;
	}
	if (ret)
	{
		std::cerr << "ERROR: SymmetricDecrypt() failed" << std::endl;
		return false;
	}
	// parse the content of decrypted message
	tmcg_openpgp_packet_ctx_t ctx;
	bool have_lit = false, have_mdc = false;
	tmcg_openpgp_octets_t lit, mdc_hash;
	tmcg_openpgp_byte_t ptag = 0xFF;
	size_t pnum = 0, mdc_len = sizeof(ctx.mdc_hash) + 2;
	if (pkts.size() > mdc_len)
		lit.insert(lit.end(), pkts.begin(), pkts.end() - mdc_len); // literal
	while (pkts.size() && ptag)
	{
		tmcg_openpgp_octets_t current_packet;
		ptag = CallasDonnerhackeFinneyShawThayerRFC4880::
			PacketDecode(pkts, opt_verbose, ctx, current_packet);
		++pnum;
		if (opt_verbose)
			std::cerr << "INFO: PacketDecode() = " << (int)ptag <<
				" version = " << (int)ctx.version << std::endl;
		if (ptag == 0x00)
		{
			std::cerr << "ERROR: parsing OpenPGP packets failed at #" <<
				pnum << " and position " << pkts.size() << std::endl;
			CallasDonnerhackeFinneyShawThayerRFC4880::PacketContextRelease(ctx);
			return false; // parsing error detected
		}
		else if ((ptag == 0xFE) || (ptag == 0xFA) || (ptag == 0xFB) ||
			(ptag == 0xFC))
		{
			std::cerr << "WARNING: unrecognized OpenPGP packet found at #" <<
				pnum << " and position " << pkts.size() << std::endl;
			CallasDonnerhackeFinneyShawThayerRFC4880::PacketContextRelease(ctx);
			continue; // ignore packet
		}
		switch (ptag)
		{
			case 2: // Signature
				std::cerr << "WARNING: signature OpenPGP packet found;" <<
					" not supported and ignored" << std::endl;
				break;
			case 4: // One-Pass Signature
				std::cerr << "WARNING: one-pass signature OpenPGP packet" <<
					" found; not supported and ignored" << std::endl;
				break;
			case 8: // Compressed Data
				std::cerr << "WARNING: compressed OpenPGP packet found;" <<
					" not supported and ignored" << std::endl;
				break;
			case 11: // Literal Data
				if (!have_lit)
				{
					have_lit = true;
					out.clear();
					for (size_t i = 0; i < ctx.datalen; i++)
						out.push_back(ctx.data[i]);
				}
				else
				{
					std::cerr << "ERROR: OpenPGP message contains more than" <<
						" one literal data packet" << std::endl;
					CallasDonnerhackeFinneyShawThayerRFC4880::
						PacketContextRelease(ctx);
					return false;
				}
				break;
			case 19: // Modification Detection Code
				have_mdc = true;
				mdc_hash.clear();
				for (size_t i = 0; i < sizeof(ctx.mdc_hash); i++)
					mdc_hash.push_back(ctx.mdc_hash[i]);
				break;
			default:
				std::cerr << "ERROR: unexpected OpenPGP packet " << (int)ptag <<
					" found at #" << pnum << std::endl;
				CallasDonnerhackeFinneyShawThayerRFC4880::
					PacketContextRelease(ctx);
				return false;
		}
		// cleanup allocated buffers and mpi's
		CallasDonnerhackeFinneyShawThayerRFC4880::PacketContextRelease(ctx);
	}
	if (!have_lit)
	{
		std::cerr << "ERROR: no literal data packet found" << std::endl;
		return false;
	}
	if (have_seipd && !have_mdc)
	{
		std::cerr << "ERROR: no modification detection code found" << std::endl;
		return false;
	}
	if (have_mdc)
	{
		tmcg_openpgp_octets_t mdc_hashing, hash;
		// "it includes the prefix data described above" [RFC4880]
		mdc_hashing.insert(mdc_hashing.end(), prefix.begin(), prefix.end());
		// "it includes all of the plaintext" [RFC4880]
		mdc_hashing.insert(mdc_hashing.end(), lit.begin(), lit.end());
		// "and the also includes two octets of values 0xD3, 0x14" [RFC4880]
		mdc_hashing.push_back(0xD3);
		mdc_hashing.push_back(0x14);
		// "passed through the SHA-1 hash function" [RFC4880]
		CallasDonnerhackeFinneyShawThayerRFC4880::
			HashCompute(TMCG_OPENPGP_HASHALGO_SHA1, mdc_hashing, hash);
		if (!CallasDonnerhackeFinneyShawThayerRFC4880::
			OctetsCompare(mdc_hash, hash))
		{
			std::cerr << "ERROR: MDC hash does not match (security issue)" <<
				std::endl;
			return false;
		}
	}
	return true;
}

bool parse_private_key
	(const std::string &in, time_t &keycreationtime_out,
	 time_t &keyexpirationtime_out, std::vector<std::string> &capl_out)
{
	// decode ASCII Armor
	tmcg_openpgp_octets_t pkts;
	tmcg_openpgp_armor_t atype = CallasDonnerhackeFinneyShawThayerRFC4880::
		ArmorDecode(in, pkts);
	if (opt_verbose)
		std::cerr << "INFO: ArmorDecode() = " << (int)atype << " with " <<
			pkts.size() << " bytes" << std::endl;
	if (atype != TMCG_OPENPGP_ARMOR_PRIVATE_KEY_BLOCK)
	{
		std::cerr << "ERROR: wrong type of ASCII Armor found" << std::endl;
		return false;
	}
	// parse the private key according to OpenPGP
	bool secdsa = false, sigdsa = false, ssbelg = false, sigelg = false;
	tmcg_openpgp_byte_t ptag = 0xFF;
	tmcg_openpgp_pkalgo_t dsa_pkalgo = TMCG_OPENPGP_PKALGO_DSA;
	tmcg_openpgp_pkalgo_t elg_pkalgo = TMCG_OPENPGP_PKALGO_ELGAMAL;
	tmcg_openpgp_hashalgo_t dsa_hashalgo = TMCG_OPENPGP_HASHALGO_UNKNOWN;
	tmcg_openpgp_hashalgo_t elg_hashalgo = TMCG_OPENPGP_HASHALGO_UNKNOWN;
	tmcg_openpgp_signature_t dsa_sigtype, elg_sigtype;
	tmcg_openpgp_byte_t dsa_keyflags[32], elg_keyflags[32];
	tmcg_openpgp_byte_t dsa_psa[32], dsa_pha[32], dsa_pca[32];
	tmcg_openpgp_byte_t elg_psa[32], elg_pha[32], elg_pca[32];
	tmcg_openpgp_byte_t *key, *iv;
	tmcg_openpgp_octets_t seskey, salt, mpis, hash_input, hash;
	tmcg_openpgp_octets_t pub_hashing, sub_hashing, issuer, dsa_hspd, elg_hspd;
	gcry_cipher_hd_t hd;
	gcry_error_t ret;
	size_t erroff, keylen, ivlen, chksum, mlen, chksum2;
	int algo;
	tmcg_openpgp_packet_ctx_t ctx;
	tmcg_mpi_vector_t qual, v_i, x_rvss_qual;
	std::vector<std::string> capl;
	tmcg_mpi_matrix_t c_ik;
	while (pkts.size() && ptag)
	{
		tmcg_openpgp_octets_t current_packet;
		ptag = CallasDonnerhackeFinneyShawThayerRFC4880::
			PacketDecode(pkts, opt_verbose, ctx, current_packet, qual,
				x_rvss_qual, capl, v_i, c_ik);
		if (opt_verbose && ptag)
			std::cerr << "INFO: PacketDecode(pkts.size = " << pkts.size() <<
				") = " << (int)ptag;
		if (!ptag)
		{
			std::cerr << std::endl << "ERROR: parsing OpenPGP packets failed" <<
				" at position " << pkts.size() << std::endl;
			CallasDonnerhackeFinneyShawThayerRFC4880::PacketContextRelease(ctx);
			cleanup_containers(qual, v_i, x_rvss_qual, c_ik);
			return false; // error detected
		}
		if (opt_verbose)
			std::cerr << " tag = " << (int)ptag << " version = " <<
				(int)ctx.version << std::endl;
		switch (ptag)
		{
			case 2: // Signature Packet
				issuer.clear();
				if (opt_verbose)
					std::cerr << "INFO: issuer = " << std::hex;
				for (size_t i = 0; i < sizeof(ctx.issuer); i++)
				{
					if (opt_verbose)
						std::cerr << (int)ctx.issuer[i] << " ";
					issuer.push_back(ctx.issuer[i]);
				}
				if (opt_verbose)
					std::cerr << std::dec << std::endl;
				if (secdsa && !ssbelg &&
					((ctx.type == TMCG_OPENPGP_SIGNATURE_GENERIC_CERTIFICATION) ||
					 (ctx.type == TMCG_OPENPGP_SIGNATURE_PERSONA_CERTIFICATION) ||
					 (ctx.type == TMCG_OPENPGP_SIGNATURE_CASUAL_CERTIFICATION) ||
					 (ctx.type == TMCG_OPENPGP_SIGNATURE_POSITIVE_CERTIFICATION)) &&
					CallasDonnerhackeFinneyShawThayerRFC4880::OctetsCompare(keyid, issuer))
				{
					if (opt_verbose)
					{
						std::cerr << std::hex;
						std::cerr << "INFO: sig type = 0x";
						std::cerr << (int)ctx.type;
						std::cerr << std::dec;
						std::cerr << " pkalgo = ";
						std::cerr << (int)ctx.pkalgo;
						std::cerr << " hashalgo = ";
						std::cerr << (int)ctx.hashalgo;
						std::cerr << std::endl;
					}
					if (sigdsa)
						std::cerr << "WARNING: more than one self-signatures" <<
						"; using last signature to check UID" << std::endl;
					dsa_sigtype = ctx.type;
					dsa_pkalgo = ctx.pkalgo;
					dsa_hashalgo = ctx.hashalgo;
					keyexpirationtime_out = ctx.keyexpirationtime;
					for (size_t i = 0; i < sizeof(dsa_keyflags); i++)
						dsa_keyflags[i] = ctx.keyflags[i];
					for (size_t i = 0; i < sizeof(dsa_psa); i++)
						dsa_psa[i] = ctx.psa[i];
					for (size_t i = 0; i < sizeof(dsa_pha); i++)
						dsa_pha[i] = ctx.pha[i];
					for (size_t i = 0; i < sizeof(dsa_pca); i++)
						dsa_pca[i] = ctx.pca[i];
					dsa_hspd.clear();
					for (size_t i = 0; i < ctx.hspdlen; i++)
						dsa_hspd.push_back(ctx.hspd[i]);
					if (dsa_pkalgo != TMCG_OPENPGP_PKALGO_DSA)
					{
						std::cerr << "ERROR: public-key signature algorithms other than DSA not supported" << std::endl;
						CallasDonnerhackeFinneyShawThayerRFC4880::PacketContextRelease(ctx);
						cleanup_containers(qual, v_i, x_rvss_qual, c_ik);
						return false;
					}
					gcry_mpi_set(dsa_r, ctx.r);
					gcry_mpi_set(dsa_s, ctx.s);
					if ((dsa_hashalgo != TMCG_OPENPGP_HASHALGO_SHA256) &&
					    (dsa_hashalgo != TMCG_OPENPGP_HASHALGO_SHA384) &&
					    (dsa_hashalgo != TMCG_OPENPGP_HASHALGO_SHA512))
						std::cerr << "WARNING: insecure hash algorithm " <<
							(int)dsa_hashalgo << " used for signatures" <<
							std::endl;
					sigdsa = true;
					// store the whole packet
					uidsig.clear();
					for (size_t i = 0; i < current_packet.size(); i++)
						uidsig.push_back(current_packet[i]);
				}
				else if (secdsa && ssbelg &&
					(ctx.type == TMCG_OPENPGP_SIGNATURE_SUBKEY_BINDING) && 
					CallasDonnerhackeFinneyShawThayerRFC4880::OctetsCompare(keyid, issuer))
				{
					if (opt_verbose)
					{
						std::cerr << std::hex;
						std::cerr << "INFO: sig type = 0x";
						std::cerr << (int)ctx.type;
						std::cerr << std::dec;
						std::cerr << " pkalgo = ";
						std::cerr << (int)ctx.pkalgo;
						std::cerr << " hashalgo = ";
						std::cerr << (int)ctx.hashalgo;
						std::cerr << std::endl;
					}
					if (sigelg)
						std::cerr << "WARNING: more than one subkey binding" <<
							" signature; using last signature" << std::endl;
					elg_sigtype = ctx.type;
					elg_pkalgo = ctx.pkalgo;
					elg_hashalgo = ctx.hashalgo;
					for (size_t i = 0; i < sizeof(elg_keyflags); i++)
						elg_keyflags[i] = ctx.keyflags[i];
					for (size_t i = 0; i < sizeof(elg_psa); i++)
						elg_psa[i] = ctx.psa[i];
					for (size_t i = 0; i < sizeof(elg_pha); i++)
						elg_pha[i] = ctx.pha[i];
					for (size_t i = 0; i < sizeof(elg_pca); i++)
						elg_pca[i] = ctx.pca[i];
					elg_hspd.clear();
					for (size_t i = 0; i < ctx.hspdlen; i++)
						elg_hspd.push_back(ctx.hspd[i]);
					if (elg_pkalgo != TMCG_OPENPGP_PKALGO_DSA)
					{
						std::cerr << "ERROR: public-key signature algorithms" <<
							" other than DSA not supported" << std::endl;
						CallasDonnerhackeFinneyShawThayerRFC4880::
							PacketContextRelease(ctx);
						cleanup_containers(qual, v_i, x_rvss_qual, c_ik);
						return false;
					}
					gcry_mpi_set(elg_r, ctx.r);
					gcry_mpi_set(elg_s, ctx.s);
					if ((elg_hashalgo != TMCG_OPENPGP_HASHALGO_SHA256) &&
					    (elg_hashalgo != TMCG_OPENPGP_HASHALGO_SHA384) &&
					    (elg_hashalgo != TMCG_OPENPGP_HASHALGO_SHA512))
						std::cerr << "WARNING: insecure hash algorithm " <<
							(int)elg_hashalgo << " used for signatures" <<
							std::endl;
					sigelg = true;
					// store the whole packet
					subsig.clear();
					for (size_t i = 0; i < current_packet.size(); i++)
						subsig.push_back(current_packet[i]);
				}
				break;
			case 5: // Secret-Key Packet
				if (((ctx.pkalgo == 107) || (ctx.pkalgo == 108)) && !secdsa)
				{
					secdsa = true;
					keycreationtime_out = ctx.keycreationtime;
					gcry_mpi_set(dsa_p, ctx.p);
					gcry_mpi_set(dsa_q, ctx.q);
					gcry_mpi_set(dsa_g, ctx.g);
					gcry_mpi_set(dsa_y, ctx.y);
					pub.clear();
					CallasDonnerhackeFinneyShawThayerRFC4880::
						PacketPubEncode(ctx.keycreationtime,
							TMCG_OPENPGP_PKALGO_DSA, dsa_p, dsa_q, dsa_g, dsa_y,
							pub);
					pub_hashing.clear();
					for (size_t i = 6; i < pub.size(); i++)
						pub_hashing.push_back(pub[i]);
					keyid.clear();
					CallasDonnerhackeFinneyShawThayerRFC4880::
						KeyidCompute(pub_hashing, keyid);
					if (opt_verbose)
					{
						std::cerr << "INFO: Key ID of tDSS key: " << std::hex;
						for (size_t i = 0; i < keyid.size(); i++)
							std::cerr << (int)keyid[i] << " ";
						std::cerr << std::dec << std::endl;
						std::cerr << " encdatalen = " << ctx.encdatalen << std::endl;
						std::cerr << " symalgo = " << (int)ctx.symalgo << std::endl;
						std::cerr << " S2K: convention = " << (int)ctx.s2kconv << " type = " << (int)ctx.s2k_type;
						std::cerr << " hashalgo = " << (int)ctx.s2k_hashalgo << " count = " << (int)ctx.s2k_count;
						std::cerr << std::endl;
					}
					if (!mpz_set_gcry_mpi(ctx.p, dss_p))
					{
						std::cerr << "ERROR: mpz_set_gcry_mpi() failed for dss_p" << std::endl;
						CallasDonnerhackeFinneyShawThayerRFC4880::PacketContextRelease(ctx);
						cleanup_containers(qual, v_i, x_rvss_qual, c_ik);
						return false;
					}
					if (!mpz_set_gcry_mpi(ctx.q, dss_q))
					{
						std::cerr << "ERROR: mpz_set_gcry_mpi() failed for dss_q" << std::endl;
						CallasDonnerhackeFinneyShawThayerRFC4880::PacketContextRelease(ctx);
						cleanup_containers(qual, v_i, x_rvss_qual, c_ik);
						return false;
					}
					if (!mpz_set_gcry_mpi(ctx.g, dss_g))
					{
						std::cerr << "ERROR: mpz_set_gcry_mpi() failed for dss_g" << std::endl;
						CallasDonnerhackeFinneyShawThayerRFC4880::PacketContextRelease(ctx);
						cleanup_containers(qual, v_i, x_rvss_qual, c_ik);
						return false;
					}
					if (!mpz_set_gcry_mpi(ctx.h, dss_h))
					{
						std::cerr << "ERROR: mpz_set_gcry_mpi() failed for dss_h" << std::endl;
						CallasDonnerhackeFinneyShawThayerRFC4880::PacketContextRelease(ctx);
						cleanup_containers(qual, v_i, x_rvss_qual, c_ik);
						return false;
					}
					if (!mpz_set_gcry_mpi(ctx.y, dss_y))
					{
						std::cerr << "ERROR: mpz_set_gcry_mpi() failed for dss_y" << std::endl;
						CallasDonnerhackeFinneyShawThayerRFC4880::PacketContextRelease(ctx);
						cleanup_containers(qual, v_i, x_rvss_qual, c_ik);
						return false;
					}
					dss_n = get_gcry_mpi_ui(ctx.n);
					dss_t = get_gcry_mpi_ui(ctx.t);
					dss_i = get_gcry_mpi_ui(ctx.i);
					size_t qualsize = qual.size();
					for (size_t i = 0; i < qualsize; i++)
						dss_qual.push_back(get_gcry_mpi_ui(qual[i]));
					if (ctx.pkalgo == 107)
					{
						size_t x_rvss_qualsize = x_rvss_qual.size();
						for (size_t i = 0; i < x_rvss_qualsize; i++)
							dss_x_rvss_qual.push_back(get_gcry_mpi_ui(x_rvss_qual[i]));
					}
					dss_c_ik.resize(c_ik.size());
					for (size_t i = 0; i < c_ik.size(); i++)
					{
						for (size_t k = 0; k < c_ik[i].size(); k++)
						{
							mpz_ptr tmp = new mpz_t();
							mpz_init(tmp);
							if (!mpz_set_gcry_mpi(c_ik[i][k], tmp))
							{
								std::cerr << "ERROR: mpz_set_gcry_mpi() failed for tmp" << std::endl;
								mpz_clear(tmp);
								delete [] tmp;
								CallasDonnerhackeFinneyShawThayerRFC4880::PacketContextRelease(ctx);
								cleanup_containers(qual, v_i, x_rvss_qual, c_ik);
								return false;
							}
							dss_c_ik[i].push_back(tmp);
						}
					}
					if (ctx.s2kconv == 0)
					{
						if (!mpz_set_gcry_mpi(ctx.x_i, dss_x_i))
						{
							std::cerr << "ERROR: mpz_set_gcry_mpi() failed for dss_x_i" << std::endl;
							CallasDonnerhackeFinneyShawThayerRFC4880::PacketContextRelease(ctx);
							cleanup_containers(qual, v_i, x_rvss_qual, c_ik);
							return false;
						}
						if (!mpz_set_gcry_mpi(ctx.xprime_i, dss_xprime_i))
						{
							std::cerr << "ERROR: mpz_set_gcry_mpi() failed for dss_xprime_i" << std::endl;
							CallasDonnerhackeFinneyShawThayerRFC4880::PacketContextRelease(ctx);
							cleanup_containers(qual, v_i, x_rvss_qual, c_ik);
							return false;
						}
					}
					else if ((ctx.s2kconv == 254) || (ctx.s2kconv == 255))
					{
						keylen = CallasDonnerhackeFinneyShawThayerRFC4880::AlgorithmKeyLength(ctx.symalgo);
						ivlen = CallasDonnerhackeFinneyShawThayerRFC4880::AlgorithmIVLength(ctx.symalgo);
						algo = CallasDonnerhackeFinneyShawThayerRFC4880::AlgorithmSymGCRY(ctx.symalgo);
						if (!keylen || !ivlen)
						{
							std::cerr << "ERROR: unknown symmetric algorithm" << std::endl;
							CallasDonnerhackeFinneyShawThayerRFC4880::PacketContextRelease(ctx);
							cleanup_containers(qual, v_i, x_rvss_qual, c_ik);
							return false;
						}
						salt.clear();
						for (size_t i = 0; i < sizeof(ctx.s2k_salt); i++)
							salt.push_back(ctx.s2k_salt[i]);
						seskey.clear();
						if (ctx.s2k_type == 0x00)
						{
							salt.clear();
							CallasDonnerhackeFinneyShawThayerRFC4880::S2KCompute(ctx.s2k_hashalgo,
								keylen, passphrase, salt, false, ctx.s2k_count, seskey);
						}
						else if (ctx.s2k_type == 0x01)
						{
							CallasDonnerhackeFinneyShawThayerRFC4880::S2KCompute(ctx.s2k_hashalgo,
								keylen, passphrase, salt, false, ctx.s2k_count, seskey);
						}
						else if (ctx.s2k_type == 0x03)
						{
							CallasDonnerhackeFinneyShawThayerRFC4880::S2KCompute(ctx.s2k_hashalgo,
								keylen, passphrase, salt, true, ctx.s2k_count, seskey);
						}
						else
						{
							std::cerr << "ERROR: unknown S2K specifier" << std::endl;
							CallasDonnerhackeFinneyShawThayerRFC4880::PacketContextRelease(ctx);
							cleanup_containers(qual, v_i, x_rvss_qual, c_ik);
							return false;
						}
						if (seskey.size() != keylen)
						{
							std::cerr << "ERROR: S2K failed" << std::endl;
							CallasDonnerhackeFinneyShawThayerRFC4880::PacketContextRelease(ctx);
							cleanup_containers(qual, v_i, x_rvss_qual, c_ik);
							return false;
						}
						if (!ctx.encdatalen || !ctx.encdata)
						{
							std::cerr << "ERROR: nothing to decrypt" << std::endl;
							CallasDonnerhackeFinneyShawThayerRFC4880::PacketContextRelease(ctx);
							cleanup_containers(qual, v_i, x_rvss_qual, c_ik);
							return false;
						}
						key = new tmcg_openpgp_byte_t[keylen];
						for (size_t i = 0; i < keylen; i++)
							key[i] = seskey[i];
						iv = new tmcg_openpgp_byte_t[ivlen];
						for (size_t i = 0; i < ivlen; i++)
							iv[i] = ctx.iv[i];
						ret = gcry_cipher_open(&hd, algo, GCRY_CIPHER_MODE_CFB, 0);
						if (ret)
						{
							std::cerr << "ERROR: gcry_cipher_open() failed" << std::endl;
							delete [] key;
							delete [] iv;
							CallasDonnerhackeFinneyShawThayerRFC4880::PacketContextRelease(ctx);
							cleanup_containers(qual, v_i, x_rvss_qual, c_ik);
							return false;
						}
						ret = gcry_cipher_setkey(hd, key, keylen);
						if (ret)
						{
							std::cerr << "ERROR: gcry_cipher_setkey() failed" << std::endl;
							gcry_cipher_close(hd);
							delete [] key;
							delete [] iv;
							CallasDonnerhackeFinneyShawThayerRFC4880::PacketContextRelease(ctx);
							cleanup_containers(qual, v_i, x_rvss_qual, c_ik);
							return false;
						}
						ret = gcry_cipher_setiv(hd, iv, ivlen);
						if (ret)
						{
							std::cerr << "ERROR: gcry_cipher_setiv() failed" << std::endl;
							gcry_cipher_close(hd);
							delete [] key;
							delete [] iv;
							CallasDonnerhackeFinneyShawThayerRFC4880::PacketContextRelease(ctx);
							cleanup_containers(qual, v_i, x_rvss_qual, c_ik);
							return false;
						}
						ret = gcry_cipher_decrypt(hd, ctx.encdata, ctx.encdatalen, NULL, 0);
						if (ret)
						{
							std::cerr << "ERROR: gcry_cipher_decrypt() failed" << std::endl;
							gcry_cipher_close(hd);
							delete [] key;
							delete [] iv;
							CallasDonnerhackeFinneyShawThayerRFC4880::PacketContextRelease(ctx);
							cleanup_containers(qual, v_i, x_rvss_qual, c_ik);
							return false;
						}
						gcry_cipher_close(hd);
						delete [] key;
						delete [] iv;
						// read MPIs x_i, xprime_i and verify checksum/hash
						mpis.clear();
						chksum = 0;
						for (size_t i = 0; i < ctx.encdatalen; i++)
							mpis.push_back(ctx.encdata[i]);
						mlen = CallasDonnerhackeFinneyShawThayerRFC4880::PacketMPIDecode(mpis, dsa_x, chksum);
						if (!mlen || (mlen > mpis.size()))
						{
							std::cerr << "ERROR: reading MPI x_i failed (bad passphrase)" << std::endl;
							CallasDonnerhackeFinneyShawThayerRFC4880::PacketContextRelease(ctx);
							cleanup_containers(qual, v_i, x_rvss_qual, c_ik);
							return false;
						}
						mpis.erase(mpis.begin(), mpis.begin()+mlen);
						if (!mpz_set_gcry_mpi(dsa_x, dss_x_i))
						{
							std::cerr << "ERROR: mpz_set_gcry_mpi() failed for dss_x_i" << std::endl;
							CallasDonnerhackeFinneyShawThayerRFC4880::PacketContextRelease(ctx);
							cleanup_containers(qual, v_i, x_rvss_qual, c_ik);
							return false;
						}
						mlen = CallasDonnerhackeFinneyShawThayerRFC4880::PacketMPIDecode(mpis, dsa_x, chksum);
						if (!mlen || (mlen > mpis.size()))
						{
							std::cerr << "ERROR: reading MPI xprime_i failed (bad passphrase)" << std::endl;
							CallasDonnerhackeFinneyShawThayerRFC4880::PacketContextRelease(ctx);
							cleanup_containers(qual, v_i, x_rvss_qual, c_ik);
							return false;
						}
						mpis.erase(mpis.begin(), mpis.begin()+mlen);
						if (!mpz_set_gcry_mpi(dsa_x, dss_xprime_i))
						{
							std::cerr << "ERROR: mpz_set_gcry_mpi() failed for dss_xprime_i" << std::endl;
							CallasDonnerhackeFinneyShawThayerRFC4880::PacketContextRelease(ctx);
							cleanup_containers(qual, v_i, x_rvss_qual, c_ik);
							return false;
						}
						if (ctx.s2kconv == 255)
						{
							if (mpis.size() < 2)
							{
								std::cerr << "ERROR: no checksum found" << std::endl;
								CallasDonnerhackeFinneyShawThayerRFC4880::PacketContextRelease(ctx);
								cleanup_containers(qual, v_i, x_rvss_qual, c_ik);
								return false;
							}
							chksum2 = (mpis[0] << 8) + mpis[1];
							if (chksum != chksum2)
							{
								std::cerr << "ERROR: checksum mismatch" << std::endl;
								CallasDonnerhackeFinneyShawThayerRFC4880::PacketContextRelease(ctx);
								cleanup_containers(qual, v_i, x_rvss_qual, c_ik);
								return false;
							}
						}
						else
						{
							if ((mpis.size() != 20) || (ctx.encdatalen < 20))
							{
								std::cerr << "ERROR: no SHA-1 hash found" << std::endl;
								CallasDonnerhackeFinneyShawThayerRFC4880::PacketContextRelease(ctx);
								cleanup_containers(qual, v_i, x_rvss_qual, c_ik);
								return false;
							}
							hash_input.clear(), hash.clear();
							for (size_t i = 0; i < (ctx.encdatalen - 20); i++)
								hash_input.push_back(ctx.encdata[i]);
							CallasDonnerhackeFinneyShawThayerRFC4880::HashCompute(TMCG_OPENPGP_HASHALGO_SHA1, hash_input, hash);
							if (!CallasDonnerhackeFinneyShawThayerRFC4880::OctetsCompare(hash, mpis))
							{
								std::cerr << "ERROR: SHA-1 hash mismatch" << std::endl;
								CallasDonnerhackeFinneyShawThayerRFC4880::PacketContextRelease(ctx);
								cleanup_containers(qual, v_i, x_rvss_qual, c_ik);
								return false;
							}
						}
					}
					else
					{
						std::cerr << "ERROR: S2K format not supported" << std::endl;
						CallasDonnerhackeFinneyShawThayerRFC4880::PacketContextRelease(ctx);
						cleanup_containers(qual, v_i, x_rvss_qual, c_ik);
						return false;
					}
					// create one-to-one mapping based on the stored canonicalized peer list
					idx2dkg.clear(), dkg2idx.clear();
					if ((ctx.pkalgo == 107) && (capl.size() != dss_n))
					{
						std::cerr << "ERROR: tDSS parameter n and CAPL size does not match" << std::endl;
						CallasDonnerhackeFinneyShawThayerRFC4880::PacketContextRelease(ctx);
						cleanup_containers(qual, v_i, x_rvss_qual, c_ik);
						return false;
					}
					else if ((ctx.pkalgo == 108) && (capl.size() != dss_qual.size()))
					{
						std::cerr << "ERROR: QUAL size of tDSS key and CAPL does not match" << std::endl;
						CallasDonnerhackeFinneyShawThayerRFC4880::PacketContextRelease(ctx);
						cleanup_containers(qual, v_i, x_rvss_qual, c_ik);
						return false;
					}
					for (size_t i = 0; i < peers.size(); i++)
					{
						bool found = false;
						for (size_t j = 0; j < capl.size(); j++)
						{
							if (peers[i] == capl[j])
							{
								assert((j < dss_n));
								found = true;
								idx2dkg[i] = j, dkg2idx[j] = i;
								if (opt_verbose)
									std::cerr << "INFO: mapping " << i << " -> P_" << j << std::endl; 
								break;
							}
						}
						if (!found)
						{
							std::cerr << "ERROR: peer \"" << peers[i] <<
								"\" not found inside CAPL from tDSS key" << std::endl;
							CallasDonnerhackeFinneyShawThayerRFC4880::PacketContextRelease(ctx);
							cleanup_containers(qual, v_i, x_rvss_qual, c_ik);
							return false;
						}
					}
					// copy CAPL information
					capl_out.clear();
					for (size_t i = 0; i < capl.size(); i++)
						capl_out.push_back(capl[i]);
					// store the whole packet
					sec.clear();
					for (size_t i = 0; i < current_packet.size(); i++)
						sec.push_back(current_packet[i]);
				}
				else if ((ctx.pkalgo == TMCG_OPENPGP_PKALGO_DSA) && !secdsa)
				{
					secdsa = true;
					keycreationtime_out = ctx.keycreationtime;
					gcry_mpi_set(dsa_p, ctx.p);
					gcry_mpi_set(dsa_q, ctx.q);
					gcry_mpi_set(dsa_g, ctx.g);
					gcry_mpi_set(dsa_y, ctx.y);
					pub.clear();
					CallasDonnerhackeFinneyShawThayerRFC4880::PacketPubEncode(ctx.keycreationtime, TMCG_OPENPGP_PKALGO_DSA,
						dsa_p, dsa_q, dsa_g, dsa_y, pub);
					pub_hashing.clear();
					for (size_t i = 6; i < pub.size(); i++)
						pub_hashing.push_back(pub[i]);
					keyid.clear();
					CallasDonnerhackeFinneyShawThayerRFC4880::KeyidCompute(pub_hashing, keyid);
					if (opt_verbose)
					{
						std::cerr << "INFO: Key ID of DSA key: " << std::hex;
						for (size_t i = 0; i < keyid.size(); i++)
							std::cerr << (int)keyid[i] << " ";
						std::cerr << std::dec << std::endl;
						std::cerr << " encdatalen = " << ctx.encdatalen << std::endl;
						std::cerr << " symalgo = " << (int)ctx.symalgo << std::endl;
						std::cerr << " S2K: convention = " << (int)ctx.s2kconv << " type = " << (int)ctx.s2k_type;
						std::cerr << " hashalgo = " << (int)ctx.s2k_hashalgo << " count = " << (int)ctx.s2k_count;
						std::cerr << std::endl;
					}
					if (!mpz_set_gcry_mpi(ctx.p, dss_p))
					{
						std::cerr << "ERROR: mpz_set_gcry_mpi() failed for dss_p" << std::endl;
						CallasDonnerhackeFinneyShawThayerRFC4880::PacketContextRelease(ctx);
						cleanup_containers(qual, v_i, x_rvss_qual, c_ik);
						return false;
					}
					if (!mpz_set_gcry_mpi(ctx.q, dss_q))
					{
						std::cerr << "ERROR: mpz_set_gcry_mpi() failed for dss_q" << std::endl;
						CallasDonnerhackeFinneyShawThayerRFC4880::PacketContextRelease(ctx);
						cleanup_containers(qual, v_i, x_rvss_qual, c_ik);
						return false;
					}
					if (!mpz_set_gcry_mpi(ctx.g, dss_g))
					{
						std::cerr << "ERROR: mpz_set_gcry_mpi() failed for dss_g" << std::endl;
						CallasDonnerhackeFinneyShawThayerRFC4880::PacketContextRelease(ctx);
						cleanup_containers(qual, v_i, x_rvss_qual, c_ik);
						return false;
					}
					if (ctx.s2kconv == 0)
					{
						gcry_mpi_set(dsa_x, ctx.x); // not encrypted
					}
					else if ((ctx.s2kconv == 254) || (ctx.s2kconv == 255))
					{
						keylen = CallasDonnerhackeFinneyShawThayerRFC4880::AlgorithmKeyLength(ctx.symalgo);
						ivlen = CallasDonnerhackeFinneyShawThayerRFC4880::AlgorithmIVLength(ctx.symalgo);
						algo = CallasDonnerhackeFinneyShawThayerRFC4880::AlgorithmSymGCRY(ctx.symalgo);
						if (!keylen || !ivlen)
						{
							std::cerr << "ERROR: unknown symmetric algorithm" << std::endl;
							CallasDonnerhackeFinneyShawThayerRFC4880::PacketContextRelease(ctx);
							cleanup_containers(qual, v_i, x_rvss_qual, c_ik);
							return false;
						}
						salt.clear();
						for (size_t i = 0; i < sizeof(ctx.s2k_salt); i++)
							salt.push_back(ctx.s2k_salt[i]);
						seskey.clear();
						if (ctx.s2k_type == 0x00)
						{
							salt.clear();
							CallasDonnerhackeFinneyShawThayerRFC4880::S2KCompute(ctx.s2k_hashalgo,
								keylen, passphrase, salt, false, ctx.s2k_count, seskey);
						}
						else if (ctx.s2k_type == 0x01)
						{
							CallasDonnerhackeFinneyShawThayerRFC4880::S2KCompute(ctx.s2k_hashalgo,
								keylen, passphrase, salt, false, ctx.s2k_count, seskey);
						}
						else if (ctx.s2k_type == 0x03)
						{
							CallasDonnerhackeFinneyShawThayerRFC4880::S2KCompute(ctx.s2k_hashalgo,
								keylen, passphrase, salt, true, ctx.s2k_count, seskey);
						}
						else
						{
							std::cerr << "ERROR: unknown S2K specifier" << std::endl;
							CallasDonnerhackeFinneyShawThayerRFC4880::PacketContextRelease(ctx);
							cleanup_containers(qual, v_i, x_rvss_qual, c_ik);
							return false;
						}
						if (seskey.size() != keylen)
						{
							std::cerr << "ERROR: S2K failed" << std::endl;
							CallasDonnerhackeFinneyShawThayerRFC4880::PacketContextRelease(ctx);
							cleanup_containers(qual, v_i, x_rvss_qual, c_ik);
							return false;
						}
						if (!ctx.encdatalen || !ctx.encdata)
						{
							std::cerr << "ERROR: nothing to decrypt" << std::endl;
							CallasDonnerhackeFinneyShawThayerRFC4880::PacketContextRelease(ctx);
							cleanup_containers(qual, v_i, x_rvss_qual, c_ik);
							return false;
						}
						key = new tmcg_openpgp_byte_t[keylen];
						for (size_t i = 0; i < keylen; i++)
							key[i] = seskey[i];
						iv = new tmcg_openpgp_byte_t[ivlen];
						for (size_t i = 0; i < ivlen; i++)
							iv[i] = ctx.iv[i];
						ret = gcry_cipher_open(&hd, algo, GCRY_CIPHER_MODE_CFB, 0);
						if (ret)
						{
							std::cerr << "ERROR: gcry_cipher_open() failed" << std::endl;
							delete [] key;
							delete [] iv;
							CallasDonnerhackeFinneyShawThayerRFC4880::PacketContextRelease(ctx);
							cleanup_containers(qual, v_i, x_rvss_qual, c_ik);
							return false;
						}
						ret = gcry_cipher_setkey(hd, key, keylen);
						if (ret)
						{
							std::cerr << "ERROR: gcry_cipher_setkey() failed" << std::endl;
							gcry_cipher_close(hd);
							delete [] key;
							delete [] iv;
							CallasDonnerhackeFinneyShawThayerRFC4880::PacketContextRelease(ctx);
							cleanup_containers(qual, v_i, x_rvss_qual, c_ik);
							return false;
						}
						ret = gcry_cipher_setiv(hd, iv, ivlen);
						if (ret)
						{
							std::cerr << "ERROR: gcry_cipher_setiv() failed" << std::endl;
							gcry_cipher_close(hd);
							delete [] key;
							delete [] iv;
							CallasDonnerhackeFinneyShawThayerRFC4880::PacketContextRelease(ctx);
							cleanup_containers(qual, v_i, x_rvss_qual, c_ik);
							return false;
						}
						ret = gcry_cipher_decrypt(hd, ctx.encdata, ctx.encdatalen, NULL, 0);
						if (ret)
						{
							std::cerr << "ERROR: gcry_cipher_decrypt() failed" << std::endl;
							gcry_cipher_close(hd);
							delete [] key;
							delete [] iv;
							CallasDonnerhackeFinneyShawThayerRFC4880::PacketContextRelease(ctx);
							cleanup_containers(qual, v_i, x_rvss_qual, c_ik);
							return false;
						}
						gcry_cipher_close(hd);
						delete [] key;
						delete [] iv;
						// read MPI x and verify checksum/hash
						mpis.clear();
						chksum = 0;
						for (size_t i = 0; i < ctx.encdatalen; i++)
							mpis.push_back(ctx.encdata[i]);
						mlen = CallasDonnerhackeFinneyShawThayerRFC4880::PacketMPIDecode(mpis, dsa_x, chksum);
						if (!mlen || (mlen > mpis.size()))
						{
							std::cerr << "ERROR: reading MPI x failed (bad passphrase)" << std::endl;
							CallasDonnerhackeFinneyShawThayerRFC4880::PacketContextRelease(ctx);
							cleanup_containers(qual, v_i, x_rvss_qual, c_ik);
							return false;
						}
						mpis.erase(mpis.begin(), mpis.begin()+mlen);
						if (ctx.s2kconv == 255)
						{
							if (mpis.size() < 2)
							{
								std::cerr << "ERROR: no checksum found" << std::endl;
								CallasDonnerhackeFinneyShawThayerRFC4880::PacketContextRelease(ctx);
								cleanup_containers(qual, v_i, x_rvss_qual, c_ik);
								return false;
							}
							chksum2 = (mpis[0] << 8) + mpis[1];
							if (chksum != chksum2)
							{
								std::cerr << "ERROR: checksum mismatch" << std::endl;
								CallasDonnerhackeFinneyShawThayerRFC4880::PacketContextRelease(ctx);
								cleanup_containers(qual, v_i, x_rvss_qual, c_ik);
								return false;
							}
						}
						else
						{
							if ((mpis.size() != 20) || (ctx.encdatalen < 20))
							{
								std::cerr << "ERROR: no SHA-1 hash found" << std::endl;
								CallasDonnerhackeFinneyShawThayerRFC4880::PacketContextRelease(ctx);
								cleanup_containers(qual, v_i, x_rvss_qual, c_ik);
								return false;
							}
							hash_input.clear(), hash.clear();
							for (size_t i = 0; i < (ctx.encdatalen - 20); i++)
								hash_input.push_back(ctx.encdata[i]);
							CallasDonnerhackeFinneyShawThayerRFC4880::HashCompute(TMCG_OPENPGP_HASHALGO_SHA1, hash_input, hash);
							if (!CallasDonnerhackeFinneyShawThayerRFC4880::OctetsCompare(hash, mpis))
							{
								std::cerr << "ERROR: SHA-1 hash mismatch" << std::endl;
								CallasDonnerhackeFinneyShawThayerRFC4880::PacketContextRelease(ctx);
								cleanup_containers(qual, v_i, x_rvss_qual, c_ik);
								return false;
							}
						}
					}
					else
					{
						std::cerr << "ERROR: S2K format not supported" << std::endl;
						CallasDonnerhackeFinneyShawThayerRFC4880::PacketContextRelease(ctx);
						cleanup_containers(qual, v_i, x_rvss_qual, c_ik);
						return false;
					}
					// store the whole packet
					sec.clear();
					for (size_t i = 0; i < current_packet.size(); i++)
						sec.push_back(current_packet[i]);
				}
				else if (((ctx.pkalgo == 108) || (ctx.pkalgo == TMCG_OPENPGP_PKALGO_DSA)) && secdsa)
				{
					std::cerr << "ERROR: more than one primary key not supported" << std::endl;
					CallasDonnerhackeFinneyShawThayerRFC4880::PacketContextRelease(ctx);
					cleanup_containers(qual, v_i, x_rvss_qual, c_ik);
					return false;
				}
				else
					std::cerr << "WARNING: public-key algorithm not supported; packet ignored" << std::endl;
				break;
			case 13: // User ID Packet
				if (opt_verbose)
					std::cerr << "INFO: uid = " << ctx.uid << std::endl;
				userid = "";
				for (size_t i = 0; i < sizeof(ctx.uid); i++)
				{
					if (ctx.uid[i])
						userid += ctx.uid[i];
					else
						break;
				}
				// store the whole packet
				uid.clear();
				for (size_t i = 0; i < current_packet.size(); i++)
					uid.push_back(current_packet[i]);
				break;
			case 7: // Secret-Subkey Packet
				if ((ctx.pkalgo == 109) && !ssbelg)
				{
					ssbelg = true;
					gcry_mpi_set(elg_p, ctx.p);
					gcry_mpi_set(elg_q, ctx.q);
					gcry_mpi_set(elg_g, ctx.g);
					gcry_mpi_set(elg_y, ctx.y);
					sub.clear();
					CallasDonnerhackeFinneyShawThayerRFC4880::PacketSubEncode(ctx.keycreationtime, TMCG_OPENPGP_PKALGO_ELGAMAL,
						elg_p, dsa_q, elg_g, elg_y, sub);
					sub_hashing.clear();
					for (size_t i = 6; i < sub.size(); i++)
						sub_hashing.push_back(sub[i]);
					subkeyid.clear();
					CallasDonnerhackeFinneyShawThayerRFC4880::KeyidCompute(sub_hashing, subkeyid);
					if (opt_verbose)
					{
						std::cerr << "INFO: Key ID of ElGamal subkey: " << std::hex;
						for (size_t i = 0; i < subkeyid.size(); i++)
							std::cerr << (int)subkeyid[i] << " ";
						std::cerr << std::dec << std::endl;
						std::cerr << " symalgo = " << (int)ctx.symalgo << std::endl;
						std::cerr << " encdatalen = " << ctx.encdatalen << std::endl;
						std::cerr << " S2K: convention = " << (int)ctx.s2kconv << " type = " << (int)ctx.s2k_type;
						std::cerr << " hashalgo = " << (int)ctx.s2k_hashalgo << " count = " << (int)ctx.s2k_count;
						std::cerr << std::endl;
					}
					if (!mpz_set_gcry_mpi(ctx.p, dkg_p))
					{
						std::cerr << "ERROR: converting key component dkg_p failed" << std::endl;
						CallasDonnerhackeFinneyShawThayerRFC4880::PacketContextRelease(ctx);
						cleanup_containers(qual, v_i, x_rvss_qual, c_ik);
						return false;
					}
					if (!mpz_set_gcry_mpi(ctx.q, dkg_q))
					{
						std::cerr << "ERROR: converting key component dkg_q failed" << std::endl;
						CallasDonnerhackeFinneyShawThayerRFC4880::PacketContextRelease(ctx);
						cleanup_containers(qual, v_i, x_rvss_qual, c_ik);
						return false;
					}
					if (!mpz_set_gcry_mpi(ctx.g, dkg_g))
					{
						std::cerr << "ERROR: converting key component dkg_g failed" << std::endl;
						CallasDonnerhackeFinneyShawThayerRFC4880::PacketContextRelease(ctx);
						cleanup_containers(qual, v_i, x_rvss_qual, c_ik);
						return false;
					}
					if (!mpz_set_gcry_mpi(ctx.h, dkg_h))
					{
						std::cerr << "ERROR: converting key component dkg_h failed" << std::endl;
						CallasDonnerhackeFinneyShawThayerRFC4880::PacketContextRelease(ctx);
						cleanup_containers(qual, v_i, x_rvss_qual, c_ik);
						return false;
					}
					if (!mpz_set_gcry_mpi(ctx.y, dkg_y))
					{
						std::cerr << "ERROR: converting key component dkg_y failed" << std::endl;
						CallasDonnerhackeFinneyShawThayerRFC4880::PacketContextRelease(ctx);
						cleanup_containers(qual, v_i, x_rvss_qual, c_ik);
						return false;
					}
					dkg_n = get_gcry_mpi_ui(ctx.n);
					dkg_t = get_gcry_mpi_ui(ctx.t);
					dkg_i = get_gcry_mpi_ui(ctx.i);
					for (size_t i = 0; i < qual.size(); i++)
						dkg_qual.push_back(get_gcry_mpi_ui(qual[i]));
					for (size_t i = 0; i < v_i.size(); i++)
					{
						mpz_ptr tmp = new mpz_t();
						mpz_init(tmp);
						if (!mpz_set_gcry_mpi(v_i[i], tmp))
						{
							std::cerr << "ERROR: mpz_set_gcry_mpi() failed for tmp (v_i)" << std::endl;
							mpz_clear(tmp);
							delete [] tmp;
							CallasDonnerhackeFinneyShawThayerRFC4880::PacketContextRelease(ctx);
							cleanup_containers(qual, v_i, x_rvss_qual, c_ik);
							return false;
						}
						dkg_v_i.push_back(tmp);
					}
					dkg_c_ik.resize(c_ik.size());
					for (size_t i = 0; i < c_ik.size(); i++)
					{
						for (size_t k = 0; k < c_ik[i].size(); k++)
						{
							mpz_ptr tmp = new mpz_t();
							mpz_init(tmp);
							if (!mpz_set_gcry_mpi(c_ik[i][k], tmp))
							{
								std::cerr << "ERROR: mpz_set_gcry_mpi() failed for tmp (c_ik)" << std::endl;
								mpz_clear(tmp);
								delete [] tmp;
								CallasDonnerhackeFinneyShawThayerRFC4880::PacketContextRelease(ctx);
								cleanup_containers(qual, v_i, x_rvss_qual, c_ik);
								return false;
							}
							dkg_c_ik[i].push_back(tmp);
						}
					}
					if (ctx.s2kconv == 0)
					{
						gcry_mpi_set(elg_x, ctx.x_i); // not encrypted
						if (!mpz_set_gcry_mpi(ctx.x_i, dkg_x_i))
						{
							std::cerr << "ERROR: converting key component dkg_x_i failed" << std::endl;
							CallasDonnerhackeFinneyShawThayerRFC4880::PacketContextRelease(ctx);
							cleanup_containers(qual, v_i, x_rvss_qual, c_ik);
							return false;
						}
						if (!mpz_set_gcry_mpi(ctx.xprime_i, dkg_xprime_i))
						{
							std::cerr << "ERROR: converting key component dkg_xprime_i failed" << std::endl;
							CallasDonnerhackeFinneyShawThayerRFC4880::PacketContextRelease(ctx);
							cleanup_containers(qual, v_i, x_rvss_qual, c_ik);
							return false;
						}
					}
					else if ((ctx.s2kconv == 254) || (ctx.s2kconv == 255))
					{
						keylen = CallasDonnerhackeFinneyShawThayerRFC4880::AlgorithmKeyLength(ctx.symalgo);
						ivlen = CallasDonnerhackeFinneyShawThayerRFC4880::AlgorithmIVLength(ctx.symalgo);
						if (!keylen || !ivlen)
						{
							std::cerr << "ERROR: unknown symmetric algorithm" << std::endl;
							CallasDonnerhackeFinneyShawThayerRFC4880::PacketContextRelease(ctx);
							cleanup_containers(qual, v_i, x_rvss_qual, c_ik);
							return false;
						}
						salt.clear();
						for (size_t i = 0; i < sizeof(ctx.s2k_salt); i++)
							salt.push_back(ctx.s2k_salt[i]);
						seskey.clear();
						if (ctx.s2k_type == 0x00)
						{
							salt.clear();
							CallasDonnerhackeFinneyShawThayerRFC4880::S2KCompute(ctx.s2k_hashalgo,
								keylen, passphrase, salt, false, ctx.s2k_count, seskey);
						}
						else if (ctx.s2k_type == 0x01)
						{
							CallasDonnerhackeFinneyShawThayerRFC4880::S2KCompute(ctx.s2k_hashalgo,
								keylen, passphrase, salt, false, ctx.s2k_count, seskey);
						}
						else if (ctx.s2k_type == 0x03)
						{
							CallasDonnerhackeFinneyShawThayerRFC4880::S2KCompute(ctx.s2k_hashalgo,
								keylen, passphrase, salt, true, ctx.s2k_count, seskey);
						}
						else
						{
							std::cerr << "ERROR: unknown S2K specifier" << std::endl;
							CallasDonnerhackeFinneyShawThayerRFC4880::PacketContextRelease(ctx);
							cleanup_containers(qual, v_i, x_rvss_qual, c_ik);
							return false;
						}
						if (seskey.size() != keylen)
						{
							std::cerr << "ERROR: S2K failed" << std::endl;
							CallasDonnerhackeFinneyShawThayerRFC4880::PacketContextRelease(ctx);
							cleanup_containers(qual, v_i, x_rvss_qual, c_ik);
							return false;
						}
						if (!ctx.encdatalen || !ctx.encdata)
						{
							std::cerr << "ERROR: nothing to decrypt" << std::endl;
							CallasDonnerhackeFinneyShawThayerRFC4880::PacketContextRelease(ctx);
							cleanup_containers(qual, v_i, x_rvss_qual, c_ik);
							return false;
						}
						key = new tmcg_openpgp_byte_t[keylen];
						for (size_t i = 0; i < keylen; i++)
							key[i] = seskey[i];
						iv = new tmcg_openpgp_byte_t[ivlen];
						for (size_t i = 0; i < ivlen; i++)
							iv[i] = ctx.iv[i];
						ret = gcry_cipher_open(&hd, (int)ctx.symalgo, GCRY_CIPHER_MODE_CFB, 0);
						if (ret)
						{
							std::cerr << "ERROR: gcry_cipher_open() failed" << std::endl;
							delete [] key;
							delete [] iv;
							CallasDonnerhackeFinneyShawThayerRFC4880::PacketContextRelease(ctx);
							cleanup_containers(qual, v_i, x_rvss_qual, c_ik);
							return false;
						}
						ret = gcry_cipher_setkey(hd, key, keylen);
						if (ret)
						{
							std::cerr << "ERROR: gcry_cipher_setkey() failed" << std::endl;
							gcry_cipher_close(hd);
							delete [] key;
							delete [] iv;
							CallasDonnerhackeFinneyShawThayerRFC4880::PacketContextRelease(ctx);
							cleanup_containers(qual, v_i, x_rvss_qual, c_ik);
							return false;
						}
						ret = gcry_cipher_setiv(hd, iv, ivlen);
						if (ret)
						{
							std::cerr << "ERROR: gcry_cipher_setiv() failed" << std::endl;
							gcry_cipher_close(hd);
							delete [] key;
							delete [] iv;
							CallasDonnerhackeFinneyShawThayerRFC4880::PacketContextRelease(ctx);
							cleanup_containers(qual, v_i, x_rvss_qual, c_ik);
							return false;
						}
						ret = gcry_cipher_decrypt(hd, ctx.encdata, ctx.encdatalen, NULL, 0);
						if (ret)
						{
							std::cerr << "ERROR: gcry_cipher_decrypt() failed" << std::endl;
							gcry_cipher_close(hd);
							delete [] key;
							delete [] iv;
							CallasDonnerhackeFinneyShawThayerRFC4880::PacketContextRelease(ctx);
							cleanup_containers(qual, v_i, x_rvss_qual, c_ik);
							return false;
						}
						gcry_cipher_close(hd);
						delete [] key;
						delete [] iv;
						// read MPI x reps. MPIs x_i, xprime_i and verify checksum/hash
						mpis.clear();
						chksum = 0;
						for (size_t i = 0; i < ctx.encdatalen; i++)
							mpis.push_back(ctx.encdata[i]);
						mlen = CallasDonnerhackeFinneyShawThayerRFC4880::PacketMPIDecode(mpis, elg_x, chksum);
						if (!mlen || (mlen > mpis.size()))
						{
							std::cerr << "ERROR: reading MPI x_i failed (bad passphrase)" << std::endl;
							CallasDonnerhackeFinneyShawThayerRFC4880::PacketContextRelease(ctx);
							cleanup_containers(qual, v_i, x_rvss_qual, c_ik);
							return false;
						}
						mpis.erase(mpis.begin(), mpis.begin()+mlen);
 						if (!mpz_set_gcry_mpi(elg_x, dkg_x_i))
						{
							std::cerr << "ERROR: converting key component dkg_x_i failed" << std::endl;
							CallasDonnerhackeFinneyShawThayerRFC4880::PacketContextRelease(ctx);
							cleanup_containers(qual, v_i, x_rvss_qual, c_ik);
							return false;
						}
						mlen = CallasDonnerhackeFinneyShawThayerRFC4880::PacketMPIDecode(mpis, elg_x, chksum);
						if (!mlen || (mlen > mpis.size()))
						{
							std::cerr << "ERROR: reading MPI xprime_i failed (bad passphrase)" << std::endl;
							CallasDonnerhackeFinneyShawThayerRFC4880::PacketContextRelease(ctx);
							cleanup_containers(qual, v_i, x_rvss_qual, c_ik);
							return false;
						}
						mpis.erase(mpis.begin(), mpis.begin()+mlen);
						if (!mpz_set_gcry_mpi(elg_x, dkg_xprime_i))
						{
							std::cerr << "ERROR: converting key component dkg_xprime_i failed" << std::endl;
							CallasDonnerhackeFinneyShawThayerRFC4880::PacketContextRelease(ctx);
							cleanup_containers(qual, v_i, x_rvss_qual, c_ik);
							return false;
						}
						if (ctx.s2kconv == 255)
						{
							if (mpis.size() < 2)
							{
								std::cerr << "ERROR: no checksum found" << std::endl;
								CallasDonnerhackeFinneyShawThayerRFC4880::PacketContextRelease(ctx);
								cleanup_containers(qual, v_i, x_rvss_qual, c_ik);
								return false;
							}
							chksum2 = (mpis[0] << 8) + mpis[1];
							if (chksum != chksum2)
							{
								std::cerr << "ERROR: checksum mismatch" << std::endl;
								CallasDonnerhackeFinneyShawThayerRFC4880::PacketContextRelease(ctx);
								cleanup_containers(qual, v_i, x_rvss_qual, c_ik);
								return false;
							}
						}
						else
						{
							if ((mpis.size() != 20) || (ctx.encdatalen < 20))
							{
								std::cerr << "ERROR: no SHA-1 hash found" << std::endl;
								CallasDonnerhackeFinneyShawThayerRFC4880::PacketContextRelease(ctx);
								cleanup_containers(qual, v_i, x_rvss_qual, c_ik);
								return false;
							}
							hash_input.clear(), hash.clear();
							for (size_t i = 0; i < (ctx.encdatalen - 20); i++)
								hash_input.push_back(ctx.encdata[i]);
							CallasDonnerhackeFinneyShawThayerRFC4880::HashCompute(TMCG_OPENPGP_HASHALGO_SHA1, hash_input, hash);
							if (!CallasDonnerhackeFinneyShawThayerRFC4880::OctetsCompare(hash, mpis))
							{
								std::cerr << "ERROR: SHA-1 hash mismatch" << std::endl;
								CallasDonnerhackeFinneyShawThayerRFC4880::PacketContextRelease(ctx);
								cleanup_containers(qual, v_i, x_rvss_qual, c_ik);
								return false;
							}
						}
					}
					else
					{
						std::cerr << "ERROR: S2K format not supported" << std::endl;
						CallasDonnerhackeFinneyShawThayerRFC4880::PacketContextRelease(ctx);
						cleanup_containers(qual, v_i, x_rvss_qual, c_ik);
						return false;
					}
					// store the whole packet
					ssb.clear();
					for (size_t i = 0; i < current_packet.size(); i++)
						ssb.push_back(current_packet[i]);
				}
				else if ((ctx.pkalgo == 109) && ssbelg)
					std::cerr << "WARNING: ElGamal subkey already found; packet ignored" << std::endl; 
				else
					std::cerr << "WARNING: public-key algorithm not supported; packet ignored" << std::endl;
				break;
		}
		// cleanup allocated buffers and mpi's
		CallasDonnerhackeFinneyShawThayerRFC4880::PacketContextRelease(ctx);
		cleanup_containers(qual, v_i, x_rvss_qual, c_ik);
	}
	if (!secdsa)
	{
		std::cerr << "ERROR: no tDSS/DSA private key found" << std::endl;
		return false;
	}
	if (!sigdsa)
	{
		std::cerr << "ERROR: no self-signature for tDSS/DSA key found" << std::endl;
		return false;
	}
	if (ssbelg && !sigelg)
	{
		std::cerr << "ERROR: no self-signature for ElGamal subkey found" << std::endl;
		return false;
	}

	// build keys, check key usage and self-signatures
	gcry_sexp_t dsakey;
	tmcg_openpgp_octets_t dsa_trailer, elg_trailer, dsa_left, elg_left, empty;
	if (opt_verbose)
		std::cerr << "INFO: Primary User ID: " << userid << std::endl;
	ret = gcry_sexp_build(&dsakey, &erroff, "(public-key (dsa (p %M) (q %M) (g %M) (y %M)))", dsa_p, dsa_q, dsa_g, dsa_y);
	if (ret)
	{
		std::cerr << "ERROR: parsing tDSS/DSA key material failed" << std::endl;
		return false;
	}
	size_t flags = 0;
	for (size_t i = 0; i < sizeof(dsa_keyflags); i++)
	{
		if (dsa_keyflags[i])	
			flags = (flags << 8) + dsa_keyflags[i];
		else
			break;
	}
	if (opt_verbose)
	{
		std::cerr << "INFO: tDSS/DSA key flags: ";
		if ((flags & 0x01) == 0x01)
			std::cerr << "C"; // The key may be used to certify other keys.
		if ((flags & 0x02) == 0x02)
			std::cerr << "S"; // The key may be used to sign data.
		if ((flags & 0x04) == 0x04)
			std::cerr << "E"; // The key may be used encrypt communications.
		if ((flags & 0x08) == 0x08)
			std::cerr << "e"; // The key may be used encrypt storage.
		if ((flags & 0x10) == 0x10)
			std::cerr << "D"; // The private component of this key may have been split by a secret-sharing mechanism.		
		if ((flags & 0x20) == 0x20)
			std::cerr << "A"; // The key may be used for authentication.
		if ((flags & 0x80) == 0x80)
			std::cerr << "M"; // The private component of this key may be in the possession of more than one person.
		std::cerr << std::endl;
	}
	if ((flags & 0x02) != 0x02)
	{
		std::cerr << "ERROR: tDSS/DSA primary key cannot used to sign data" << std::endl;
		gcry_sexp_release(dsakey);
		return false;
	}
	dsa_trailer.push_back(4); // only V4 format supported
	dsa_trailer.push_back(dsa_sigtype);
	dsa_trailer.push_back(dsa_pkalgo);
	dsa_trailer.push_back(dsa_hashalgo);
	dsa_trailer.push_back(dsa_hspd.size() >> 8); // length of hashed subpacket data
	dsa_trailer.push_back(dsa_hspd.size());
	dsa_trailer.insert(dsa_trailer.end(), dsa_hspd.begin(), dsa_hspd.end());
	hash.clear();
	CallasDonnerhackeFinneyShawThayerRFC4880::CertificationHash(pub_hashing,
		userid, empty, dsa_trailer, dsa_hashalgo, hash, dsa_left);
	ret = CallasDonnerhackeFinneyShawThayerRFC4880::AsymmetricVerifyDSA(hash, dsakey, dsa_r, dsa_s);
	if (ret)
	{
		std::cerr << "ERROR: verification of tDSS/DSA key self-signature failed (rc = " << gcry_err_code(ret) << ", str = " <<
			gcry_strerror(ret) << ")" << std::endl;
		gcry_sexp_release(dsakey);
		return false;
	}
	if (ssbelg)
	{
		flags = 0;
		for (size_t i = 0; i < sizeof(elg_keyflags); i++)
		{
			if (elg_keyflags[i])
				flags = (flags << 8) + elg_keyflags[i];
			else
				break;
		}
		if (opt_verbose)
		{
			std::cerr << "INFO: ElGamal key flags: ";
			if ((flags & 0x01) == 0x01)
				std::cerr << "C"; // The key may be used to certify other keys.
			if ((flags & 0x02) == 0x02)
				std::cerr << "S"; // The key may be used to sign data.
			if ((flags & 0x04) == 0x04)
				std::cerr << "E"; // The key may be used encrypt communications.
			if ((flags & 0x08) == 0x08)
				std::cerr << "e"; // The key may be used encrypt storage.
			if ((flags & 0x10) == 0x10)
				std::cerr << "D"; // The private component of this key may have been split by a secret-sharing mechanism.
			if ((flags & 0x20) == 0x20)
				std::cerr << "A"; // The key may be used for authentication.
			if ((flags & 0x80) == 0x80)
				std::cerr << "M"; // The private component of this key may be in the possession of more than one person.
			std::cerr << std::endl;
		}
		if ((flags & 0x04) != 0x04)
		{
			std::cerr << "ERROR: ElGamal subkey cannot used to encrypt communications" << std::endl;
			gcry_sexp_release(dsakey);
			return false;
		}
		elg_trailer.push_back(4); // only V4 format supported
		elg_trailer.push_back(elg_sigtype);
		elg_trailer.push_back(elg_pkalgo);
		elg_trailer.push_back(elg_hashalgo);
		elg_trailer.push_back(elg_hspd.size() >> 8); // length of hashed subpacket data
		elg_trailer.push_back(elg_hspd.size());
		elg_trailer.insert(elg_trailer.end(), elg_hspd.begin(), elg_hspd.end());
		hash.clear();
		CallasDonnerhackeFinneyShawThayerRFC4880::KeyHash(pub_hashing, sub_hashing, elg_trailer, elg_hashalgo, hash, elg_left);
		ret = CallasDonnerhackeFinneyShawThayerRFC4880::AsymmetricVerifyDSA(hash, dsakey, elg_r, elg_s);
		if (ret)
		{
			std::cerr << "ERROR: verification of ElGamal subkey self-signature failed (rc = " << gcry_err_code(ret) << ", str = " <<
				gcry_strerror(ret) << ")" << std::endl;
			gcry_sexp_release(dsakey);
			return false;
		}
	}
	gcry_sexp_release(dsakey);
	return true;
}

void release_mpis
	()
{
	mpz_clear(dss_p);
	mpz_clear(dss_q);
	mpz_clear(dss_g);
	mpz_clear(dss_h);
	mpz_clear(dss_x_i);
	mpz_clear(dss_xprime_i);
	mpz_clear(dss_y);
	for (size_t i = 0; i < dss_c_ik.size(); i++)
	{
		for (size_t k = 0; k < dss_c_ik[i].size(); k++)
		{
			mpz_clear(dss_c_ik[i][k]);
			delete [] dss_c_ik[i][k];
		}
	}
	gcry_mpi_release(dsa_p);
	gcry_mpi_release(dsa_q);
	gcry_mpi_release(dsa_g);
	gcry_mpi_release(dsa_y);
	gcry_mpi_release(dsa_x);
	mpz_clear(dkg_p);
	mpz_clear(dkg_q);
	mpz_clear(dkg_g);
	mpz_clear(dkg_h);
	mpz_clear(dkg_x_i);
	mpz_clear(dkg_xprime_i);
	mpz_clear(dkg_y);
	for (size_t i = 0; i < dkg_v_i.size(); i++)
	{
		mpz_clear(dkg_v_i[i]);
		delete [] dkg_v_i[i];
	}
	for (size_t i = 0; i < dkg_c_ik.size(); i++)
	{
		for (size_t k = 0; k < dkg_c_ik[i].size(); k++)
		{
			mpz_clear(dkg_c_ik[i][k]);
			delete [] dkg_c_ik[i][k];
		}
	}
	gcry_mpi_release(elg_p);
	gcry_mpi_release(elg_q);
	gcry_mpi_release(elg_g);
	gcry_mpi_release(elg_y);
	gcry_mpi_release(elg_x);
	gcry_mpi_release(dsa_r);
	gcry_mpi_release(dsa_s);
	gcry_mpi_release(elg_r);
	gcry_mpi_release(elg_s);
	gcry_mpi_release(rsa_n);
	gcry_mpi_release(rsa_e);
	gcry_mpi_release(rsa_md);
	gcry_mpi_release(gk);
	gcry_mpi_release(myk);
	gcry_mpi_release(sig_r);
	gcry_mpi_release(sig_s);
	gcry_mpi_release(revdsa_r);
	gcry_mpi_release(revdsa_s);
	gcry_mpi_release(revelg_r);
	gcry_mpi_release(revelg_s);
	gcry_mpi_release(revrsa_md);
}

