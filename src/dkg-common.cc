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

extern std::string				passphrase, userid;
extern tmcg_octets_t				keyid, subkeyid, pub, sub, uidsig, subsig, sec, ssb, uid;
extern std::map<size_t, size_t>			idx2dkg, dkg2idx;
extern mpz_t					dss_p, dss_q, dss_g, dss_h, dss_x_i, dss_xprime_i, dss_y;
extern size_t					dss_n, dss_t, dss_i;
extern std::vector<size_t>			dss_qual, dss_x_rvss_qual;
extern std::vector< std::vector<mpz_ptr> >	dss_c_ik;
extern mpz_t					dkg_p, dkg_q, dkg_g, dkg_h, dkg_x_i, dkg_xprime_i, dkg_y;
extern size_t					dkg_n, dkg_t, dkg_i;
extern std::vector<size_t>			dkg_qual;
extern std::vector<mpz_ptr>			dkg_v_i;
extern std::vector< std::vector<mpz_ptr> >	dkg_c_ik;
extern gcry_mpi_t 				dsa_p, dsa_q, dsa_g, dsa_y, dsa_x, elg_p, elg_q, elg_g, elg_y, elg_x;
extern gcry_mpi_t				dsa_r, dsa_s, elg_r, elg_s, rsa_n, rsa_e, rsa_md;
extern gcry_mpi_t 				gk, myk, sig_r, sig_s;
extern gcry_mpi_t				revdsa_r, revdsa_s, revelg_r, revelg_s, revrsa_md;

extern int					opt_verbose;

bool get_passphrase
	(const std::string &prompt, std::string &passphrase)
{
	struct termios old_term, new_term;
	
	// disable echo on stdin
	if (tcgetattr(fileno(stdin), &old_term) < 0)
	{
		perror("get_passphrase (tcgetattr)");
		return false;
	}
	new_term = old_term;
	new_term.c_lflag &= ~(ECHO | ISIG);
	new_term.c_lflag |= ECHONL;
	if (tcsetattr(fileno(stdin), TCSANOW, &new_term) < 0)
	{
		perror("get_passphrase (tcsetattr)");
		return false;
	}
	// read the passphrase
	std::cout << prompt.c_str() << ": ";
	std::getline(std::cin, passphrase);
	std::cin.clear();
	// enable echo on stdin
	if (tcsetattr(fileno(stdin), TCSANOW, &old_term) < 0)
	{
		perror("get_passphrase (tcsetattr)");
		return false;
	}
	return true;
}

bool read_key_file
	(const std::string &filename, std::string &result)
{
	// read the public/private key from file
	std::string line;
	std::stringstream key;
	std::ifstream ifs(filename.c_str(), std::ifstream::in);
	if (!ifs.is_open())
	{
		std::cerr << "ERROR: cannot open public/private key file" << std::endl;
		return false;
	}
	while (std::getline(ifs, line))
		key << line << std::endl;
	if (!ifs.eof())
	{
		ifs.close();
		std::cerr << "ERROR: reading public/private key file until EOF failed" << std::endl;
		return false;
	}
	ifs.close();
	result = key.str();
	return true;
}

bool read_binary_key_file
	(const std::string &filename, const tmcg_armor_t type, std::string &result)
{
	// read the public/private key from file and convert to ASCII armor
	tmcg_octets_t input;
	std::ifstream ifs(filename.c_str(), std::ifstream::in);
	if (!ifs.is_open())
	{
		std::cerr << "ERROR: cannot open public/private key file" << std::endl;
		return false;
	}
	char c;
	while (ifs.get(c))
		input.push_back(c);
	if (!ifs.eof())
	{
		ifs.close();
		std::cerr << "ERROR: reading public/private key file until EOF failed" << std::endl;
		return false;
	}
	ifs.close();
	CallasDonnerhackeFinneyShawThayerRFC4880::ArmorEncode(type, input, result);
	return true;
}

bool read_message
	(const std::string &filename, std::string &result)
{
	// read the (encrypted) message from file
	std::string line;
	std::stringstream msg;
	std::ifstream ifs(filename.c_str(), std::ifstream::in);
	if (!ifs.is_open())
	{
		std::cerr << "ERROR: cannot open input file" << std::endl;
		return false;
	}
	while (std::getline(ifs, line))
		msg << line << std::endl;
	if (!ifs.eof())
	{
		ifs.close();
		std::cerr << "ERROR: reading from input file until EOF failed" << std::endl;
		return false;
	}
	ifs.close();
	result = msg.str();
	return true;
}

bool read_binary_message
	(const std::string &filename, std::string &result)
{
	// read the (encrypted) message from file and convert to ASCII armor
	tmcg_octets_t input;
	std::ifstream ifs(filename.c_str(), std::ifstream::in);
	if (!ifs.is_open())
	{
		std::cerr << "ERROR: cannot open input file" << std::endl;
		return false;
	}
	char c;
	while (ifs.get(c))
		input.push_back(c);
	if (!ifs.eof())
	{
		ifs.close();
		std::cerr << "ERROR: reading from input file until EOF failed" << std::endl;
		return false;
	}
	ifs.close();
	CallasDonnerhackeFinneyShawThayerRFC4880::ArmorEncode(TMCG_OPENPGP_ARMOR_MESSAGE, input, result);
	return true;
}

bool write_message
	(const std::string &filename, const tmcg_octets_t &msg)
{
	// write out the (decrypted) message to file
	std::ofstream ofs(filename.c_str(), std::ofstream::out);
	if (!ofs.good())
	{
		std::cerr << "ERROR: cannot open output file" << std::endl;
		return false;
	}
	for (size_t i = 0; i < msg.size(); i++)
	{
		ofs << msg[i];
		if (!ofs.good())
		{
			ofs.close();
			std::cerr << "ERROR: writing to output file failed" << std::endl;
			return false;
		}
	}
	ofs.close();
	return true;
}

bool write_message
	(const std::string &filename, const std::string &msg)
{
	// write out the (decrypted) message to file
	std::ofstream ofs(filename.c_str(), std::ofstream::out);
	if (!ofs.good())
	{
		std::cerr << "ERROR: cannot open output file" << std::endl;
		return false;
	}
	for (size_t i = 0; i < msg.length(); i++)
	{
		ofs << msg[i];
		if (!ofs.good())
		{
			ofs.close();
			std::cerr << "ERROR: writing to output file failed" << std::endl;
			return false;
		}
	}
	ofs.close();
	return true;
}

bool lock_memory
	()
{
	if (mlockall(MCL_CURRENT | MCL_FUTURE) < 0)
	{
		perror("lock_memory (mlockall)");
		return false;
	}
	return true;
}

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

void cleanup_ctx
	(tmcg_openpgp_packet_ctx &ctx)
{
	gcry_mpi_release(ctx.me);
	gcry_mpi_release(ctx.gk);
	gcry_mpi_release(ctx.myk);
	gcry_mpi_release(ctx.md);
	gcry_mpi_release(ctx.r);
	gcry_mpi_release(ctx.s);
	gcry_mpi_release(ctx.n);
	gcry_mpi_release(ctx.e);
	gcry_mpi_release(ctx.d);
	gcry_mpi_release(ctx.p);
	gcry_mpi_release(ctx.q);
	gcry_mpi_release(ctx.u);
	gcry_mpi_release(ctx.g);
	gcry_mpi_release(ctx.h);
	gcry_mpi_release(ctx.y);
	gcry_mpi_release(ctx.x);
	gcry_mpi_release(ctx.t);
	gcry_mpi_release(ctx.i);
	gcry_mpi_release(ctx.qualsize);
	gcry_mpi_release(ctx.x_rvss_qualsize);
	gcry_mpi_release(ctx.x_i);
	gcry_mpi_release(ctx.xprime_i);
	if (ctx.hspd != NULL)
		delete [] ctx.hspd;
	if (ctx.encdata != NULL)
		delete [] ctx.encdata;
	if (ctx.compdata != NULL)
		delete [] ctx.compdata;
	if (ctx.data != NULL)
		delete [] ctx.data;
}

void cleanup_containers
	(std::vector<gcry_mpi_t> &qual, std::vector<gcry_mpi_t> &v_i, std::vector< std::vector<gcry_mpi_t> > &c_ik)
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
	(std::vector<gcry_mpi_t> &qual, std::vector<gcry_mpi_t> &v_i, std::vector<gcry_mpi_t> &x_rvss_qual, std::vector< std::vector<gcry_mpi_t> > &c_ik)
{
	cleanup_containers(qual, v_i, c_ik);
	for (size_t i = 0; i < x_rvss_qual.size(); i++)
		gcry_mpi_release(x_rvss_qual[i]);
	x_rvss_qual.clear();
}

bool parse_message
	(const std::string &in, tmcg_octets_t &enc_out, bool &have_seipd_out)
{
	// decode ASCII armor and parse encrypted message
	tmcg_armor_t atype = TMCG_OPENPGP_ARMOR_UNKNOWN;
	tmcg_octets_t pkts;
	atype = CallasDonnerhackeFinneyShawThayerRFC4880::ArmorDecode(in, pkts);
	if (opt_verbose)
		std::cout << "ArmorDecode() = " << (int)atype << " with " << pkts.size() << " bytes" << std::endl;
	if (atype != TMCG_OPENPGP_ARMOR_MESSAGE)
	{
		std::cerr << "ERROR: wrong type of ASCII Armor found (type = " << (int)atype << ")" << std::endl;
		return false;
	}
	bool have_pkesk = false, have_sed = false;
	tmcg_byte_t ptag = 0xFF;
	size_t pnum = 0;
	while (pkts.size() && ptag)
	{
		tmcg_octets_t pkesk_keyid;
		tmcg_openpgp_packet_ctx ctx;
		tmcg_octets_t current_packet;
		std::vector<gcry_mpi_t> qual, v_i;
		std::vector<std::string> capl;
		std::vector< std::vector<gcry_mpi_t> > c_ik;
		ptag = CallasDonnerhackeFinneyShawThayerRFC4880::PacketDecode(pkts, ctx, current_packet, qual, capl, v_i, c_ik);
		++pnum;
		if (opt_verbose)
			std::cout << "PacketDecode() = " << (int)ptag << " version = " << (int)ctx.version << std::endl;
		if (ptag == 0x00)
		{
			std::cerr << "ERROR: parsing OpenPGP packets failed at #" << pnum << " and position " << pkts.size() << std::endl;
			cleanup_ctx(ctx);
			cleanup_containers(qual, v_i, c_ik);
			return false; // parsing error detected
		}
		else if (ptag == 0xFE)
		{
			std::cerr << "WARNING: unrecognized OpenPGP packet found at #" << pnum << " and position " << pkts.size() << std::endl;
			cleanup_ctx(ctx);
			cleanup_containers(qual, v_i, c_ik);
			continue; // ignore packet
		}
		switch (ptag)
		{
			case 1: // Public-Key Encrypted Session Key
				if (opt_verbose)
					std::cout << " pkalgo = " << (int)ctx.pkalgo << std::endl;
				if (ctx.pkalgo != 16)
				{
					std::cerr << "WARNING: public-key algorithm not supported; packet #" << pnum << " ignored" << std::endl;
					break;
				}
				if (opt_verbose)
					std::cout << " keyid = " << std::hex;
				pkesk_keyid.clear();
				for (size_t i = 0; i < sizeof(ctx.keyid); i++)
				{
					if (opt_verbose)
						std::cout << (int)ctx.keyid[i] << " ";
					pkesk_keyid.push_back(ctx.keyid[i]);
				}
				if (opt_verbose)
					std::cout << std::dec << std::endl;
				if (CallasDonnerhackeFinneyShawThayerRFC4880::OctetsCompareZero(pkesk_keyid))
					std::cerr << "WARNING: PKESK wildcard keyid found; try to decrypt" << std::endl;
				else if (!CallasDonnerhackeFinneyShawThayerRFC4880::OctetsCompare(pkesk_keyid, subkeyid))
				{
					if (opt_verbose)
						std::cout << "WARNING: PKESK keyid does not match subkey ID" << std::endl;
					break;
				}
				if (have_pkesk)
					std::cerr << "WARNING: matching PKESK packet already found; g^k and my^k overwritten" << std::endl;
				gcry_mpi_set(gk, ctx.gk);
				gcry_mpi_set(myk, ctx.myk);
				have_pkesk = true;
				break;
			case 9: // Symmetrically Encrypted Data
				if (!have_pkesk)
					std::cerr << "WARNING: no preceding PKESK packet found; decryption may fail" << std::endl;
				if ((!have_sed) && (!have_seipd_out))
				{
					have_sed = true;
					enc_out.clear();
					for (size_t i = 0; i < ctx.encdatalen; i++)
						enc_out.push_back(ctx.encdata[i]);
				}
				else
				{
					std::cerr << "ERROR: duplicate SED/SEIPD packet found" << std::endl;
					cleanup_ctx(ctx);
					cleanup_containers(qual, v_i, c_ik);
					return false;
				}
				break;
			case 18: // Symmetrically Encrypted Integrity Protected Data
				if ((!have_sed) && (!have_seipd_out))
				{
					have_seipd_out = true;
					enc_out.clear();
					for (size_t i = 0; i < ctx.encdatalen; i++)
						enc_out.push_back(ctx.encdata[i]);
				}
				else
				{
					std::cerr << "ERROR: duplicate SED/SEIPD packet found" << std::endl;
					cleanup_ctx(ctx);
					cleanup_containers(qual, v_i, c_ik);
					return false;
				}
				break;
			default:
				std::cerr << "ERROR: unexpected OpenPGP packet " << (int)ptag<< " found at #" << pnum << std::endl;
				cleanup_ctx(ctx);
				cleanup_containers(qual, v_i, c_ik);
				return false;
		}
		// cleanup allocated buffers and mpi's
		cleanup_ctx(ctx);
		cleanup_containers(qual, v_i, c_ik);
	}
	if (!have_pkesk)
	{
		std::cerr << "ERROR: no public-key encrypted session key found" << std::endl;
		return false;
	}
	if (!have_sed && !have_seipd_out)
	{
		std::cerr << "ERROR: no symmetrically encrypted (and integrity protected) data found" << std::endl;
		return false;
	}
	if (have_sed && have_seipd_out)
	{
		std::cerr << "ERROR: multiple types of symmetrically encrypted data found" << std::endl;
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
	(const bool have_seipd, const tmcg_octets_t &in, tmcg_octets_t &key, tmcg_octets_t &out)
{
	// decrypt the given message
	tmcg_byte_t symalgo = 0;
	if (opt_verbose)
		std::cout << "symmetric decryption of message ..." << std::endl;
	if (key.size() > 0)
	{
		symalgo = key[0];
		if (opt_verbose)
			std::cout << "symalgo = " << (int)symalgo << std::endl;
	}
	else
	{
		std::cerr << "ERROR: no session key provided" << std::endl;
		return false;
	}
	gcry_error_t ret;
	tmcg_octets_t prefix, pkts;
	if (have_seipd)
		ret = CallasDonnerhackeFinneyShawThayerRFC4880::SymmetricDecrypt(in, key, prefix, false, symalgo, pkts);
	else
	{
		std::cerr << "ERROR: encrypted message was not integrity protected" << std::endl;
		return false;
	}
	if (ret)
	{
		std::cerr << "ERROR: SymmetricDecrypt() failed" << std::endl;
		return false;
	}
	// parse the content of decrypted message
	tmcg_openpgp_packet_ctx ctx;
	std::vector<gcry_mpi_t> qual, v_i;
	std::vector<std::string> capl;
	std::vector< std::vector<gcry_mpi_t> > c_ik;
	bool have_lit = false, have_mdc = false;
	tmcg_octets_t lit, mdc_hash;
	tmcg_byte_t ptag = 0xFF;
	size_t pnum = 0, mdc_len = sizeof(ctx.mdc_hash) + 2;
	if (pkts.size() > mdc_len)
		lit.insert(lit.end(), pkts.begin(), pkts.end() - mdc_len); // store literal data
	while (pkts.size() && ptag)
	{
		tmcg_octets_t current_packet;
		ptag = CallasDonnerhackeFinneyShawThayerRFC4880::PacketDecode(pkts, ctx, current_packet, qual, capl, v_i, c_ik);
		++pnum;
		if (opt_verbose)
			std::cout << "PacketDecode() = " << (int)ptag << " version = " << (int)ctx.version << std::endl;
		if (ptag == 0x00)
		{
			std::cerr << "ERROR: parsing OpenPGP packets failed at #" << pnum << " and position " << pkts.size() << std::endl;
			cleanup_ctx(ctx);
			cleanup_containers(qual, v_i, c_ik);
			return false; // parsing error detected
		}
		else if (ptag == 0xFE)
		{
			std::cerr << "WARNING: unrecognized OpenPGP packet found at #" << pnum << " and position " << pkts.size() << std::endl;
			cleanup_ctx(ctx);
			cleanup_containers(qual, v_i, c_ik);
			continue; // ignore packet
		}
		switch (ptag)
		{
			case 2: // Signature
				std::cerr << "WARNING: signature OpenPGP packet found; not supported and ignored" << std::endl;
				break;
			case 4: // One-Pass Signature
				std::cerr << "WARNING: one-pass signature OpenPGP packet found; not supported and ignored" << std::endl;
				break;
			case 8: // Compressed Data
				std::cerr << "WARNING: compressed OpenPGP packet found; not supported and ignored" << std::endl;
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
					std::cerr << "ERROR: OpenPGP message contains more than one literal data packet" << std::endl;
					cleanup_ctx(ctx);
					cleanup_containers(qual, v_i, c_ik);
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
				std::cerr << "ERROR: unexpected OpenPGP packet " << (int)ptag<< " found at #" << pnum << std::endl;
				cleanup_ctx(ctx);
				cleanup_containers(qual, v_i, c_ik);
				return false;
		}
		// cleanup allocated buffers and mpi's
		cleanup_ctx(ctx);
		cleanup_containers(qual, v_i, c_ik);
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
		tmcg_octets_t mdc_hashing, hash;
		mdc_hashing.insert(mdc_hashing.end(), prefix.begin(), prefix.end()); // "it includes the prefix data described above" [RFC4880]
		mdc_hashing.insert(mdc_hashing.end(), lit.begin(), lit.end()); // "it includes all of the plaintext" [RFC4880]
		mdc_hashing.push_back(0xD3); // "and the also includes two octets of values 0xD3, 0x14" [RFC4880]
		mdc_hashing.push_back(0x14);
		CallasDonnerhackeFinneyShawThayerRFC4880::HashCompute(2, mdc_hashing, hash); // "passed through the SHA-1 hash function" [RFC4880]
		if (!CallasDonnerhackeFinneyShawThayerRFC4880::OctetsCompare(mdc_hash, hash))
		{
			std::cerr << "ERROR: MDC hash does not match (security issue)" << std::endl;
			return false;
		}
	}
	return true;
}

bool parse_signature
	(const std::string &in, tmcg_byte_t stype,
	time_t &sigcreationtime_out, time_t &sigexpirationtime_out, tmcg_byte_t &hashalgo_out, tmcg_octets_t &trailer_out, bool &sigV3_out)
{
	// decode ASCII armor and parse the signature according to OpenPGP
	tmcg_armor_t atype = TMCG_OPENPGP_ARMOR_UNKNOWN;
	tmcg_octets_t pkts;
	atype = CallasDonnerhackeFinneyShawThayerRFC4880::ArmorDecode(in, pkts);
	if (opt_verbose)
		std::cout << "ArmorDecode() = " << (int)atype << " with " << pkts.size() << " bytes" << std::endl;
	if (atype != TMCG_OPENPGP_ARMOR_SIGNATURE)
	{
		std::cerr << "ERROR: wrong type of ASCII Armor found (type = " << (int)atype << ")" << std::endl;
		return false;
	}
	bool sig = false;
	tmcg_byte_t ptag = 0xFF;
	size_t pnum = 0;
	while (pkts.size() && ptag)
	{
		tmcg_openpgp_packet_ctx ctx;
		tmcg_octets_t current_packet, issuer;
		std::vector<gcry_mpi_t> qual, v_i;
		std::vector<std::string> capl;
		std::vector< std::vector<gcry_mpi_t> > c_ik;
		ptag = CallasDonnerhackeFinneyShawThayerRFC4880::PacketDecode(pkts, ctx, current_packet, qual, capl, v_i, c_ik);
		++pnum;
		if (opt_verbose)
			std::cout << "PacketDecode() = " << (int)ptag << " version = " << (int)ctx.version << std::endl;
		if (ptag == 0x00)
		{
			std::cerr << "ERROR: parsing OpenPGP packets failed at #" << pnum << " and position " << pkts.size() << std::endl;
			cleanup_ctx(ctx);
			cleanup_containers(qual, v_i, c_ik);
			return false; // parsing error detected
		}
		else if (ptag == 0xFE)
		{
			std::cerr << "WARNING: unrecognized OpenPGP packet found at #" << pnum << " and position " << pkts.size() << std::endl;
			cleanup_ctx(ctx);
			cleanup_containers(qual, v_i, c_ik);
			continue; // ignore packet
		}
		switch (ptag)
		{
			case 2: // Signature Packet
				if (ctx.pkalgo != 17)
				{
					std::cerr << "ERROR: public-key signature algorithms other than DSA not supported" << std::endl;
					cleanup_ctx(ctx);
					cleanup_containers(qual, v_i, c_ik);
					return false;
				}
				if ((ctx.hashalgo < 8) || (ctx.hashalgo >= 11))
					std::cerr << "WARNING: insecure hash algorithm " << (int)ctx.hashalgo << " used for signature" << std::endl;
				issuer.clear();
				for (size_t i = 0; i < sizeof(ctx.issuer); i++)
					issuer.push_back(ctx.issuer[i]);
				if (!sig && (ctx.type == stype) && CallasDonnerhackeFinneyShawThayerRFC4880::OctetsCompare(keyid, issuer))
				{
					sigcreationtime_out = ctx.sigcreationtime;
					sigexpirationtime_out = ctx.sigexpirationtime;
					hashalgo_out = ctx.hashalgo;
					gcry_mpi_set(sig_r, ctx.r);
					gcry_mpi_set(sig_s, ctx.s);
					time_t kmax = ctx.sigcreationtime + ctx.sigexpirationtime;
					if (ctx.sigexpirationtime && (time(NULL) > kmax))
						std::cerr << "WARNING: DSA signature is expired" << std::endl;
					// construct the trailer
					trailer_out.clear();
					if (ctx.version == 3)
					{
						tmcg_octets_t sigtime_octets; // V3 format
						std::cerr << "WARNING: V3 signature packet detected; verification may fail" << std::endl;
						sig = true;
						sigV3_out = true;
						CallasDonnerhackeFinneyShawThayerRFC4880::PacketTimeEncode(ctx.sigcreationtime, sigtime_octets);
						trailer_out.push_back(ctx.type); // type (e.g. 0x00 Binary Document)
						trailer_out.insert(trailer_out.end(), sigtime_octets.begin(), sigtime_octets.end()); // creation time
					}
					else if (ctx.version == 4)
					{
						sig = true;
						sigV3_out = false;
						trailer_out.push_back(4); // V4 format
						trailer_out.push_back(ctx.type); // type (e.g. 0x00 Binary Document)
						trailer_out.push_back(ctx.pkalgo); // public-key algorithm (i.e. DSA)
						trailer_out.push_back(ctx.hashalgo); // hash algorithm
						trailer_out.push_back(ctx.hspdlen >> 8); // length of hashed subpacket data
						trailer_out.push_back(ctx.hspdlen);
						for (size_t i = 0; i < ctx.hspdlen; i++)
							trailer_out.push_back(ctx.hspd[i]); // hashed subpacket data
					}
					else
						std::cerr << "WARNING: unrecognized signature packet version " << (int)ctx.version << std::endl;
				}
				else if (sig && (ctx.type == stype) && CallasDonnerhackeFinneyShawThayerRFC4880::OctetsCompare(keyid, issuer))
				{
					std::cerr << "WARNING: more than one admissible signature; packet ignored" << std::endl;
				}
				break;
			default:
				std::cerr << "ERROR: unexpected OpenPGP packet " << (int)ptag<< " found at #" << pnum << std::endl;
				cleanup_ctx(ctx);
				cleanup_containers(qual, v_i, c_ik);
				return false;
		}
		// cleanup allocated buffers and mpi's
		cleanup_ctx(ctx);
		cleanup_containers(qual, v_i, c_ik);
	}
	if (sig)
		return true;
	else
		return false; // no admissible signature found
}

bool parse_public_key
	(const std::string &in,
	 time_t &keycreationtime_out, time_t &keyexpirationtime_out,
	 time_t &subkeycreationtime_out, time_t &subkeyexpirationtime_out,
	 tmcg_byte_t &keyusage_out, bool elg_required)
{
	// decode ASCII Armor
	tmcg_octets_t pkts;
	tmcg_armor_t atype = CallasDonnerhackeFinneyShawThayerRFC4880::ArmorDecode(in, pkts);
	if (opt_verbose)
		std::cout << "ArmorDecode() = " << (int)atype << " with " << pkts.size() << " bytes" << std::endl;
	if (atype != TMCG_OPENPGP_ARMOR_PUBLIC_KEY_BLOCK)
	{
		std::cerr << "ERROR: wrong type of ASCII Armor found (type = " << (int)atype << ")" << std::endl;
		return false;
	}
	// parse the public key according to OpenPGP
	bool pubdsa = false, sigdsa = false, sigdsaV3 = false, subelg = false, sigelg = false, sigelgV3 = false, uid = false, uat = false;
	bool revdsa = false, revdsaV3 = false, revelg = false, revelgV3 = false;
	bool ignore_further_subkeys = false, ignore_further_signatures = false;
	tmcg_byte_t ptag = 0xFF;
	tmcg_byte_t dsa_sigtype, dsa_pkalgo, dsa_hashalgo, dsa_keyflags[32], revdsa_sigtype, revdsa_pkalgo, revdsa_hashalgo;
	tmcg_byte_t elg_sigtype, elg_pkalgo, elg_hashalgo, elg_keyflags[32], revelg_sigtype, revelg_pkalgo, revelg_hashalgo;
	tmcg_byte_t dsa_psa[255], dsa_pha[255], dsa_pca[255], elg_psa[255], elg_pha[255], elg_pca[255];
	tmcg_octets_t pub_hashing, sub_hashing, issuer, dsa_hspd, revdsa_hspd, elg_hspd, revelg_hspd, hash;
	time_t dsa_creation = 0, dsa_sigtime = 0, revdsa_sigtime = 0, elg_creation = 0, elg_sigtime = 0, revelg_sigtime = 0;
	gcry_sexp_t dsakey;
	gcry_error_t ret;
	size_t erroff, pnum = 0;
	while (pkts.size() && ptag)
	{
		tmcg_openpgp_packet_ctx ctx;
		tmcg_octets_t current_packet;
		std::vector<gcry_mpi_t> qual, v_i;
		std::vector<std::string> capl;
		std::vector< std::vector<gcry_mpi_t> > c_ik;
		ptag = CallasDonnerhackeFinneyShawThayerRFC4880::PacketDecode(pkts, ctx, current_packet, qual, capl, v_i, c_ik);
		++pnum;
		if (opt_verbose)
			std::cout << "PacketDecode() = " << (int)ptag << " version = " << (int)ctx.version << std::endl;
		if (ptag == 0x00)
		{
			std::cerr << "ERROR: parsing OpenPGP packets failed at #" << pnum << " and position " << pkts.size() << std::endl;
			cleanup_ctx(ctx);
			cleanup_containers(qual, v_i, c_ik);
			return false; // parsing error detected
		}
		else if (ptag == 0xFE)
		{
			std::cerr << "WARNING: unrecognized OpenPGP packet found at #" << pnum << " and position " << pkts.size() << std::endl;
			cleanup_ctx(ctx);
			cleanup_containers(qual, v_i, c_ik);
			continue; // ignore packet
		}
		switch (ptag)
		{
			case 2: // Signature Packet
				if (ignore_further_signatures)
					break;
				issuer.clear();
				for (size_t i = 0; i < sizeof(ctx.issuer); i++)
					issuer.push_back(ctx.issuer[i]);
				if (pubdsa && !subelg && !uid && !uat && (ctx.type >= 0x10) && (ctx.type <= 0x13) && 
					CallasDonnerhackeFinneyShawThayerRFC4880::OctetsCompare(keyid, issuer))
				{
					std::cerr << "ERROR: no uid/uat found for this self-signature" << std::endl;
					cleanup_ctx(ctx);
					cleanup_containers(qual, v_i, c_ik);
					return false;
				}
				else if (pubdsa && !subelg && uid && !uat && (ctx.type >= 0x10) && (ctx.type <= 0x13) && 
					CallasDonnerhackeFinneyShawThayerRFC4880::OctetsCompare(keyid, issuer))
				{
					if (ctx.version == 3)
					{
						std::cerr << "WARNING: V3 signature packet detected; verification may fail" << std::endl;
						sigdsaV3 = true;
						dsa_sigtime = ctx.sigcreationtime;
					}
					if (sigdsa)
						std::cerr << "WARNING: more than one self-signatures; using last signature to check UID" << std::endl;
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
					if (opt_verbose)
						std::cout << "INFO: dsa_hspd = " << std::hex;
					for (size_t i = 0; i < ctx.hspdlen; i++)
					{
						dsa_hspd.push_back(ctx.hspd[i]);
						if (opt_verbose)
							std::cout << (int)ctx.hspd[i] << " ";
					}
					if (opt_verbose)
						std::cout << std::dec << std::endl << "INFO: dsa_hspd.size() = " << dsa_hspd.size() << std::endl;
					if (dsa_pkalgo != 17)
					{
						std::cerr << "ERROR: public-key signature algorithms other than DSA not supported" << std::endl;
						cleanup_ctx(ctx);
						cleanup_containers(qual, v_i, c_ik);
						return false;
					}
					gcry_mpi_set(dsa_r, ctx.r);
					gcry_mpi_set(dsa_s, ctx.s);
					unsigned int rbits = 0, sbits = 0;
					rbits = gcry_mpi_get_nbits(dsa_r);
					sbits = gcry_mpi_get_nbits(dsa_s);
					if (opt_verbose)
						std::cout << "INFO: rbits = " << rbits << " sbits = " << sbits << std::endl;
					if ((dsa_hashalgo < 8) || (dsa_hashalgo >= 11))
						std::cerr << "WARNING: insecure hash algorithm " << (int)dsa_hashalgo << " used for signatures" << std::endl;
					time_t kmax = dsa_creation + ctx.keyexpirationtime;
					if (ctx.keyexpirationtime && (time(NULL) > kmax))
						std::cerr << "WARNING: DSA primary key is expired" << std::endl;
					sigdsa = true;
					// store the whole packet
					uidsig.clear();
					for (size_t i = 0; i < current_packet.size(); i++)
						uidsig.push_back(current_packet[i]);
				}
				else if (pubdsa && !subelg && !uid && uat && (ctx.type >= 0x10) && (ctx.type <= 0x13) && 
					CallasDonnerhackeFinneyShawThayerRFC4880::OctetsCompare(keyid, issuer))
				{
					std::cerr << "WARNING: ignore certifying self-signature for a user attribute" << std::endl;
				}
				else if (pubdsa && subelg && !sigelg && (ctx.type == 0x18) && 
					CallasDonnerhackeFinneyShawThayerRFC4880::OctetsCompare(keyid, issuer))
				{
					if (ctx.version == 3)
					{
						std::cerr << "WARNING: V3 signature packet detected; verification may fail" << std::endl;
						sigelgV3 = true;
						elg_sigtime = ctx.sigcreationtime;
					}
					elg_sigtype = ctx.type;
					elg_pkalgo = ctx.pkalgo;
					elg_hashalgo = ctx.hashalgo;
					subkeyexpirationtime_out = ctx.keyexpirationtime;
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
					if (opt_verbose)
						std::cout << "INFO: elg_hspd.size() = " << elg_hspd.size() << std::endl;
					if (elg_pkalgo != 17)
					{
						std::cerr << "ERROR: public-key signature algorithms other than DSA not supported" << std::endl;
						cleanup_ctx(ctx);
						cleanup_containers(qual, v_i, c_ik);
						return false;
					}
					gcry_mpi_set(elg_r, ctx.r);
					gcry_mpi_set(elg_s, ctx.s);
					unsigned int rbits = 0, sbits = 0;
					rbits = gcry_mpi_get_nbits(elg_r);
					sbits = gcry_mpi_get_nbits(elg_s);
					if (opt_verbose)
						std::cout << "INFO: rbits = " << rbits << " sbits = " << sbits << std::endl;
					if ((elg_hashalgo < 8) || (elg_hashalgo >= 11))
						std::cerr << "WARNING: insecure hash algorithm " << (int)elg_hashalgo << " used for signatures" << std::endl;
					time_t kmax = elg_creation + ctx.keyexpirationtime;
					if (ctx.keyexpirationtime && (time(NULL) > kmax))
						std::cerr << "WARNING: ElGamal subkey is expired" << std::endl;
					sigelg = true;
					// store the whole packet
					subsig.clear();
					for (size_t i = 0; i < current_packet.size(); i++)
						subsig.push_back(current_packet[i]);
				}
				else if (pubdsa && subelg && sigelg && (ctx.type == 0x18) && 
					CallasDonnerhackeFinneyShawThayerRFC4880::OctetsCompare(keyid, issuer))
				{
					std::cerr << "WARNING: more than one subkey binding signature; using first signature" << std::endl;
				}
				else if (pubdsa && !subelg && (ctx.type == 0x20) && // Key revocation signature 
					CallasDonnerhackeFinneyShawThayerRFC4880::OctetsCompare(keyid, issuer))
				{
					std::cerr << "WARNING: key revocation signature on primary key" << std::endl;
					revdsa = true;
					revdsa_sigtype = ctx.type;
					revdsa_pkalgo = ctx.pkalgo;
					revdsa_hashalgo = ctx.hashalgo;
					if (ctx.version == 3)
					{
						std::cerr << "WARNING: V3 signature packet detected; verification may fail" << std::endl;
						revdsaV3 = true;
						revdsa_sigtime = ctx.sigcreationtime;
					}
					else
					{
						revdsa_hspd.clear();
						for (size_t i = 0; i < ctx.hspdlen; i++)
							revdsa_hspd.push_back(ctx.hspd[i]);
					}
					if (opt_verbose)
						std::cout << "INFO: revdsa_hspd.size() = " << revdsa_hspd.size() << std::endl;
					if (revdsa_pkalgo != 17)
					{
						std::cerr << "ERROR: public-key signature algorithms other than DSA not supported" << std::endl;
						cleanup_ctx(ctx);
						cleanup_containers(qual, v_i, c_ik);
						return false;
					}
					gcry_mpi_set(revdsa_r, ctx.r);
					gcry_mpi_set(revdsa_s, ctx.s);
					unsigned int rbits = 0, sbits = 0;
					rbits = gcry_mpi_get_nbits(revdsa_r);
					sbits = gcry_mpi_get_nbits(revdsa_s);
					if (opt_verbose)
						std::cout << "INFO: rbits = " << rbits << " sbits = " << sbits << std::endl;
					if ((revdsa_hashalgo < 8) || (revdsa_hashalgo >= 11))
						std::cerr << "WARNING: insecure hash algorithm " << (int)revdsa_hashalgo << " used for signatures" << std::endl;
				}
				else if (pubdsa && subelg && (ctx.type == 0x28) && // Subkey revocation signature 
					CallasDonnerhackeFinneyShawThayerRFC4880::OctetsCompare(keyid, issuer))
				{
					std::cerr << "WARNING: subkey revocation signature on subkey" << std::endl;
					revelg = true;
					revelg_sigtype = ctx.type;
					revelg_pkalgo = ctx.pkalgo;
					revelg_hashalgo = ctx.hashalgo;
					if (ctx.version == 3)
					{
						std::cerr << "WARNING: V3 signature packet detected; verification may fail" << std::endl;
						revelgV3 = true;
						revelg_sigtime = ctx.sigcreationtime;
					}
					else
					{
						revelg_hspd.clear();
						for (size_t i = 0; i < ctx.hspdlen; i++)
							revelg_hspd.push_back(ctx.hspd[i]);
					}
					if (opt_verbose)
						std::cout << "INFO: revelg_hspd.size() = " << revelg_hspd.size() << std::endl;
					if (revelg_pkalgo != 17)
					{
						std::cerr << "ERROR: public-key signature algorithms other than DSA not supported" << std::endl;
						cleanup_ctx(ctx);
						cleanup_containers(qual, v_i, c_ik);
						return false;
					}
					gcry_mpi_set(revelg_r, ctx.r);
					gcry_mpi_set(revelg_s, ctx.s);
					unsigned int rbits = 0, sbits = 0;
					rbits = gcry_mpi_get_nbits(revelg_r);
					sbits = gcry_mpi_get_nbits(revelg_s);
					if (opt_verbose)
						std::cout << "INFO: rbits = " << rbits << " sbits = " << sbits << std::endl;
					if ((revelg_hashalgo < 8) || (revelg_hashalgo >= 11))
						std::cerr << "WARNING: insecure hash algorithm " << (int)revelg_hashalgo << " used for signatures" << std::endl;
				}
				break;
			case 6: // Public-Key Packet
				if (ctx.version != 4)
					std::cerr << "WARNING: public-key packet version " << (int)ctx.version << " not supported" << std::endl;
				else if ((ctx.pkalgo == 17) && !pubdsa)
				{
					pubdsa = true;
					gcry_mpi_set(dsa_p, ctx.p);
					gcry_mpi_set(dsa_q, ctx.q);
					gcry_mpi_set(dsa_g, ctx.g);
					gcry_mpi_set(dsa_y, ctx.y);
					dsa_creation = ctx.keycreationtime;
					keycreationtime_out = ctx.keycreationtime;
					pub.clear();
					CallasDonnerhackeFinneyShawThayerRFC4880::PacketPubEncode(ctx.keycreationtime, ctx.pkalgo,
						dsa_p, dsa_q, dsa_g, dsa_y, pub);
					pub_hashing.clear();
					for (size_t i = 6; i < pub.size(); i++)
						pub_hashing.push_back(pub[i]);
					keyid.clear();
					CallasDonnerhackeFinneyShawThayerRFC4880::KeyidCompute(pub_hashing, keyid);
					if (opt_verbose)
					{
						std::cout << "INFO: Key ID of DSA primary key: " << std::hex;
						for (size_t i = 0; i < keyid.size(); i++)
							std::cout << (int)keyid[i] << " ";
						std::cout << std::dec << std::endl;
					}
				}
				else if ((ctx.pkalgo == 17) && pubdsa)
				{
					std::cerr << "ERROR: more than one primary key not supported" << std::endl;
					cleanup_ctx(ctx);
					cleanup_containers(qual, v_i, c_ik);
					return false;
				}
				else
					std::cerr << "WARNING: public-key algorithm " << (int)ctx.pkalgo << " not supported" << std::endl;
				break;
			case 13: // User ID Packet
				if (uid)
					std::cerr << "WARNING: more than one uid packet found; using last to verify signature" << std::endl;
				uid = true, uat = false;
				userid = "";
				for (size_t i = 0; i < sizeof(ctx.uid); i++)
				{
					if (ctx.uid[i])
						userid += ctx.uid[i];
					else
						break;
				}
				break;
			case 14: // Public-Subkey Packet
				ignore_further_signatures = true;
				if (ctx.version != 4)
					std::cerr << "WARNING: public-subkey packet version " << (int)ctx.version << " not supported" << std::endl;
				else if ((!ignore_further_subkeys && (ctx.pkalgo == 16)) ||
					 (ignore_further_subkeys && revelg && (ctx.pkalgo == 16)))
				{
					subelg = true, sigelg = false, sigelgV3 = false, revelg = false, revelgV3 = false;
					gcry_mpi_set(elg_p, ctx.p);
					gcry_mpi_set(elg_g, ctx.g);
					gcry_mpi_set(elg_y, ctx.y);
					elg_creation = ctx.keycreationtime;
					subkeycreationtime_out = ctx.keycreationtime;
					sub.clear();
					CallasDonnerhackeFinneyShawThayerRFC4880::PacketSubEncode(ctx.keycreationtime, ctx.pkalgo,
						elg_p, dsa_q, elg_g, elg_y, sub);
					sub_hashing.clear();
					for (size_t i = 6; i < sub.size(); i++)
						sub_hashing.push_back(sub[i]);
					subkeyid.clear();
					CallasDonnerhackeFinneyShawThayerRFC4880::KeyidCompute(sub_hashing, subkeyid);
					if (opt_verbose)
					{
						std::cout << "INFO: Key ID of ElGamal subkey: " << std::hex;
						for (size_t i = 0; i < subkeyid.size(); i++)
							std::cout << (int)subkeyid[i] << " ";
						std::cout << std::dec << std::endl;
					}
					ignore_further_subkeys = true;
					ignore_further_signatures = false;
				}
				else
					std::cerr << "WARNING: public-key algorithm " << (int)ctx.pkalgo << " for subkey not supported" << std::endl;
				break;
			case 17: // User Attribute Packet
				std::cerr << "WARNING: user attribute packet found; ignored" << std::endl;
				uid = false, uat = true;
				break;
			default:
				std::cerr << "ERROR: unexpected OpenPGP packet found at #" << pnum << " and position " << pkts.size() << std::endl;
				cleanup_ctx(ctx);
				cleanup_containers(qual, v_i, c_ik);
				return false;
		}
		// cleanup allocated buffers and mpi's
		cleanup_ctx(ctx);
		cleanup_containers(qual, v_i, c_ik);
	}
	if (!pubdsa)
	{
		std::cerr << "ERROR: no DSA key found" << std::endl;
		return false;
	}
	if (!subelg && elg_required)
	{
		std::cerr << "ERROR: no ElGamal subkey found" << std::endl;
		return false;
	}
	if (!sigdsa)
	{
		std::cerr << "ERROR: no self-signature for DSA key found" << std::endl;
		return false;
	}
	if ((!sigelg && elg_required) || (subelg && !sigelg))
	{
		std::cerr << "ERROR: no self-signature for ElGamal subkey found" << std::endl;
		return false;
	}
	
	// build keys, check key usage and self-signatures
	ret = gcry_sexp_build(&dsakey, &erroff, "(public-key (dsa (p %M) (q %M) (g %M) (y %M)))", dsa_p, dsa_q, dsa_g, dsa_y);
	if (ret)
	{
		std::cerr << "ERROR: parsing DSA key material failed" << std::endl;
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
	keyusage_out = flags & 0xFF; // return some flags
	if (opt_verbose)
	{
		std::cout << "key flags on primary key: ";
		if ((flags & 0x01) == 0x01)
			std::cout << "C"; // The key may be used to certify other keys.
		if ((flags & 0x02) == 0x02)
			std::cout << "S"; // The key may be used to sign data.
		if ((flags & 0x04) == 0x04)
			std::cout << "E"; // The key may be used encrypt communications.
		if ((flags & 0x08) == 0x08)
			std::cout << "e"; // The key may be used encrypt storage.
		if ((flags & 0x10) == 0x10)
			std::cout << "D"; // The private component of this key may have been split by a secret-sharing mechanism.		
		if ((flags & 0x20) == 0x20)
			std::cout << "A"; // The key may be used for authentication.
		if ((flags & 0x80) == 0x80)
			std::cout << "M"; // The private component of this key may be in the possession of more than one person.
		std::cout << std::endl;
		std::cout << "INFO: userid = \"" << userid << "\"" << std::endl;
		std::cout << "INFO: dsa_sigtype = 0x" << std::hex << (int)dsa_sigtype << std::dec << 
			" dsa_pkalgo = " << (int)dsa_pkalgo << " dsa_hashalgo = " << (int)dsa_hashalgo << " dsa_hspd.size() = " << dsa_hspd.size() << std::endl;
	}
	tmcg_octets_t dsa_trailer, dsa_left;
	hash.clear();
	if (sigdsaV3)
	{
		tmcg_octets_t dsa_sigtime_octets;
		CallasDonnerhackeFinneyShawThayerRFC4880::PacketTimeEncode(dsa_sigtime, dsa_sigtime_octets);
		// The concatenation of the data to be signed, the signature type, and
		// creation time from the Signature packet (5 additional octets) is
		// hashed. The resulting hash value is used in the signature algorithm.
		// The high 16 bits (first two octets) of the hash are included in the
		// Signature packet to provide a quick test to reject some invalid
		// signatures.
		// A V3 signature hashes five octets of the packet body, starting from
		// the signature type field. This data is the signature type, followed
		// by the four-octet signature time.
		dsa_trailer.push_back(dsa_sigtype);
		dsa_trailer.insert(dsa_trailer.end(), dsa_sigtime_octets.begin(), dsa_sigtime_octets.end());
		CallasDonnerhackeFinneyShawThayerRFC4880::CertificationHashV3(pub_hashing, userid, dsa_trailer, dsa_hashalgo, hash, dsa_left);
	}
	else
	{
		dsa_trailer.push_back(4); // only V4 format supported
		dsa_trailer.push_back(dsa_sigtype);
		dsa_trailer.push_back(dsa_pkalgo);
		dsa_trailer.push_back(dsa_hashalgo);
		dsa_trailer.push_back(dsa_hspd.size() >> 8); // length of hashed subpacket data
		dsa_trailer.push_back(dsa_hspd.size());
		dsa_trailer.insert(dsa_trailer.end(), dsa_hspd.begin(), dsa_hspd.end());
		CallasDonnerhackeFinneyShawThayerRFC4880::CertificationHash(pub_hashing, userid, dsa_trailer, dsa_hashalgo, hash, dsa_left);
	}
	if (opt_verbose)
		std::cout << "INFO: dsa_left = " << std::hex << (int)dsa_left[0] << " " << (int)dsa_left[1] << std::dec << std::endl;
	ret = CallasDonnerhackeFinneyShawThayerRFC4880::AsymmetricVerifyDSA(hash, dsakey, dsa_r, dsa_s);
	if (ret)
	{
		std::cerr << "ERROR: verification of DSA key self-signature failed (rc = " << gcry_err_code(ret) << ", str = " <<
			gcry_strerror(ret) << ")" << std::endl;
		gcry_sexp_release(dsakey);
		return false;
	}
	if (revdsa)
	{
		if (opt_verbose)
			std::cout << "INFO: revdsa_sigtype = 0x" << std::hex << (int)revdsa_sigtype << std::dec << 
				" revdsa_pkalgo = " << (int)revdsa_pkalgo << " revdsa_hashalgo = " << (int)revdsa_hashalgo <<
				" revdsa_hspd.size() = " << revdsa_hspd.size() << std::endl;
		tmcg_octets_t revdsa_trailer, revdsa_left;
		hash.clear();
		if (revdsaV3)
		{
			tmcg_octets_t revdsa_sigtime_octets;
			CallasDonnerhackeFinneyShawThayerRFC4880::PacketTimeEncode(revdsa_sigtime, revdsa_sigtime_octets);
			// The concatenation of the data to be signed, the signature type, and
			// creation time from the Signature packet (5 additional octets) is
			// hashed. The resulting hash value is used in the signature algorithm.
			// The high 16 bits (first two octets) of the hash are included in the
			// Signature packet to provide a quick test to reject some invalid
			// signatures.
			// A V3 signature hashes five octets of the packet body, starting from
			// the signature type field. This data is the signature type, followed
			// by the four-octet signature time.
			revdsa_trailer.push_back(revdsa_sigtype);
			revdsa_trailer.insert(revdsa_trailer.end(), revdsa_sigtime_octets.begin(), revdsa_sigtime_octets.end());
			CallasDonnerhackeFinneyShawThayerRFC4880::KeyRevocationHashV3(pub_hashing, revdsa_trailer, revdsa_hashalgo, hash, revdsa_left);
		}
		else
		{
			revdsa_trailer.push_back(4); // only V4 format supported
			revdsa_trailer.push_back(revdsa_sigtype);
			revdsa_trailer.push_back(revdsa_pkalgo);
			revdsa_trailer.push_back(revdsa_hashalgo);
			revdsa_trailer.push_back(revdsa_hspd.size() >> 8); // length of hashed subpacket data
			revdsa_trailer.push_back(revdsa_hspd.size());
			revdsa_trailer.insert(revdsa_trailer.end(), revdsa_hspd.begin(), revdsa_hspd.end());
			CallasDonnerhackeFinneyShawThayerRFC4880::KeyRevocationHash(pub_hashing, revdsa_trailer, revdsa_hashalgo, hash, revdsa_left);
		}
		if (opt_verbose)
			std::cout << "INFO: revdsa_left = " << std::hex << (int)revdsa_left[0] << " " << (int)revdsa_left[1] << std::dec << std::endl;
		ret = CallasDonnerhackeFinneyShawThayerRFC4880::AsymmetricVerifyDSA(hash, dsakey, revdsa_r, revdsa_s);
		gcry_sexp_release(dsakey);
		if (ret)
		{
			std::cerr << "ERROR: verification of primary key revocation signature failed (rc = " << gcry_err_code(ret) << ", str = " <<
				gcry_strerror(ret) << ")" << std::endl;
			return false;
		}
		else
		{
			std::cerr << "ERROR: valid revocation signature on primary key found" << std::endl;
			return false;
		}
	}
	if (elg_required || (subelg && sigelg))
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
			std::cout << "key flags on subkey: ";
			if ((flags & 0x01) == 0x01)
				std::cout << "C"; // The key may be used to certify other keys.
			if ((flags & 0x02) == 0x02)
				std::cout << "S"; // The key may be used to sign data.
			if ((flags & 0x04) == 0x04)
				std::cout << "E"; // The key may be used encrypt communications.
			if ((flags & 0x08) == 0x08)
				std::cout << "e"; // The key may be used encrypt storage.
			if ((flags & 0x10) == 0x10)
				std::cout << "D"; // The private component of this key may have been split by a secret-sharing mechanism.		
			if ((flags & 0x20) == 0x20)
				std::cout << "A"; // The key may be used for authentication.
			if ((flags & 0x80) == 0x80)
				std::cout << "M"; // The private component of this key may be in the possession of more than one person.
			std::cout << std::endl;
			std::cout << "INFO: elg_sigtype = 0x" << std::hex << (int)elg_sigtype << std::dec << 
				" elg_pkalgo = " << (int)elg_pkalgo << " elg_hashalgo = " << (int)elg_hashalgo << " elg_hspd.size() = " << elg_hspd.size() << std::endl;
		}
		if (elg_required && ((flags & 0x04) != 0x04))
		{
			std::cerr << "ERROR: ElGamal subkey cannot used to encrypt communications" << std::endl;
			gcry_sexp_release(dsakey);
			return false;
		}
		tmcg_octets_t elg_trailer, elg_left;
		hash.clear();
		if (sigelgV3)
		{
			tmcg_octets_t elg_sigtime_octets;
			CallasDonnerhackeFinneyShawThayerRFC4880::PacketTimeEncode(elg_sigtime, elg_sigtime_octets);
			// The concatenation of the data to be signed, the signature type, and
			// creation time from the Signature packet (5 additional octets) is
			// hashed. The resulting hash value is used in the signature algorithm.
			// The high 16 bits (first two octets) of the hash are included in the
			// Signature packet to provide a quick test to reject some invalid
			// signatures.
			// A V3 signature hashes five octets of the packet body, starting from
			// the signature type field. This data is the signature type, followed
			// by the four-octet signature time.
			elg_trailer.push_back(elg_sigtype);
			elg_trailer.insert(elg_trailer.end(), elg_sigtime_octets.begin(), elg_sigtime_octets.end());
			CallasDonnerhackeFinneyShawThayerRFC4880::SubkeyBindingHashV3(pub_hashing, sub_hashing, elg_trailer, elg_hashalgo, hash, elg_left);
		}
		else
		{
			elg_trailer.push_back(4); // only V4 format supported
			elg_trailer.push_back(elg_sigtype);
			elg_trailer.push_back(elg_pkalgo);
			elg_trailer.push_back(elg_hashalgo);
			elg_trailer.push_back(elg_hspd.size() >> 8); // length of hashed subpacket data
			elg_trailer.push_back(elg_hspd.size());
			elg_trailer.insert(elg_trailer.end(), elg_hspd.begin(), elg_hspd.end());
			CallasDonnerhackeFinneyShawThayerRFC4880::SubkeyBindingHash(pub_hashing, sub_hashing, elg_trailer, elg_hashalgo, hash, elg_left);
		}
		if (opt_verbose)
			std::cout << "INFO: elg_left = " << std::hex << (int)elg_left[0] << " " << (int)elg_left[1] << std::dec << std::endl;
		ret = CallasDonnerhackeFinneyShawThayerRFC4880::AsymmetricVerifyDSA(hash, dsakey, elg_r, elg_s);
		if (ret)
		{
			std::cerr << "ERROR: verification of ElGamal subkey self-signature failed (rc = " << gcry_err_code(ret) << ", str = " <<
				gcry_strerror(ret) <<")" << std::endl;
			gcry_sexp_release(dsakey);
			return false;
		}
		if (revelg)
		{
			if (opt_verbose)
				std::cout << "INFO: revelg_sigtype = 0x" << std::hex << (int)revelg_sigtype << std::dec << 
					" revelg_pkalgo = " << (int)revelg_pkalgo << " revelg_hashalgo = " << (int)revelg_hashalgo <<
					" revelg_hspd.size() = " << revelg_hspd.size() << std::endl;
			tmcg_octets_t revelg_trailer, revelg_left;
			hash.clear();
			if (revelgV3)
			{
				tmcg_octets_t revelg_sigtime_octets;
				CallasDonnerhackeFinneyShawThayerRFC4880::PacketTimeEncode(revelg_sigtime, revelg_sigtime_octets);
				// The concatenation of the data to be signed, the signature type, and
				// creation time from the Signature packet (5 additional octets) is
				// hashed. The resulting hash value is used in the signature algorithm.
				// The high 16 bits (first two octets) of the hash are included in the
				// Signature packet to provide a quick test to reject some invalid
				// signatures.
				// A V3 signature hashes five octets of the packet body, starting from
				// the signature type field. This data is the signature type, followed
				// by the four-octet signature time.
				revelg_trailer.push_back(revelg_sigtype);
				revelg_trailer.insert(revelg_trailer.end(), revelg_sigtime_octets.begin(), revelg_sigtime_octets.end());
				CallasDonnerhackeFinneyShawThayerRFC4880::KeyRevocationHashV3(pub_hashing, sub_hashing, revelg_trailer, revelg_hashalgo, hash, revelg_left);
			}
			else
			{
				revelg_trailer.push_back(4); // only V4 format supported
				revelg_trailer.push_back(revelg_sigtype);
				revelg_trailer.push_back(revelg_pkalgo);
				revelg_trailer.push_back(revelg_hashalgo);
				revelg_trailer.push_back(revelg_hspd.size() >> 8); // length of hashed subpacket data
				revelg_trailer.push_back(revelg_hspd.size());
				revelg_trailer.insert(revelg_trailer.end(), revelg_hspd.begin(), revelg_hspd.end());
				CallasDonnerhackeFinneyShawThayerRFC4880::KeyRevocationHash(pub_hashing, sub_hashing, revelg_trailer, revelg_hashalgo, hash, revelg_left);
			}
			if (opt_verbose)
				std::cout << "INFO: revelg_left = " << std::hex << (int)revelg_left[0] << " " << (int)revelg_left[1] << std::dec << std::endl;
			ret = CallasDonnerhackeFinneyShawThayerRFC4880::AsymmetricVerifyDSA(hash, dsakey, revelg_r, revelg_s);
			gcry_sexp_release(dsakey);
			if (ret)
			{
				std::cerr << "ERROR: verification of subkey revocation signature failed (rc = " << gcry_err_code(ret) << ", str = " <<
					gcry_strerror(ret) << ")" << std::endl;
				return false;
			}
			else
			{
				if (elg_required)
				{
					std::cerr << "ERROR: valid revocation signature on subkey found" << std::endl;
					return false;
				}
				else
					std::cerr << "WARNING: valid revocation signature on subkey found" << std::endl;
			}
		}
	}
	gcry_sexp_release(dsakey);
	return true;
}

bool parse_private_key
	(const std::string &in, time_t &keycreationtime_out, time_t &keyexpirationtime_out, std::vector<std::string> &capl_out)
{
	// decode ASCII Armor
	tmcg_octets_t pkts;
	tmcg_armor_t atype = CallasDonnerhackeFinneyShawThayerRFC4880::ArmorDecode(in, pkts);
	if (opt_verbose)
		std::cout << "ArmorDecode() = " << (int)atype << " with " << pkts.size() << " bytes" << std::endl;
	if (atype != TMCG_OPENPGP_ARMOR_PRIVATE_KEY_BLOCK)
	{
		std::cerr << "ERROR: wrong type of ASCII Armor found" << std::endl;
		return false;
	}
	// parse the private key according to OpenPGP
	bool secdsa = false, sigdsa = false, ssbelg = false, sigelg = false;
	tmcg_byte_t ptag = 0xFF;
	tmcg_byte_t dsa_sigtype, dsa_pkalgo, dsa_hashalgo, dsa_keyflags[32], elg_sigtype, elg_pkalgo, elg_hashalgo, elg_keyflags[32];
	tmcg_byte_t dsa_psa[255], dsa_pha[255], dsa_pca[255], elg_psa[255], elg_pha[255], elg_pca[255];
	tmcg_byte_t *key, *iv;
	tmcg_octets_t seskey, salt, mpis, hash_input, hash, pub_hashing, sub_hashing, issuer, dsa_hspd, elg_hspd;
	gcry_cipher_hd_t hd;
	gcry_error_t ret;
	size_t erroff, keylen, ivlen, chksum, mlen, chksum2;
	int algo;
	tmcg_openpgp_packet_ctx ctx;
	std::vector<gcry_mpi_t> qual, v_i, x_rvss_qual;
	std::vector<std::string> capl;
	std::vector< std::vector<gcry_mpi_t> > c_ik;
	while (pkts.size() && ptag)
	{
		tmcg_octets_t current_packet;
		ptag = CallasDonnerhackeFinneyShawThayerRFC4880::PacketDecode(pkts, ctx, current_packet, qual, x_rvss_qual, capl, v_i, c_ik);
		if (opt_verbose)
			std::cout << "PacketDecode(pkts.size = " << pkts.size() << ") = " << (int)ptag;
		if (!ptag)
		{
			std::cerr << "ERROR: parsing OpenPGP packets failed at position " << pkts.size() << std::endl;
			cleanup_ctx(ctx);
			cleanup_containers(qual, v_i, x_rvss_qual, c_ik);
			return false; // error detected
		}
		if (opt_verbose)
			std::cout << " tag = " << (int)ptag << " version = " << (int)ctx.version << std::endl;
		switch (ptag)
		{
			case 2: // Signature Packet
				issuer.clear();
				if (opt_verbose)
					std::cout << " issuer = " << std::hex;
				for (size_t i = 0; i < sizeof(ctx.issuer); i++)
				{
					if (opt_verbose)
						std::cout << (int)ctx.issuer[i] << " ";
					issuer.push_back(ctx.issuer[i]);
				}
				if (opt_verbose)
					std::cout << std::dec << std::endl;
				if (secdsa && !ssbelg && (ctx.type >= 0x10) && (ctx.type <= 0x13) &&
					CallasDonnerhackeFinneyShawThayerRFC4880::OctetsCompare(keyid, issuer))
				{
					if (opt_verbose)
					{
						std::cout << std::hex;
						std::cout << " sigtype = 0x";
						std::cout << (int)ctx.type;
						std::cout << std::dec;
						std::cout << " pkalgo = ";
						std::cout << (int)ctx.pkalgo;
						std::cout << " hashalgo = ";
						std::cout << (int)ctx.hashalgo;
						std::cout << std::endl;
					}
					if (sigdsa)
						std::cerr << "WARNING: more than one self-signatures; using last signature to check UID" << std::endl;
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
					if (dsa_pkalgo != 17)
					{
						std::cerr << "ERROR: public-key signature algorithms other than DSA not supported" << std::endl;
						cleanup_ctx(ctx);
						cleanup_containers(qual, v_i, x_rvss_qual, c_ik);
						return false;
					}
					gcry_mpi_set(dsa_r, ctx.r);
					gcry_mpi_set(dsa_s, ctx.s);
					if ((dsa_hashalgo < 8) || (dsa_hashalgo >= 11))
						std::cerr << "WARNING: insecure hash algorithm " << (int)dsa_hashalgo << 
							" used for signatures" << std::endl;
					sigdsa = true;
					// store the whole packet
					uidsig.clear();
					for (size_t i = 0; i < current_packet.size(); i++)
						uidsig.push_back(current_packet[i]);
				}
				else if (secdsa && ssbelg && (ctx.type == 0x18) && 
					CallasDonnerhackeFinneyShawThayerRFC4880::OctetsCompare(keyid, issuer))
				{
					if (opt_verbose)
					{
						std::cout << std::hex;
						std::cout << " sigtype = 0x";
						std::cout << (int)ctx.type;
						std::cout << std::dec;
						std::cout << " pkalgo = ";
						std::cout << (int)ctx.pkalgo;
						std::cout << " hashalgo = ";
						std::cout << (int)ctx.hashalgo;
						std::cout << std::endl;
					}
					if (sigelg)
						std::cerr << "WARNING: more than one subkey binding signature; using last signature" << std::endl;
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
					if (elg_pkalgo != 17)
					{
						std::cerr << "ERROR: public-key signature algorithms other than DSA not supported" << std::endl;
						cleanup_ctx(ctx);
						cleanup_containers(qual, v_i, x_rvss_qual, c_ik);
						return false;
					}
					gcry_mpi_set(elg_r, ctx.r);
					gcry_mpi_set(elg_s, ctx.s);
					if ((elg_hashalgo < 8) || (elg_hashalgo >= 11))
						std::cerr << "WARNING: insecure hash algorithm " << (int)elg_hashalgo << 
							" used for signatures" << std::endl;
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
					CallasDonnerhackeFinneyShawThayerRFC4880::PacketPubEncode(ctx.keycreationtime, 17, // public-key is DSA 
						dsa_p, dsa_q, dsa_g, dsa_y, pub);
					pub_hashing.clear();
					for (size_t i = 6; i < pub.size(); i++)
						pub_hashing.push_back(pub[i]);
					keyid.clear();
					CallasDonnerhackeFinneyShawThayerRFC4880::KeyidCompute(pub_hashing, keyid);
					if (opt_verbose)
					{
						std::cout << " Key ID of tDSS key: " << std::hex;
						for (size_t i = 0; i < keyid.size(); i++)
							std::cout << (int)keyid[i] << " ";
						std::cout << std::dec << std::endl;
						std::cout << " encdatalen = " << ctx.encdatalen << std::endl;
						std::cout << " symalgo = " << (int)ctx.symalgo << std::endl;
						std::cout << " S2K: convention = " << (int)ctx.s2kconv << " type = " << (int)ctx.s2k_type;
						std::cout << " hashalgo = " << (int)ctx.s2k_hashalgo << " count = " << (int)ctx.s2k_count;
						std::cout << std::endl;
					}
					if (!mpz_set_gcry_mpi(ctx.p, dss_p))
					{
						std::cerr << "ERROR: mpz_set_gcry_mpi() failed for dss_p" << std::endl;
						cleanup_ctx(ctx);
						cleanup_containers(qual, v_i, x_rvss_qual, c_ik);
						return false;
					}
					if (!mpz_set_gcry_mpi(ctx.q, dss_q))
					{
						std::cerr << "ERROR: mpz_set_gcry_mpi() failed for dss_q" << std::endl;
						cleanup_ctx(ctx);
						cleanup_containers(qual, v_i, x_rvss_qual, c_ik);
						return false;
					}
					if (!mpz_set_gcry_mpi(ctx.g, dss_g))
					{
						std::cerr << "ERROR: mpz_set_gcry_mpi() failed for dss_g" << std::endl;
						cleanup_ctx(ctx);
						cleanup_containers(qual, v_i, x_rvss_qual, c_ik);
						return false;
					}
					if (!mpz_set_gcry_mpi(ctx.h, dss_h))
					{
						std::cerr << "ERROR: mpz_set_gcry_mpi() failed for dss_h" << std::endl;
						cleanup_ctx(ctx);
						cleanup_containers(qual, v_i, x_rvss_qual, c_ik);
						return false;
					}
					if (!mpz_set_gcry_mpi(ctx.y, dss_y))
					{
						std::cerr << "ERROR: mpz_set_gcry_mpi() failed for dss_y" << std::endl;
						cleanup_ctx(ctx);
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
								cleanup_ctx(ctx);
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
							cleanup_ctx(ctx);
							cleanup_containers(qual, v_i, x_rvss_qual, c_ik);
							return false;
						}
						if (!mpz_set_gcry_mpi(ctx.xprime_i, dss_xprime_i))
						{
							std::cerr << "ERROR: mpz_set_gcry_mpi() failed for dss_xprime_i" << std::endl;
							cleanup_ctx(ctx);
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
							cleanup_ctx(ctx);
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
							cleanup_ctx(ctx);
							cleanup_containers(qual, v_i, x_rvss_qual, c_ik);
							return false;
						}
						if (seskey.size() != keylen)
						{
							std::cerr << "ERROR: S2K failed" << std::endl;
							cleanup_ctx(ctx);
							cleanup_containers(qual, v_i, x_rvss_qual, c_ik);
							return false;
						}
						if (!ctx.encdatalen || !ctx.encdata)
						{
							std::cerr << "ERROR: nothing to decrypt" << std::endl;
							cleanup_ctx(ctx);
							cleanup_containers(qual, v_i, x_rvss_qual, c_ik);
							return false;
						}
						key = new tmcg_byte_t[keylen];
						for (size_t i = 0; i < keylen; i++)
							key[i] = seskey[i];
						iv = new tmcg_byte_t[ivlen];
						for (size_t i = 0; i < ivlen; i++)
							iv[i] = ctx.iv[i];
						ret = gcry_cipher_open(&hd, algo, GCRY_CIPHER_MODE_CFB, 0);
						if (ret)
						{
							std::cerr << "ERROR: gcry_cipher_open() failed" << std::endl;
							delete [] key;
							delete [] iv;
							cleanup_ctx(ctx);
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
							cleanup_ctx(ctx);
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
							cleanup_ctx(ctx);
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
							cleanup_ctx(ctx);
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
							cleanup_ctx(ctx);
							cleanup_containers(qual, v_i, x_rvss_qual, c_ik);
							return false;
						}
						mpis.erase(mpis.begin(), mpis.begin()+mlen);
						if (!mpz_set_gcry_mpi(dsa_x, dss_x_i))
						{
							std::cerr << "ERROR: mpz_set_gcry_mpi() failed for dss_x_i" << std::endl;
							cleanup_ctx(ctx);
							cleanup_containers(qual, v_i, x_rvss_qual, c_ik);
							return false;
						}
						mlen = CallasDonnerhackeFinneyShawThayerRFC4880::PacketMPIDecode(mpis, dsa_x, chksum);
						if (!mlen || (mlen > mpis.size()))
						{
							std::cerr << "ERROR: reading MPI xprime_i failed (bad passphrase)" << std::endl;
							cleanup_ctx(ctx);
							cleanup_containers(qual, v_i, x_rvss_qual, c_ik);
							return false;
						}
						mpis.erase(mpis.begin(), mpis.begin()+mlen);
						if (!mpz_set_gcry_mpi(dsa_x, dss_xprime_i))
						{
							std::cerr << "ERROR: mpz_set_gcry_mpi() failed for dss_xprime_i" << std::endl;
							cleanup_ctx(ctx);
							cleanup_containers(qual, v_i, x_rvss_qual, c_ik);
							return false;
						}
						if (ctx.s2kconv == 255)
						{
							if (mpis.size() < 2)
							{
								std::cerr << "ERROR: no checksum found" << std::endl;
								cleanup_ctx(ctx);
								cleanup_containers(qual, v_i, x_rvss_qual, c_ik);
								return false;
							}
							chksum2 = (mpis[0] << 8) + mpis[1];
							if (chksum != chksum2)
							{
								std::cerr << "ERROR: checksum mismatch" << std::endl;
								cleanup_ctx(ctx);
								cleanup_containers(qual, v_i, x_rvss_qual, c_ik);
								return false;
							}
						}
						else
						{
							if ((mpis.size() != 20) || (ctx.encdatalen < 20))
							{
								std::cerr << "ERROR: no SHA-1 hash found" << std::endl;
								cleanup_ctx(ctx);
								cleanup_containers(qual, v_i, x_rvss_qual, c_ik);
								return false;
							}
							hash_input.clear(), hash.clear();
							for (size_t i = 0; i < (ctx.encdatalen - 20); i++)
								hash_input.push_back(ctx.encdata[i]);
							CallasDonnerhackeFinneyShawThayerRFC4880::HashCompute(2, hash_input, hash);
							if (!CallasDonnerhackeFinneyShawThayerRFC4880::OctetsCompare(hash, mpis))
							{
								std::cerr << "ERROR: SHA-1 hash mismatch" << std::endl;
								cleanup_ctx(ctx);
								cleanup_containers(qual, v_i, x_rvss_qual, c_ik);
								return false;
							}
						}
					}
					else
					{
						std::cerr << "ERROR: S2K format not supported" << std::endl;
						cleanup_ctx(ctx);
						cleanup_containers(qual, v_i, x_rvss_qual, c_ik);
						return false;
					}
					// create one-to-one mapping based on the stored canonicalized peer list
					idx2dkg.clear(), dkg2idx.clear();
					if ((ctx.pkalgo == 107) && (capl.size() != dss_n))
					{
						std::cerr << "ERROR: tDSS parameter n and CAPL size does not match" << std::endl;
						cleanup_ctx(ctx);
						cleanup_containers(qual, v_i, x_rvss_qual, c_ik);
						return false;
					}
					else if ((ctx.pkalgo == 108) && (capl.size() != dss_qual.size()))
					{
						std::cerr << "ERROR: QUAL size of tDSS key and CAPL does not match" << std::endl;
						cleanup_ctx(ctx);
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
									std::cout << "INFO: mapping " << i << " -> P_" << j << std::endl; 
								break;
							}
						}
						if (!found)
						{
							std::cerr << "ERROR: peer \"" << peers[i] <<
								"\" not found inside CAPL from tDSS key" << std::endl;
							cleanup_ctx(ctx);
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
				else if ((ctx.pkalgo == 17) && !secdsa)
				{
					secdsa = true;
					keycreationtime_out = ctx.keycreationtime;
					gcry_mpi_set(dsa_p, ctx.p);
					gcry_mpi_set(dsa_q, ctx.q);
					gcry_mpi_set(dsa_g, ctx.g);
					gcry_mpi_set(dsa_y, ctx.y);
					pub.clear();
					CallasDonnerhackeFinneyShawThayerRFC4880::PacketPubEncode(ctx.keycreationtime, 17, // public-key is DSA 
						dsa_p, dsa_q, dsa_g, dsa_y, pub);
					pub_hashing.clear();
					for (size_t i = 6; i < pub.size(); i++)
						pub_hashing.push_back(pub[i]);
					keyid.clear();
					CallasDonnerhackeFinneyShawThayerRFC4880::KeyidCompute(pub_hashing, keyid);
					if (opt_verbose)
					{
						std::cout << " Key ID of DSA key: " << std::hex;
						for (size_t i = 0; i < keyid.size(); i++)
							std::cout << (int)keyid[i] << " ";
						std::cout << std::dec << std::endl;
						std::cout << " encdatalen = " << ctx.encdatalen << std::endl;
						std::cout << " symalgo = " << (int)ctx.symalgo << std::endl;
						std::cout << " S2K: convention = " << (int)ctx.s2kconv << " type = " << (int)ctx.s2k_type;
						std::cout << " hashalgo = " << (int)ctx.s2k_hashalgo << " count = " << (int)ctx.s2k_count;
						std::cout << std::endl;
					}
					if (!mpz_set_gcry_mpi(ctx.p, dss_p))
					{
						std::cerr << "ERROR: mpz_set_gcry_mpi() failed for dss_p" << std::endl;
						cleanup_ctx(ctx);
						cleanup_containers(qual, v_i, x_rvss_qual, c_ik);
						return false;
					}
					if (!mpz_set_gcry_mpi(ctx.q, dss_q))
					{
						std::cerr << "ERROR: mpz_set_gcry_mpi() failed for dss_q" << std::endl;
						cleanup_ctx(ctx);
						cleanup_containers(qual, v_i, x_rvss_qual, c_ik);
						return false;
					}
					if (!mpz_set_gcry_mpi(ctx.g, dss_g))
					{
						std::cerr << "ERROR: mpz_set_gcry_mpi() failed for dss_g" << std::endl;
						cleanup_ctx(ctx);
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
							cleanup_ctx(ctx);
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
							cleanup_ctx(ctx);
							cleanup_containers(qual, v_i, x_rvss_qual, c_ik);
							return false;
						}
						if (seskey.size() != keylen)
						{
							std::cerr << "ERROR: S2K failed" << std::endl;
							cleanup_ctx(ctx);
							cleanup_containers(qual, v_i, x_rvss_qual, c_ik);
							return false;
						}
						if (!ctx.encdatalen || !ctx.encdata)
						{
							std::cerr << "ERROR: nothing to decrypt" << std::endl;
							cleanup_ctx(ctx);
							cleanup_containers(qual, v_i, x_rvss_qual, c_ik);
							return false;
						}
						key = new tmcg_byte_t[keylen];
						for (size_t i = 0; i < keylen; i++)
							key[i] = seskey[i];
						iv = new tmcg_byte_t[ivlen];
						for (size_t i = 0; i < ivlen; i++)
							iv[i] = ctx.iv[i];
						ret = gcry_cipher_open(&hd, algo, GCRY_CIPHER_MODE_CFB, 0);
						if (ret)
						{
							std::cerr << "ERROR: gcry_cipher_open() failed" << std::endl;
							delete [] key;
							delete [] iv;
							cleanup_ctx(ctx);
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
							cleanup_ctx(ctx);
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
							cleanup_ctx(ctx);
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
							cleanup_ctx(ctx);
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
							cleanup_ctx(ctx);
							cleanup_containers(qual, v_i, x_rvss_qual, c_ik);
							return false;
						}
						mpis.erase(mpis.begin(), mpis.begin()+mlen);
						if (ctx.s2kconv == 255)
						{
							if (mpis.size() < 2)
							{
								std::cerr << "ERROR: no checksum found" << std::endl;
								cleanup_ctx(ctx);
								cleanup_containers(qual, v_i, x_rvss_qual, c_ik);
								return false;
							}
							chksum2 = (mpis[0] << 8) + mpis[1];
							if (chksum != chksum2)
							{
								std::cerr << "ERROR: checksum mismatch" << std::endl;
								cleanup_ctx(ctx);
								cleanup_containers(qual, v_i, x_rvss_qual, c_ik);
								return false;
							}
						}
						else
						{
							if ((mpis.size() != 20) || (ctx.encdatalen < 20))
							{
								std::cerr << "ERROR: no SHA-1 hash found" << std::endl;
								cleanup_ctx(ctx);
								cleanup_containers(qual, v_i, x_rvss_qual, c_ik);
								return false;
							}
							hash_input.clear(), hash.clear();
							for (size_t i = 0; i < (ctx.encdatalen - 20); i++)
								hash_input.push_back(ctx.encdata[i]);
							CallasDonnerhackeFinneyShawThayerRFC4880::HashCompute(2, hash_input, hash);
							if (!CallasDonnerhackeFinneyShawThayerRFC4880::OctetsCompare(hash, mpis))
							{
								std::cerr << "ERROR: SHA-1 hash mismatch" << std::endl;
								cleanup_ctx(ctx);
								cleanup_containers(qual, v_i, x_rvss_qual, c_ik);
								return false;
							}
						}
					}
					else
					{
						std::cerr << "ERROR: S2K format not supported" << std::endl;
						cleanup_ctx(ctx);
						cleanup_containers(qual, v_i, x_rvss_qual, c_ik);
						return false;
					}
					// store the whole packet
					sec.clear();
					for (size_t i = 0; i < current_packet.size(); i++)
						sec.push_back(current_packet[i]);
				}
				else if (((ctx.pkalgo == 108) || (ctx.pkalgo == 17)) && secdsa)
				{
					std::cerr << "ERROR: more than one primary key not supported" << std::endl;
					cleanup_ctx(ctx);
					cleanup_containers(qual, v_i, x_rvss_qual, c_ik);
					return false;
				}
				else
					std::cerr << "WARNING: public-key algorithm not supported; packet ignored" << std::endl;
				break;
			case 13: // User ID Packet
				if (opt_verbose)
					std::cout << " uid = " << ctx.uid << std::endl;
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
					CallasDonnerhackeFinneyShawThayerRFC4880::PacketSubEncode(ctx.keycreationtime, 16, // public-key is ElGamal 
						elg_p, dsa_q, elg_g, elg_y, sub);
					sub_hashing.clear();
					for (size_t i = 6; i < sub.size(); i++)
						sub_hashing.push_back(sub[i]);
					subkeyid.clear();
					CallasDonnerhackeFinneyShawThayerRFC4880::KeyidCompute(sub_hashing, subkeyid);
					if (opt_verbose)
					{
						std::cout << "Key ID of ElGamal subkey: " << std::hex;
						for (size_t i = 0; i < subkeyid.size(); i++)
							std::cout << (int)subkeyid[i] << " ";
						std::cout << std::dec << std::endl;
						std::cout << " symalgo = " << (int)ctx.symalgo << std::endl;
						std::cout << " encdatalen = " << ctx.encdatalen << std::endl;
						std::cout << " S2K: convention = " << (int)ctx.s2kconv << " type = " << (int)ctx.s2k_type;
						std::cout << " hashalgo = " << (int)ctx.s2k_hashalgo << " count = " << (int)ctx.s2k_count;
						std::cout << std::endl;
					}
					if (!mpz_set_gcry_mpi(ctx.p, dkg_p))
					{
						std::cerr << "ERROR: converting key component dkg_p failed" << std::endl;
						cleanup_ctx(ctx);
						cleanup_containers(qual, v_i, x_rvss_qual, c_ik);
						return false;
					}
					if (!mpz_set_gcry_mpi(ctx.q, dkg_q))
					{
						std::cerr << "ERROR: converting key component dkg_q failed" << std::endl;
						cleanup_ctx(ctx);
						cleanup_containers(qual, v_i, x_rvss_qual, c_ik);
						return false;
					}
					if (!mpz_set_gcry_mpi(ctx.g, dkg_g))
					{
						std::cerr << "ERROR: converting key component dkg_g failed" << std::endl;
						cleanup_ctx(ctx);
						cleanup_containers(qual, v_i, x_rvss_qual, c_ik);
						return false;
					}
					if (!mpz_set_gcry_mpi(ctx.h, dkg_h))
					{
						std::cerr << "ERROR: converting key component dkg_h failed" << std::endl;
						cleanup_ctx(ctx);
						cleanup_containers(qual, v_i, x_rvss_qual, c_ik);
						return false;
					}
					if (!mpz_set_gcry_mpi(ctx.y, dkg_y))
					{
						std::cerr << "ERROR: converting key component dkg_y failed" << std::endl;
						cleanup_ctx(ctx);
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
							cleanup_ctx(ctx);
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
								cleanup_ctx(ctx);
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
							cleanup_ctx(ctx);
							cleanup_containers(qual, v_i, x_rvss_qual, c_ik);
							return false;
						}
						if (!mpz_set_gcry_mpi(ctx.xprime_i, dkg_xprime_i))
						{
							std::cerr << "ERROR: converting key component dkg_xprime_i failed" << std::endl;
							cleanup_ctx(ctx);
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
							cleanup_ctx(ctx);
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
							cleanup_ctx(ctx);
							cleanup_containers(qual, v_i, x_rvss_qual, c_ik);
							return false;
						}
						if (seskey.size() != keylen)
						{
							std::cerr << "ERROR: S2K failed" << std::endl;
							cleanup_ctx(ctx);
							cleanup_containers(qual, v_i, x_rvss_qual, c_ik);
							return false;
						}
						if (!ctx.encdatalen || !ctx.encdata)
						{
							std::cerr << "ERROR: nothing to decrypt" << std::endl;
							cleanup_ctx(ctx);
							cleanup_containers(qual, v_i, x_rvss_qual, c_ik);
							return false;
						}
						key = new tmcg_byte_t[keylen];
						for (size_t i = 0; i < keylen; i++)
							key[i] = seskey[i];
						iv = new tmcg_byte_t[ivlen];
						for (size_t i = 0; i < ivlen; i++)
							iv[i] = ctx.iv[i];
						ret = gcry_cipher_open(&hd, (int)ctx.symalgo, GCRY_CIPHER_MODE_CFB, 0);
						if (ret)
						{
							std::cerr << "ERROR: gcry_cipher_open() failed" << std::endl;
							delete [] key;
							delete [] iv;
							cleanup_ctx(ctx);
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
							cleanup_ctx(ctx);
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
							cleanup_ctx(ctx);
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
							cleanup_ctx(ctx);
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
							cleanup_ctx(ctx);
							cleanup_containers(qual, v_i, x_rvss_qual, c_ik);
							return false;
						}
						mpis.erase(mpis.begin(), mpis.begin()+mlen);
 						if (!mpz_set_gcry_mpi(elg_x, dkg_x_i))
						{
							std::cerr << "ERROR: converting key component dkg_x_i failed" << std::endl;
							cleanup_ctx(ctx);
							cleanup_containers(qual, v_i, x_rvss_qual, c_ik);
							return false;
						}
						mlen = CallasDonnerhackeFinneyShawThayerRFC4880::PacketMPIDecode(mpis, elg_x, chksum);
						if (!mlen || (mlen > mpis.size()))
						{
							std::cerr << "ERROR: reading MPI xprime_i failed (bad passphrase)" << std::endl;
							cleanup_ctx(ctx);
							cleanup_containers(qual, v_i, x_rvss_qual, c_ik);
							return false;
						}
						mpis.erase(mpis.begin(), mpis.begin()+mlen);
						if (!mpz_set_gcry_mpi(elg_x, dkg_xprime_i))
						{
							std::cerr << "ERROR: converting key component dkg_xprime_i failed" << std::endl;
							cleanup_ctx(ctx);
							cleanup_containers(qual, v_i, x_rvss_qual, c_ik);
							return false;
						}
						if (ctx.s2kconv == 255)
						{
							if (mpis.size() < 2)
							{
								std::cerr << "ERROR: no checksum found" << std::endl;
								cleanup_ctx(ctx);
								cleanup_containers(qual, v_i, x_rvss_qual, c_ik);
								return false;
							}
							chksum2 = (mpis[0] << 8) + mpis[1];
							if (chksum != chksum2)
							{
								std::cerr << "ERROR: checksum mismatch" << std::endl;
								cleanup_ctx(ctx);
								cleanup_containers(qual, v_i, x_rvss_qual, c_ik);
								return false;
							}
						}
						else
						{
							if ((mpis.size() != 20) || (ctx.encdatalen < 20))
							{
								std::cerr << "ERROR: no SHA-1 hash found" << std::endl;
								cleanup_ctx(ctx);
								cleanup_containers(qual, v_i, x_rvss_qual, c_ik);
								return false;
							}
							hash_input.clear(), hash.clear();
							for (size_t i = 0; i < (ctx.encdatalen - 20); i++)
								hash_input.push_back(ctx.encdata[i]);
							CallasDonnerhackeFinneyShawThayerRFC4880::HashCompute(2, hash_input, hash);
							if (!CallasDonnerhackeFinneyShawThayerRFC4880::OctetsCompare(hash, mpis))
							{
								std::cerr << "ERROR: SHA-1 hash mismatch" << std::endl;
								cleanup_ctx(ctx);
								cleanup_containers(qual, v_i, x_rvss_qual, c_ik);
								return false;
							}
						}
					}
					else
					{
						std::cerr << "ERROR: S2K format not supported" << std::endl;
						cleanup_ctx(ctx);
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
		cleanup_ctx(ctx);
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
	tmcg_octets_t dsa_trailer, elg_trailer, dsa_left, elg_left;
	if (opt_verbose)
		std::cout << "Primary User ID: " << userid << std::endl;
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
		std::cout << "tDSS/DSA key flags: ";
		if ((flags & 0x01) == 0x01)
			std::cout << "C"; // The key may be used to certify other keys.
		if ((flags & 0x02) == 0x02)
			std::cout << "S"; // The key may be used to sign data.
		if ((flags & 0x04) == 0x04)
			std::cout << "E"; // The key may be used encrypt communications.
		if ((flags & 0x08) == 0x08)
			std::cout << "e"; // The key may be used encrypt storage.
		if ((flags & 0x10) == 0x10)
			std::cout << "D"; // The private component of this key may have been split by a secret-sharing mechanism.		
		if ((flags & 0x20) == 0x20)
			std::cout << "A"; // The key may be used for authentication.
		if ((flags & 0x80) == 0x80)
			std::cout << "M"; // The private component of this key may be in the possession of more than one person.
		std::cout << std::endl;
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
	CallasDonnerhackeFinneyShawThayerRFC4880::CertificationHash(pub_hashing, userid, dsa_trailer, dsa_hashalgo, hash, dsa_left);
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
			std::cout << "ElGamal key flags: ";
			if ((flags & 0x01) == 0x01)
				std::cout << "C"; // The key may be used to certify other keys.
			if ((flags & 0x02) == 0x02)
				std::cout << "S"; // The key may be used to sign data.
			if ((flags & 0x04) == 0x04)
				std::cout << "E"; // The key may be used encrypt communications.
			if ((flags & 0x08) == 0x08)
				std::cout << "e"; // The key may be used encrypt storage.
			if ((flags & 0x10) == 0x10)
				std::cout << "D"; // The private component of this key may have been split by a secret-sharing mechanism.
			if ((flags & 0x20) == 0x20)
				std::cout << "A"; // The key may be used for authentication.
			if ((flags & 0x80) == 0x80)
				std::cout << "M"; // The private component of this key may be in the possession of more than one person.
			std::cout << std::endl;
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
		CallasDonnerhackeFinneyShawThayerRFC4880::SubkeyBindingHash(pub_hashing, sub_hashing, elg_trailer, elg_hashalgo, hash, elg_left);
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

bool parse_public_key_for_certification
	(const std::string &in, time_t &keycreationtime_out, time_t &keyexpirationtime_out)
{
	// decode ASCII Armor
	tmcg_octets_t pkts;
	tmcg_armor_t atype = CallasDonnerhackeFinneyShawThayerRFC4880::ArmorDecode(in, pkts);
	if (opt_verbose)
		std::cout << "ArmorDecode() = " << (int)atype << " with " << pkts.size() << " bytes" << std::endl;
	if (atype != TMCG_OPENPGP_ARMOR_PUBLIC_KEY_BLOCK)
	{
		std::cerr << "ERROR: wrong type of ASCII Armor found (type = " << (int)atype << ")" << std::endl;
		return false;
	}
	// parse the public key according to OpenPGP
	bool primary = false, sig = false, sigV3 = false, uid_flag = false, uat_flag = false, rev = false, revV3 = false;
	tmcg_byte_t ptag = 0xFF;
	tmcg_byte_t sigtype, pkalgo, hashalgo, keyflags[4], rev_sigtype, rev_pkalgo, rev_hashalgo;
	tmcg_octets_t pub_hashing, issuer, hspd, rev_hspd;
	time_t creation = 0, sigtime = 0, rev_sigtime = 0;
	size_t erroff, pnum = 0;
	while (pkts.size() && ptag)
	{
		tmcg_openpgp_packet_ctx ctx;
		tmcg_octets_t current_packet;
		std::vector<gcry_mpi_t> qual, v_i;
		std::vector<std::string> capl;
		std::vector< std::vector<gcry_mpi_t> > c_ik;
		ptag = CallasDonnerhackeFinneyShawThayerRFC4880::PacketDecode(pkts, ctx, current_packet, qual, capl, v_i, c_ik);
		++pnum;
		if (opt_verbose)
			std::cout << "PacketDecode() = " << (int)ptag << " version = " << (int)ctx.version << std::endl;
		if (ptag == 0x00)
		{
			std::cerr << "ERROR: parsing OpenPGP packets failed at #" << pnum << " and position " << pkts.size() << std::endl;
			cleanup_ctx(ctx);
			cleanup_containers(qual, v_i, c_ik);
			return false; // parsing error detected
		}
		else if (ptag == 0xFE)
		{
			std::cerr << "WARNING: unrecognized OpenPGP packet found at #" << pnum << " and position " << pkts.size() << std::endl;
			cleanup_ctx(ctx);
			cleanup_containers(qual, v_i, c_ik);
			continue; // ignore packet
		}
		switch (ptag)
		{
			case 2: // Signature Packet
				issuer.clear();
				for (size_t i = 0; i < sizeof(ctx.issuer); i++)
					issuer.push_back(ctx.issuer[i]);
				if (primary && !uid_flag && !uat_flag && (ctx.type >= 0x10) && (ctx.type <= 0x13) && 
					CallasDonnerhackeFinneyShawThayerRFC4880::OctetsCompare(keyid, issuer))
				{
					std::cerr << "ERROR: no uid/uat found for this self-signature" << std::endl;
					cleanup_ctx(ctx);
					cleanup_containers(qual, v_i, c_ik);
					return false;
				}
				else if (primary && uid_flag && !uat_flag && (ctx.type >= 0x10) && (ctx.type <= 0x13) && 
					CallasDonnerhackeFinneyShawThayerRFC4880::OctetsCompare(keyid, issuer))
				{
					if (ctx.version == 3)
					{
						std::cerr << "WARNING: V3 signature packet detected; verification may fail" << std::endl;
						sigV3 = true;
						sigtime = ctx.sigcreationtime;
					}
					if (sig)
						std::cerr << "WARNING: more than one self-signatures; using last signature to check key" << std::endl;
					sig = true;
					// store the whole packet
					uidsig.clear();
					for (size_t i = 0; i < current_packet.size(); i++)
						uidsig.push_back(current_packet[i]);
					// evaluate the content
					sigtype = ctx.type;
					pkalgo = ctx.pkalgo;
					hashalgo = ctx.hashalgo;
					keyexpirationtime_out = ctx.keyexpirationtime;
					for (size_t i = 0; i < sizeof(keyflags); i++)
						keyflags[i] = ctx.keyflags[i];
					hspd.clear();
					if (opt_verbose)
						std::cout << "INFO: hspd = " << std::hex;
					for (size_t i = 0; i < ctx.hspdlen; i++)
					{
						hspd.push_back(ctx.hspd[i]);
						if (opt_verbose)
							std::cout << (int)ctx.hspd[i] << " ";
					}
					if (opt_verbose)
						std::cout << std::dec << std::endl << "INFO: hspd.size() = " << hspd.size() << std::endl;
					if ((ctx.pkalgo == 1) || (ctx.pkalgo == 3))
					{
						gcry_mpi_set(rsa_md, ctx.md);
						unsigned int mdbits = 0;
						mdbits = gcry_mpi_get_nbits(rsa_md);
						if (opt_verbose)
							std::cout << "INFO: mdbits = " << mdbits << std::endl;
					}
					else if (ctx.pkalgo == 17)
					{
						gcry_mpi_set(dsa_r, ctx.r);
						gcry_mpi_set(dsa_s, ctx.s);
						unsigned int rbits = 0, sbits = 0;
						rbits = gcry_mpi_get_nbits(dsa_r);
						sbits = gcry_mpi_get_nbits(dsa_s);
						if (opt_verbose)
							std::cout << "INFO: rbits = " << rbits << " sbits = " << sbits << std::endl;
					}
					else
					{
						std::cerr << "ERROR: public-key signature algorithm " << (int)ctx.pkalgo << " not supported" << std::endl;
						cleanup_ctx(ctx);
						cleanup_containers(qual, v_i, c_ik);
						return false;
					}	
					if ((ctx.hashalgo < 8) || (ctx.hashalgo >= 11))
						std::cerr << "WARNING: insecure hash algorithm " << (int)ctx.hashalgo << " used for signatures" << std::endl;
					time_t kmax = creation + ctx.keyexpirationtime;
					if (ctx.keyexpirationtime && (time(NULL) > kmax))
						std::cerr << "WARNING: primary key is expired" << std::endl;
				}
				else if (primary && !uid_flag && uat_flag && (ctx.type >= 0x10) && (ctx.type <= 0x13) && 
					CallasDonnerhackeFinneyShawThayerRFC4880::OctetsCompare(keyid, issuer))
				{
					std::cerr << "WARNING: ignore self-signature for a user attribute" << std::endl;
				}
				else if (primary && (ctx.type == 0x20) && // Key revocation signature 
					CallasDonnerhackeFinneyShawThayerRFC4880::OctetsCompare(keyid, issuer))
				{
					std::cerr << "WARNING: key revocation signature on primary key" << std::endl;
					rev = true;
					rev_sigtype = ctx.type;
					rev_pkalgo = ctx.pkalgo;
					rev_hashalgo = ctx.hashalgo;
					if (ctx.version == 3)
					{
						std::cerr << "WARNING: V3 signature packet detected; verification may fail" << std::endl;
						revV3 = true;
						rev_sigtime = ctx.sigcreationtime;
					}
					else
					{
						rev_hspd.clear();
						for (size_t i = 0; i < ctx.hspdlen; i++)
							rev_hspd.push_back(ctx.hspd[i]);
					}
					if (opt_verbose)
						std::cout << "INFO: rev_hspd.size() = " << rev_hspd.size() << std::endl;
					if ((ctx.pkalgo == 1) || (ctx.pkalgo == 3))
					{
						gcry_mpi_set(revrsa_md, ctx.md);
						unsigned int mdbits = 0;
						mdbits = gcry_mpi_get_nbits(revrsa_md);
						if (opt_verbose)
							std::cout << "INFO: mdbits = " << mdbits << std::endl;
					}
					else if (ctx.pkalgo == 17)
					{
						gcry_mpi_set(revdsa_r, ctx.r);
						gcry_mpi_set(revdsa_s, ctx.s);
						unsigned int rbits = 0, sbits = 0;
						rbits = gcry_mpi_get_nbits(revdsa_r);
						sbits = gcry_mpi_get_nbits(revdsa_s);
						if (opt_verbose)
							std::cout << "INFO: rbits = " << rbits << " sbits = " << sbits << std::endl;
					}
					else
					{
						std::cerr << "ERROR: public-key signature algorithm " << (int)ctx.pkalgo << " not supported" << std::endl;
						cleanup_ctx(ctx);
						cleanup_containers(qual, v_i, c_ik);
						return false;
					}
					if ((rev_hashalgo < 8) || (rev_hashalgo >= 11))
						std::cerr << "WARNING: insecure hash algorithm " << (int)rev_hashalgo << " used for signatures" << std::endl;
				}
				break;
			case 6: // Public-Key Packet
				if (ctx.version != 4)
					std::cerr << "WARNING: public-key packet version " << (int)ctx.version << " not supported" << std::endl;
				else if (!primary)
				{
					primary = true;
					// evaluate the content
					pub.clear();
					if ((ctx.pkalgo == 1) || (ctx.pkalgo == 3))
					{
						gcry_mpi_set(rsa_n, ctx.n);
						gcry_mpi_set(rsa_e, ctx.e);
						CallasDonnerhackeFinneyShawThayerRFC4880::PacketPubEncode(ctx.keycreationtime, ctx.pkalgo, // public-key is RSA 
							rsa_n, rsa_e, rsa_n, rsa_e, pub);
					}
					else if (ctx.pkalgo == 17)
					{
						gcry_mpi_set(dsa_p, ctx.p);
						gcry_mpi_set(dsa_q, ctx.q);
						gcry_mpi_set(dsa_g, ctx.g);
						gcry_mpi_set(dsa_y, ctx.y);
						CallasDonnerhackeFinneyShawThayerRFC4880::PacketPubEncode(ctx.keycreationtime, 17, // public-key is DSA 
							dsa_p, dsa_q, dsa_g, dsa_y, pub);
					}
					else
					{
						std::cerr << "ERROR: public-key algorithm " << (int)ctx.pkalgo << " not supported" << std::endl;
						cleanup_ctx(ctx);
						cleanup_containers(qual, v_i, c_ik);
						return false;
					}
					creation = ctx.keycreationtime;
					keycreationtime_out = ctx.keycreationtime;
					pub_hashing.clear();
					for (size_t i = 6; i < pub.size(); i++)
						pub_hashing.push_back(pub[i]);
					keyid.clear();
					CallasDonnerhackeFinneyShawThayerRFC4880::KeyidCompute(pub_hashing, keyid);
					if (opt_verbose)
					{
						std::cout << "INFO: Key ID of primary key: " << std::hex;
						for (size_t i = 0; i < keyid.size(); i++)
							std::cout << (int)keyid[i] << " ";
						std::cout << std::dec << std::endl;
					}
				}
				else
				{
					std::cerr << "ERROR: more than one primary key not supported" << std::endl;
					cleanup_ctx(ctx);
					cleanup_containers(qual, v_i, c_ik);
					return false;
				}
				break;
			case 13: // User ID Packet
				if (uid_flag)
					std::cerr << "WARNING: more than one uid packet found; using last user ID" << std::endl;
				uid_flag = true, uat_flag = false;
				// store the whole packet
				uid.clear();
				for (size_t i = 0; i < current_packet.size(); i++)
					uid.push_back(current_packet[i]);
				// evaluate the content
				userid = "";
				for (size_t i = 0; i < sizeof(ctx.uid); i++)
				{
					if (ctx.uid[i])
						userid += ctx.uid[i];
					else
						break;
				}
				break;
			case 17: // User Attribute Packet
				std::cerr << "WARNING: user attribute packet found; ignored" << std::endl;
				uid_flag = false, uat_flag = true;
				break;
			default:
				if (opt_verbose)
					std::cout << "INFO: ignore packet of type " << (int)ptag << std::endl;
				break;
		}
		// cleanup allocated buffers and mpi's
		cleanup_ctx(ctx);
		cleanup_containers(qual, v_i, c_ik);
	}
	if (!primary)
	{
		std::cerr << "ERROR: no primary key found" << std::endl;
		return false;
	}
	if (!sig)
	{
		std::cerr << "ERROR: no self-signature for primary key found" << std::endl;
		return false;
	}
	
	// build keys, print key usage, and check self-signature
	gcry_sexp_t primarykey;
	gcry_error_t ret = 1;
	if ((pkalgo == 1) || (pkalgo == 3))
	{
		ret = gcry_sexp_build(&primarykey, &erroff, "(public-key (rsa (n %M) (e %M)))", rsa_n, rsa_e);
	}
	else if (pkalgo == 17)
		ret = gcry_sexp_build(&primarykey, &erroff, "(public-key (dsa (p %M) (q %M) (g %M) (y %M)))", dsa_p, dsa_q, dsa_g, dsa_y);
	if (ret)
	{
		std::cerr << "ERROR: parsing primary key material failed" << std::endl;
		return false;
	}
	size_t flags = 0;
	for (size_t i = 0; i < sizeof(keyflags); i++)
	{
		if (keyflags[i])
			flags = (flags << 8) + keyflags[i];
		else
			break;
	}
	if (opt_verbose)
	{
		std::cout << "key flags on primary key: ";
		if ((flags & 0x01) == 0x01)
			std::cout << "C"; // The key may be used to certify other keys.
		if ((flags & 0x02) == 0x02)
			std::cout << "S"; // The key may be used to sign data.
		if ((flags & 0x04) == 0x04)
			std::cout << "E"; // The key may be used encrypt communications.
		if ((flags & 0x08) == 0x08)
			std::cout << "e"; // The key may be used encrypt storage.
		if ((flags & 0x10) == 0x10)
			std::cout << "D"; // The private component of this key may have been split by a secret-sharing mechanism.		
		if ((flags & 0x20) == 0x20)
			std::cout << "A"; // The key may be used for authentication.
		if ((flags & 0x80) == 0x80)
			std::cout << "M"; // The private component of this key may be in the possession of more than one person.
		std::cout << std::endl;
		std::cout << "INFO: userid = \"" << userid << "\"" << std::endl;
		std::cout << "INFO: sigtype = 0x" << std::hex << (int)sigtype << std::dec << 
			" pkalgo = " << (int)pkalgo << " hashalgo = " << (int)hashalgo <<
			" hspd.size() = " << hspd.size() << std::endl;
	}
	tmcg_octets_t trailer, left, hash;
	if (sigV3)
	{
		tmcg_octets_t sigtime_octets;
		CallasDonnerhackeFinneyShawThayerRFC4880::PacketTimeEncode(sigtime, sigtime_octets);
		// The concatenation of the data to be signed, the signature type, and
		// creation time from the Signature packet (5 additional octets) is
		// hashed. The resulting hash value is used in the signature algorithm.
		// The high 16 bits (first two octets) of the hash are included in the
		// Signature packet to provide a quick test to reject some invalid
		// signatures.
		// A V3 signature hashes five octets of the packet body, starting from
		// the signature type field. This data is the signature type, followed
		// by the four-octet signature time.
		trailer.push_back(sigtype);
		trailer.insert(trailer.end(), sigtime_octets.begin(), sigtime_octets.end());
		CallasDonnerhackeFinneyShawThayerRFC4880::CertificationHashV3(pub_hashing, userid, trailer, hashalgo, hash, left);
	}
	else
	{
		trailer.push_back(4); // only V4 format supported
		trailer.push_back(sigtype);
		trailer.push_back(pkalgo);
		trailer.push_back(hashalgo);
		trailer.push_back(hspd.size() >> 8); // length of hashed subpacket data
		trailer.push_back(hspd.size());
		trailer.insert(trailer.end(), hspd.begin(), hspd.end());
		CallasDonnerhackeFinneyShawThayerRFC4880::CertificationHash(pub_hashing, userid, trailer, hashalgo, hash, left);
	}
	if (opt_verbose)
		std::cout << "INFO: left = " << std::hex << (int)left[0] << " " << (int)left[1] << std::dec << std::endl;
	if ((pkalgo == 1) || (pkalgo == 3))
		ret = CallasDonnerhackeFinneyShawThayerRFC4880::AsymmetricVerifyRSA(hash, primarykey, hashalgo, rsa_md);
	else if (pkalgo == 17)
		ret = CallasDonnerhackeFinneyShawThayerRFC4880::AsymmetricVerifyDSA(hash, primarykey, dsa_r, dsa_s);
	if (ret)
	{
		std::cerr << "ERROR: verification of primary key self-signature failed (rc = " << gcry_err_code(ret) << ", str = " <<
			gcry_strerror(ret) << ")" << std::endl;
		gcry_sexp_release(primarykey);
		return false;
	}
	if (rev)
	{
		if (opt_verbose)
			std::cout << "INFO: rev_sigtype = 0x" << std::hex << (int)rev_sigtype << std::dec << 
			" rev_pkalgo = " << (int)rev_pkalgo << " rev_hashalgo = " << (int)rev_hashalgo <<
			" rev_hspd.size() = " << rev_hspd.size() << std::endl;
		tmcg_octets_t rev_trailer, rev_left;
		hash.clear();
		if (revV3)
		{
			tmcg_octets_t rev_sigtime_octets;
			CallasDonnerhackeFinneyShawThayerRFC4880::PacketTimeEncode(rev_sigtime, rev_sigtime_octets);
			// The concatenation of the data to be signed, the signature type, and
			// creation time from the Signature packet (5 additional octets) is
			// hashed. The resulting hash value is used in the signature algorithm.
			// The high 16 bits (first two octets) of the hash are included in the
			// Signature packet to provide a quick test to reject some invalid
			// signatures.
			// A V3 signature hashes five octets of the packet body, starting from
			// the signature type field. This data is the signature type, followed
			// by the four-octet signature time.
			rev_trailer.push_back(rev_sigtype);
			rev_trailer.insert(rev_trailer.end(), rev_sigtime_octets.begin(), rev_sigtime_octets.end());
			CallasDonnerhackeFinneyShawThayerRFC4880::KeyRevocationHashV3(pub_hashing, rev_trailer, rev_hashalgo, hash, rev_left);
		}
		else
		{
			rev_trailer.push_back(4); // only V4 format supported
			rev_trailer.push_back(rev_sigtype);
			rev_trailer.push_back(rev_pkalgo);
			rev_trailer.push_back(rev_hashalgo);
			rev_trailer.push_back(rev_hspd.size() >> 8); // length of hashed subpacket data
			rev_trailer.push_back(rev_hspd.size());
			rev_trailer.insert(rev_trailer.end(), rev_hspd.begin(), rev_hspd.end());
			CallasDonnerhackeFinneyShawThayerRFC4880::KeyRevocationHash(pub_hashing, rev_trailer, rev_hashalgo, hash, rev_left);
		}
		if (opt_verbose)
			std::cout << "INFO: rev_left = " << std::hex << (int)rev_left[0] << " " << (int)rev_left[1] << std::dec << std::endl;
		if ((pkalgo == 1) || (pkalgo == 3))
			ret = CallasDonnerhackeFinneyShawThayerRFC4880::AsymmetricVerifyRSA(hash, primarykey, rev_hashalgo, revrsa_md);
		else if (pkalgo == 17)
			ret = CallasDonnerhackeFinneyShawThayerRFC4880::AsymmetricVerifyDSA(hash, primarykey, revdsa_r, revdsa_s);
		gcry_sexp_release(primarykey);
		if (ret)
		{
			std::cerr << "ERROR: verification of primary key revocation signature failed (rc = " << gcry_err_code(ret) << ", str = " <<
				gcry_strerror(ret) << ")" << std::endl;
			return false;
		}
		else
		{
			std::cerr << "ERROR: valid revocation signature on primary key found" << std::endl;
			return false;
		}
	}
	gcry_sexp_release(primarykey);
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

bool unlock_memory
	()
{
	if (munlockall() < 0)
	{
		perror("unlock_memory (munlockall)");
		return false;
	}
	return true;
}

