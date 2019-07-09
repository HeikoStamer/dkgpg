/*******************************************************************************
   This file is part of Distributed Privacy Guard (DKGPG).

 Copyright (C) 2018, 2019  Heiko Stamer <HeikoStamer@gmx.net>

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
#include "dkg-io.hh"

bool get_passphrase
	(const std::string &prompt,
	 const bool echo,
	 tmcg_openpgp_secure_string_t &passphrase)
{
	struct termios old_term, new_term;
	if (!echo)
	{
		// disable echo on stdin
		if (tcgetattr(fileno(stdin), &old_term) < 0)
		{
			perror("ERROR: get_passphrase (tcgetattr)");
			return false;
		}
		new_term = old_term;
		new_term.c_lflag &= ~(ECHO | ISIG);
		new_term.c_lflag |= ECHONL;
		if (tcsetattr(fileno(stdin), TCSANOW, &new_term) < 0)
		{
			perror("ERROR: get_passphrase (tcsetattr)");
			return false;
		}
	}
	// read the passphrase
	std::cerr << prompt.c_str() << ": ";
	if (feof(stdin) || ferror(stdin))
	{
		std::cin.clear();
		clearerr(stdin); // reset end-of-file and error status of stdin
	}
	std::getline(std::cin, passphrase);
	std::cin.clear();
	if (!echo)
	{
		// enable echo on stdin
		if (tcsetattr(fileno(stdin), TCSANOW, &old_term) < 0)
		{
			perror("ERROR: get_passphrase (tcsetattr)");
			return false;
		}
	}
	return true;
}

bool check_confirmation
	(const std::string &prompt)
{
	std::string input, confirm;
	// create a random confirmation challenge of 2^24 bit entropy
	tmcg_openpgp_octets_t c;
	unsigned char buf[3];
	gcry_randomize(buf, sizeof(buf), GCRY_STRONG_RANDOM);
	for (size_t i = 0; i < sizeof(buf); i++)
		c.push_back(buf[i]);
	CallasDonnerhackeFinneyShawThayerRFC4880::Radix64Encode(c, confirm, false);
	// read and check the confirmation challenge
	std::cerr << prompt.c_str() << " \"" << confirm << "\": ";
	std::getline(std::cin, input);
	std::cin.clear();
	if (input == confirm)
		return true;
	return false;
}

bool read_key_file
	(const std::string &filename,
	 std::string &result)
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
		std::cerr << "ERROR: reading from public/private key file until EOF" <<
			" failed" << std::endl;
		return false;
	}
	ifs.close();
	result = key.str();
	return true;
}

bool read_binary_key_file
	(const std::string &filename,
	 const tmcg_openpgp_armor_t type,
	 std::string &result)
{
	// read the public/private key from file and convert result to ASCII armor
	tmcg_openpgp_octets_t input;
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
		std::cerr << "ERROR: reading from public/private key file until EOF" <<
			" failed" << std::endl;
		return false;
	}
	ifs.close();
	CallasDonnerhackeFinneyShawThayerRFC4880::ArmorEncode(type, input, result);
	return true;
}

bool write_key_file
	(const std::string &filename,
	 const std::string &key)
{
	std::ofstream ofs(filename.c_str(), 
		std::ofstream::out | std::ofstream::trunc);
	if (!ofs.is_open() || !ofs.good())
	{
		std::cerr << "ERROR: cannot open public/private key file" << std::endl;
		return false;
	}
	ofs << key;
	if (!ofs.good())
	{
		ofs.close();
		std::cerr << "ERROR: writing to public/private key file failed" <<
			std::endl;
		return false;
	}
	ofs.close();
	return true;
}

bool write_key_file
	(const std::string &filename,
	 const tmcg_openpgp_armor_t type,
	 const tmcg_openpgp_octets_t &key)
{
	if (type == TMCG_OPENPGP_ARMOR_PRIVATE_KEY_BLOCK)
	{
		if (!check_strict_permissions(filename))
		{
			std::cerr << "WARNING: weak permissions of existing key file" <<
				" detected" << std::endl;
			if (!set_strict_permissions(filename))
			{
				std::cerr << "WARNING: setting strict permissions for key" <<
					" file failed" << std::endl;
			}
		}
	}
	std::string armor;
	CallasDonnerhackeFinneyShawThayerRFC4880::ArmorEncode(type, key, armor);
	return write_key_file(filename, armor);
}

bool check_strict_permissions
	(const std::string &filename)
{
	struct stat st;
	if (stat(filename.c_str(), &st) < 0)
	{
		perror("ERROR: check_strict_permissions (stat)");
		return false;
	}
	if ((st.st_mode & S_IXUSR) == S_IXUSR)
		return false;
	if ((st.st_mode & S_IRGRP) == S_IRGRP)
		return false;
	if ((st.st_mode & S_IWGRP) == S_IWGRP)
		return false;
	if ((st.st_mode & S_IXGRP) == S_IXGRP)
		return false;
	if ((st.st_mode & S_IROTH) == S_IROTH)
		return false;
	if ((st.st_mode & S_IWOTH) == S_IWOTH)
		return false;
	if ((st.st_mode & S_IXOTH) == S_IXOTH)
		return false;
	return true;
}

bool set_strict_permissions
	(const std::string &filename)
{
	mode_t perm = S_IRUSR | S_IWUSR;
	if (chmod(filename.c_str(), perm) < 0)
	{
		perror("ERROR: set_strict_permissions (chmod)");
		return false;
	}
	return true;
}

bool create_strict_permissions
	(const std::string &filename)
{
	mode_t perm = S_IRUSR | S_IWUSR;
	int fd = open(filename.c_str(), O_CREAT | O_EXCL, perm); 
	if (fd < 0)
	{
		perror("ERROR: create_strict_permissions (open)");
		return false;
	}
	if (close(fd) < 0)
	{
		perror("ERROR: create_strict_permissions (close)");
		return false;
	}
	return true;
}

bool read_binary_signature
	(const std::string &filename,
	 std::string &result)
{
	// read the signature from file and convert to ASCII armor
	tmcg_openpgp_octets_t input;
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
		std::cerr << "ERROR: reading from input file until EOF failed" <<
			std::endl;
		return false;
	}
	ifs.close();
	CallasDonnerhackeFinneyShawThayerRFC4880::
		ArmorEncode(TMCG_OPENPGP_ARMOR_SIGNATURE, input, result);
	return true;
}

bool read_message
	(const std::string &filename,
	 std::string &result)
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
		std::cerr << "ERROR: reading from input file until EOF failed" <<
			std::endl;
		return false;
	}
	ifs.close();
	result = msg.str();
	return true;
}

bool read_binary_message
	(const std::string &filename,
	 std::string &result)
{
	// read the (encrypted) message from file and convert result to ASCII armor
	tmcg_openpgp_octets_t input;
	std::ifstream ifs(filename.c_str(), std::ifstream::in);
	if (!ifs.is_open())
	{
		std::cerr << "ERROR: cannot open the input file" << std::endl;
		return false;
	}
	char c;
	while (ifs.get(c))
		input.push_back(c);
	if (!ifs.eof())
	{
		ifs.close();
		std::cerr << "ERROR: reading from input file until EOF failed" <<
			std::endl;
		return false;
	}
	ifs.close();
	CallasDonnerhackeFinneyShawThayerRFC4880::
		ArmorEncode(TMCG_OPENPGP_ARMOR_MESSAGE, input, result);
	return true;
}

bool write_message
	(const std::string &filename, const tmcg_openpgp_octets_t &msg)
{
	// write out the (decrypted) message to file
	std::ofstream ofs(filename.c_str(), std::ofstream::out);
	if (!ofs.good())
	{
		std::cerr << "ERROR: cannot open the output file" << std::endl;
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
		std::cerr << "ERROR: cannot open the output file" << std::endl;
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
		perror("ERROR: lock_memory (mlockall)");
		return false;
	}
	return true;
}

bool unlock_memory
	()
{
	if (munlockall() < 0)
	{
		perror("ERROR: unlock_memory (munlockall)");
		return false;
	}
	return true;
}

bool get_key_by_fingerprint
	(const TMCG_OpenPGP_Keyring *ring, const std::string &fingerprint,
	 const int verbose, std::string &armored_key)
{
	// get the public key from keyring based on fingerprint
	if (verbose > 1)
		std::cerr << "INFO: lookup for public key with fingerprint " <<
			"\"" << fingerprint << "\"" << std::endl;
	const TMCG_OpenPGP_Pubkey *keyref = ring->Find(fingerprint);
	if (keyref == NULL)
		return false;
	// extract ASCII-armored public key
	tmcg_openpgp_octets_t pkts;
	keyref->Export(pkts);
	CallasDonnerhackeFinneyShawThayerRFC4880::
		ArmorEncode(TMCG_OPENPGP_ARMOR_PUBLIC_KEY_BLOCK, pkts, armored_key);
	return true;
}

bool get_key_by_keyid
	(const TMCG_OpenPGP_Keyring *ring, const std::string &keyid,
	 const int verbose, std::string &armored_key)
{
	// get the public key from keyring based on key ID
	if (verbose > 1)
	{
		std::cerr << "INFO: lookup for public key with keyid " <<
			"\"" << keyid << "\"" << std::endl;
	}
	const TMCG_OpenPGP_Pubkey *keyref = ring->FindByKeyid(keyid);
	if (keyref == NULL)
		return false;
	// extract ASCII-armored public key
	tmcg_openpgp_octets_t pkts;
	keyref->Export(pkts);
	CallasDonnerhackeFinneyShawThayerRFC4880::
		ArmorEncode(TMCG_OPENPGP_ARMOR_PUBLIC_KEY_BLOCK, pkts, armored_key);
	return true;
}

bool get_key_by_signature
	(const TMCG_OpenPGP_Keyring *ring, const TMCG_OpenPGP_Signature *signature,
	 const int verbose, std::string &armored_key)
{
	// get the public key from keyring based on fingerprint
	std::string fpr;
	CallasDonnerhackeFinneyShawThayerRFC4880::
		FingerprintConvertPlain(signature->issuerfpr, fpr);
	if (!get_key_by_fingerprint(ring, fpr, verbose, armored_key))
	{
		// get the public key from keyring based on key ID
		std::string kid;
		CallasDonnerhackeFinneyShawThayerRFC4880::
			KeyidConvert(signature->issuer, kid);
		if (!get_key_by_keyid(ring, kid, verbose, armored_key))
		{
			std::cerr << "ERROR: public key not found in keyring" << std::endl;
			return false;
		}
	}
	return true;
}

