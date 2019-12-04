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

// include headers
#ifdef HAVE_CONFIG_H
	#include "dkgpg_config.h"
#endif

#include <string>
#include <vector>

#include <libTMCG.hh>

#include "dkg-io.hh"

int main
	(int argc, char **argv)
{
	static const char *usage = "dkg-sop [OPTIONS] SUBCOMMAND";
	static const char *about = PACKAGE_STRING " " PACKAGE_URL;
	static const char *version = "dkg-sop " PACKAGE_VERSION;
	std::string subcmd;
	int opt_verbose = 0;

	for (size_t i = 0; i < (size_t)(argc - 1); i++)
	{
		std::string arg = argv[i+1];
		// read options
		if ((arg.find("--") == 0) || (arg.find("-V") == 0) ||
			(arg.find("-h") == 0))
		{
			if ((arg.find("-h") == 0) || (arg.find("--help") == 0))
			{
				std::cout << usage << std::endl;
				std::cout << about << std::endl;
				std::cout << "Arguments mandatory for long options are also" <<
					" mandatory for short options." << std::endl;
				std::cout << "  -h, --help     print this help" << std::endl;
				std::cout << "  -V, --verbose  turn on verbose output" <<
					std::endl;
				return 0; // not continue
			}
			if ((arg.find("-V") == 0) || (arg.find("--verbose") == 0))
				opt_verbose++; // increase verbosity
			continue;
		}
		else if (arg.find("-") == 0)
		{
			std::cerr << "ERROR: unknown SOP option \"" << arg << "\"" <<
				std::endl;
			return 37;
		}
		subcmd = arg;
	}

	// initialize LibTMCG
	if (!init_libTMCG())
	{
		std::cerr << "ERROR: initialization of LibTMCG failed" << std::endl;
		return -1;
	}
	if (opt_verbose)
	{
		std::cerr << "INFO: using LibTMCG version " << version_libTMCG() <<
			std::endl;
	}

	if (subcmd == "version")
	{
		std::cout << version << std::endl;
	}
	else
	{
		std::cerr << "ERROR: SOP subcommand \"" << subcmd << "\" not" <<
			" supported" << std::endl;
		return 69;
	}
	
	return 0;
}

