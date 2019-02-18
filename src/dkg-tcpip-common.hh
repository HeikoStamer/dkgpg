/*******************************************************************************
   This file is part of Distributed Privacy Guard (DKGPG).

 Copyright (C) 2017, 2019  Heiko Stamer <HeikoStamer@gmx.net>

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

#ifndef INCLUDED_dkg_tcpip_common_HH
	#define INCLUDED_dkg_tcpip_common_HH

	// include headers
	#include <string>
	#include <iostream>
	#include <sstream>
	#include <vector>
	#include <map>
	#include <algorithm>
	#include <cassert>
	#include <cstring>
	#include <cstdio>
	#include <unistd.h>
	#include <errno.h>
	#include <fcntl.h>

	#include <sys/types.h>
	#include <sys/wait.h>
	#include <signal.h>
	#include <netdb.h>
	#include <netinet/in.h>
	#include <sys/socket.h>

	RETSIGTYPE tcpip_sig_handler_quit
		(int sig);
	void tcpip_init
		(const std::string &hostname);
	void tcpip_bindports
		(const uint16_t start, const bool broadcast);
	size_t tcpip_connect
		(const uint16_t start, const bool broadcast);
	void tcpip_accept
		();
	void tcpip_fork
		();
	int tcpip_io
		();
	void tcpip_close
		();
	void tcpip_done
		();
	int run_tcpip
		(const size_t peers,
		 unsigned long int opt_p,
		 const std::string &hostname,
		 const std::string &port);

#endif

