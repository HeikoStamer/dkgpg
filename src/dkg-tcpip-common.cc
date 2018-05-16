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
#include "dkg-tcpip-common.hh"

extern int						pipefd[DKGPG_MAX_N][DKGPG_MAX_N][2];
extern int						broadcast_pipefd[DKGPG_MAX_N][DKGPG_MAX_N][2];
extern pid_t					pid[DKGPG_MAX_N];
extern std::vector<std::string>	peers;
extern bool						instance_forked;
extern int						opt_verbose;
extern void						fork_instance(const size_t whoami);

static const size_t				tcpip_pipe_buffer_size = 4096;

std::string 					tcpip_thispeer;
std::map<std::string, size_t> 	tcpip_peer2pipe;
std::map<size_t, std::string> 	tcpip_pipe2peer;
std::map<size_t, int>	 		tcpip_pipe2socket;
std::map<size_t, int>			tcpip_broadcast_pipe2socket;
std::map<size_t, int>	 		tcpip_pipe2socket_out;
std::map<size_t, int>			tcpip_broadcast_pipe2socket_out;
std::map<size_t, int>	 		tcpip_pipe2socket_in;
std::map<size_t, int>			tcpip_broadcast_pipe2socket_in;

typedef std::map<size_t, int>::const_iterator tcpip_mci_t;

// This is the signal handler called when receiving SIGINT, SIGQUIT,
// and SIGTERM, respectively.
RETSIGTYPE tcpip_sig_handler_quit(int sig)
{
	// child process?
	if (instance_forked && (pid[tcpip_peer2pipe[tcpip_thispeer]] == 0))
	{
		if (opt_verbose)
			std::cerr << "tcpip_sig_handler_quit(): child got signal " <<
				sig << std::endl;
	}
	else
	{
		if (opt_verbose)
			std::cerr << "tcpip_sig_handler_quit(): parent got signal " <<
				sig << std::endl;
		// remove our own signal handler and quit
		signal(SIGINT, SIG_DFL);
		signal(SIGQUIT, SIG_DFL);
		signal(SIGTERM, SIG_DFL);
		tcpip_close();
		tcpip_done();
		exit(-1);
	}
}

void tcpip_init
	(const std::string &hostname)
{
	// initialize peer identity
	tcpip_thispeer = hostname;
	// initialize peer2pipe and pipe2peer mapping
	if (opt_verbose)
		std::cerr << "INFO: using built-in TCP/IP service for message" <<
			" exchange instead of GNUnet CADET" << std::endl;
	if (std::find(peers.begin(), peers.end(), hostname) == peers.end())
	{
		std::cerr << "ERROR: cannot find hostname \"" << hostname << "\" of" <<
			" this peer within PEERS" << std::endl;
		exit(-1);
	}
	for (size_t i = 0; i < peers.size(); i++)
	{
		tcpip_peer2pipe[peers[i]] = i;
		tcpip_pipe2peer[i] = peers[i];
	}
	// open pipes to communicate with forked instance
	for (size_t i = 0; i < peers.size(); i++)
	{
		for (size_t j = 0; j < peers.size(); j++)
		{
			if (pipe2(pipefd[i][j], O_NONBLOCK) < 0)
			{
				perror("ERROR: dkg-tcpip-common (pipe)");
				exit(-1);
			}
			if (pipe2(broadcast_pipefd[i][j], O_NONBLOCK) < 0)
			{
				perror("ERROR: dkg-tcpip-common (pipe)");
				exit(-1);
			}
		}
	}
	// install our own signal handler
	struct sigaction act;
	memset(&act, 0, sizeof(act));
	act.sa_handler = &tcpip_sig_handler_quit;
	if (sigaction(SIGINT, &act, NULL) < 0)
	{
		perror("ERROR: dkg-tcpip-common (sigaction)");
		exit(-1);
	}
	if (sigaction(SIGQUIT, &act, NULL) < 0)
	{
		perror("ERROR: dkg-tcpip-common (sigaction)");
		exit(-1);
	}
	if (sigaction(SIGTERM, &act, NULL) < 0)
	{
		perror("ERROR: dkg-tcpip-common (sigaction)");
		exit(-1);
	}
}

void tcpip_bindports
	(const uint16_t start, const bool broadcast)
{
	uint16_t peers_size = 0;
	if (peers.size() <= DKGPG_MAX_N)
	{
		peers_size = (uint16_t)peers.size();
	}
	else
	{
		std::cerr << "ERROR: too many peers defined" << std::endl;
		tcpip_close();
		tcpip_done();
		exit(-1);
	}
	uint16_t peer_offset = tcpip_peer2pipe[tcpip_thispeer] * peers_size;
	uint16_t local_start = start + peer_offset;
	uint16_t local_end = local_start + peers_size;
	size_t i = 0;
	if (broadcast)
		local_start += peers_size * peers_size; // different port range
	for (uint16_t port = local_start; port < local_end; port++, i++)
	{
		struct addrinfo hints = { 0 }, *res, *rp;
		hints.ai_family = AF_INET;
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_flags = AI_PASSIVE | AI_NUMERICSERV | AI_ADDRCONFIG;
		std::stringstream ports;
		ports << port;
		int ret;
		if ((ret = getaddrinfo(NULL, (ports.str()).c_str(), &hints, &res)) != 0)
		{
			std::cerr << "ERROR: resolving wildcard address failed: ";
			if (ret == EAI_SYSTEM)
				perror("ERROR: dkg-tcpip-common (getaddrinfo)");
			else
				std::cerr << gai_strerror(ret);
			std::cerr << std::endl;
			tcpip_close();
			tcpip_done();
			exit(-1);
		}
		int sockfd = -1;
		for (rp = res; rp != NULL; rp = rp->ai_next)
		{
			if ((sockfd = socket(rp->ai_family, rp->ai_socktype,
				rp->ai_protocol)) < 0)
			{
				perror("WARNING: dkg-tcpip-common (socket)");
				continue; // try next address
			}
			char hbuf[NI_MAXHOST], sbuf[NI_MAXSERV];
			memset(hbuf, 0, sizeof(hbuf));
			memset(sbuf, 0, sizeof(sbuf));
			if ((ret = getnameinfo(rp->ai_addr, rp->ai_addrlen,
				hbuf, sizeof(hbuf), sbuf, sizeof(sbuf),
				NI_NUMERICHOST | NI_NUMERICSERV)) != 0)
			{
				std::cerr << "ERROR: resolving wildcard address failed: ";
				if (ret == EAI_SYSTEM)
					perror("ERROR: dkg-tcpip-common (getnameinfo)");
				else
					std::cerr << gai_strerror(ret);
				std::cerr << std::endl;
				if (close(sockfd) < 0)
					perror("ERROR: dkg-tcpip-common (close)");
				freeaddrinfo(res);
				tcpip_close();
				tcpip_done();
				exit(-1);
			}
			if (opt_verbose)
				std::cerr << "INFO: bind TCP/IP port " << port <<
					" at address " << hbuf << std::endl;
			if (bind(sockfd, rp->ai_addr, rp->ai_addrlen) < 0)
			{
				perror("WARNING: dkg-tcpip-common (bind)");
				if (close(sockfd) < 0)
					perror("ERROR: dkg-tcpip-common (close)");
				sockfd = -1;
				continue; // try next address
			}
			break; // on success: leave the loop
		}
		freeaddrinfo(res);
		if ((rp == NULL) || (sockfd < 0))
		{
			std::cerr << "ERROR: cannot bind TCP/IP port " << port <<
				" for any valid IP address of this host" << std::endl;
			tcpip_close();
			tcpip_done();
			exit(-1);
		}
		else if (listen(sockfd, SOMAXCONN) < 0)
		{
			perror("ERROR: dkg-tcpip-common (listen)");
			if (close(sockfd) < 0)
				perror("ERROR: dkg-tcpip-common (close)");
			tcpip_close();
			tcpip_done();
			exit(-1);
		}
		if (broadcast)
			tcpip_broadcast_pipe2socket[i] = sockfd;
		else
			tcpip_pipe2socket[i] = sockfd;
	}
}

size_t tcpip_connect
	(const uint16_t start, const bool broadcast)
{
	for (size_t i = 0; i < peers.size(); i++)
	{
		if ((broadcast && !tcpip_broadcast_pipe2socket_out.count(i)) ||
			(!broadcast && !tcpip_pipe2socket_out.count(i)))
		{
			uint16_t peers_size = 0;
			if (peers.size() <= DKGPG_MAX_N)
			{
				peers_size = (uint16_t)peers.size();
			}
			else
			{
				std::cerr << "ERROR: too many peers defined" << std::endl;
				tcpip_close();
				tcpip_done();
				exit(-1);
			}
			uint16_t peer_offset = (uint16_t)tcpip_peer2pipe[tcpip_thispeer];
			uint16_t port = start + (i * peers_size) + peer_offset;
			int ret;
			struct addrinfo hints = { 0 }, *res, *rp;
			hints.ai_family = AF_INET;
			hints.ai_socktype = SOCK_STREAM;
			hints.ai_flags = AI_NUMERICSERV | AI_ADDRCONFIG;
			if (broadcast)
				port += peers_size * peers_size; // different port range
			std::stringstream ports;
			ports << port;
			if ((ret = getaddrinfo(peers[i].c_str(), (ports.str()).c_str(),
				&hints, &res)) != 0)
			{
				std::cerr << "ERROR: resolving hostname \"" <<
					peers[i] << "\" failed: ";
				if (ret == EAI_SYSTEM)
					perror("ERROR: dkg-tcpip-common (getaddrinfo)");
				else
					std::cerr << gai_strerror(ret);
				std::cerr << std::endl;
				tcpip_close();
				tcpip_done();
				exit(-1);
			}
			for (rp = res; rp != NULL; rp = rp->ai_next)
			{
				int sockfd;
				if ((sockfd = socket(rp->ai_family, rp->ai_socktype,
					rp->ai_protocol)) < 0)
				{
					perror("WARNING: dkg-tcpip-common (socket)");
					continue; // try next address
				}
				if (connect(sockfd, rp->ai_addr, rp->ai_addrlen) < 0)
				{
					if (errno != ECONNREFUSED)
						perror("WARNING: dkg-tcpip-common (connect)");					
					if (close(sockfd) < 0)
						perror("ERROR: dkg-tcpip-common (close)");
					continue; // try next address
				}
				else
				{
					char hbuf[NI_MAXHOST], sbuf[NI_MAXSERV];
					memset(hbuf, 0, sizeof(hbuf));
					memset(sbuf, 0, sizeof(sbuf));
					if ((ret = getnameinfo(rp->ai_addr, rp->ai_addrlen,
						hbuf, sizeof(hbuf), sbuf, sizeof(sbuf),
						NI_NUMERICHOST | NI_NUMERICSERV)) != 0)
					{
						std::cerr << "ERROR: resolving hostname \"" <<
							peers[i] << "\" failed: ";
						if (ret == EAI_SYSTEM)
							perror("ERROR: dkg-tcpip-common (getnameinfo)");
						else
							std::cerr << gai_strerror(ret);
						std::cerr << std::endl;
						if (close(sockfd) < 0)
							perror("ERROR: dkg-tcpip-common (close)");
						freeaddrinfo(res);
						tcpip_close();
						tcpip_done();
						exit(-1);
					}
					if (opt_verbose)
						std::cerr << "INFO: resolved hostname \"" <<
							peers[i] << "\" to address " << hbuf << std::endl;
					if (opt_verbose)
						std::cerr << "INFO: connected to host \"" <<
							peers[i] << "\" on port " << port << std::endl;
					if (broadcast)
						tcpip_broadcast_pipe2socket_out[i] = sockfd;
					else
						tcpip_pipe2socket_out[i] = sockfd;
					break; // on success: leave the loop
				}
			}
			freeaddrinfo(res);
		}
	}
	if (broadcast)
		return tcpip_broadcast_pipe2socket_out.size();
	else
		return tcpip_pipe2socket_out.size();
}

void tcpip_accept
	()
{
	while ((tcpip_pipe2socket_in.size() < peers.size()) ||
		(tcpip_broadcast_pipe2socket_in.size() < peers.size()))
	{
		fd_set rfds;
		struct timeval tv;
		int retval, maxfd = 0;
		FD_ZERO(&rfds);
		for (tcpip_mci_t pi = tcpip_pipe2socket.begin();
			pi != tcpip_pipe2socket.end(); ++pi)
		{
			FD_SET(pi->second, &rfds);
			if (pi->second > maxfd)
				maxfd = pi->second;
		}
		for (tcpip_mci_t pi = tcpip_broadcast_pipe2socket.begin();
			pi != tcpip_broadcast_pipe2socket.end(); ++pi)
		{
			FD_SET(pi->second, &rfds);
			if (pi->second > maxfd)
				maxfd = pi->second;
		}
		tv.tv_sec = 1;
		tv.tv_usec = 0;
		retval = select((maxfd + 1), &rfds, NULL, NULL, &tv);
		if (retval < 0)
		{
			if ((errno == EAGAIN) || (errno == EINTR))
			{
				if (errno == EAGAIN)
					perror("WARNING: dkg-tcpip-common (select)");
				continue;
			}
			else
			{
				perror("ERROR: dkg-tcpip-common (select)");
				tcpip_close();
				tcpip_done();
				exit(-1);
			}
		}
		if (retval == 0)
			continue; // timeout
		for (tcpip_mci_t pi = tcpip_pipe2socket.begin();
			pi != tcpip_pipe2socket.end(); ++pi)
		{
			if (FD_ISSET(pi->second, &rfds))
			{
				struct sockaddr_storage sin = { 0 };
				socklen_t slen = (socklen_t)sizeof(sin);
				int connfd = accept(pi->second, (struct sockaddr*)&sin, &slen);
				if (connfd < 0)
				{
					perror("ERROR: dkg-tcpip-common (accept)");
					tcpip_close();
					tcpip_done();
					exit(-1);
				}
				tcpip_pipe2socket_in[pi->first] = connfd;
				char ipaddr[INET6_ADDRSTRLEN];
				int ret;
				if ((ret = getnameinfo((struct sockaddr *)&sin, slen,
					ipaddr, sizeof(ipaddr), NULL, 0, NI_NUMERICHOST)) != 0)
				{
					std::cerr << "ERROR: resolving incoming address failed: ";
					if (ret == EAI_SYSTEM)
						perror("ERROR: dkg-tcpip-common (getnameinfo)");
					else
						std::cerr << gai_strerror(ret);
					std::cerr << std::endl;
					tcpip_close();
					tcpip_done();
					exit(-1);
				}
				if (opt_verbose)
					std::cerr << "INFO: accept connection for P/D/R/S_" <<
						pi->first << " from address " << ipaddr << std::endl;
			}
		}
		for (tcpip_mci_t pi = tcpip_broadcast_pipe2socket.begin();
			pi != tcpip_broadcast_pipe2socket.end(); ++pi)
		{
			if (FD_ISSET(pi->second, &rfds))
			{
				struct sockaddr_storage sin = { 0 };
				socklen_t slen = (socklen_t)sizeof(sin);
				int connfd = accept(pi->second, (struct sockaddr*)&sin, &slen);
				if (connfd < 0)
				{
					perror("ERROR: dkg-tcpip-common (accept)");
					exit(-1);
				}
				tcpip_broadcast_pipe2socket_in[pi->first] = connfd;
				char ipaddr[INET6_ADDRSTRLEN];
				int ret;
				if ((ret = getnameinfo((struct sockaddr *)&sin, slen,
					ipaddr, sizeof(ipaddr), NULL, 0, NI_NUMERICHOST)) != 0)
				{
					std::cerr << "ERROR: resolving incoming address failed: ";
					if (ret == EAI_SYSTEM)
						perror("ERROR: dkg-tcpip-common (getnameinfo)");
					else
						std::cerr << gai_strerror(ret);
					std::cerr << std::endl;
					tcpip_close();
					tcpip_done();
					exit(-1);
				}
				if (opt_verbose)
					std::cerr << "INFO: accept broadcast connection for" <<
						" P/D/R/S_" << pi->first << " from address " << 
						ipaddr << std::endl;
			}
		}
	}
}


void tcpip_fork
	()
{
	if ((tcpip_pipe2socket_in.size() == peers.size()) &&
		(tcpip_broadcast_pipe2socket_in.size() == peers.size()))
	{
		// fork instance
		if (opt_verbose)
			std::cerr << "INFO: forking the protocol instance ..." << std::endl;
		fork_instance(tcpip_peer2pipe[tcpip_thispeer]);
	}
	else
	{
		std::cerr << "ERROR: not enough connections established" << std::endl;
		tcpip_close();
		tcpip_done();
		exit(-1);
	}
}

int tcpip_io
	()
{
	size_t thisidx = tcpip_peer2pipe[tcpip_thispeer]; // index of this peer
	while (1)
	{
		if (instance_forked)
		{
			// exit, if forked instance has terminated 
			int wstatus = 0;
			int thispid = pid[thisidx];
			int ret = waitpid(thispid, &wstatus, WNOHANG);
			if (ret < 0)
				perror("ERROR: dkg-tcpip-common (waitpid)");
			else if (ret == thispid)
			{
				instance_forked = false;
				if (!WIFEXITED(wstatus))
				{
					std::cerr << "ERROR: protocol instance ";
					if (WIFSIGNALED(wstatus))
						std::cerr << thispid << " terminated by signal " <<
							WTERMSIG(wstatus) << std::endl;
					if (WCOREDUMP(wstatus))
						std::cerr << thispid << " dumped core" << std::endl;
					return -1;
				}
				else if (WIFEXITED(wstatus))
				{
					if (opt_verbose)
						std::cerr << "INFO: protocol instance " << thispid <<
							" terminated with exit status " <<
							WEXITSTATUS(wstatus) << std::endl;
					return WEXITSTATUS(wstatus);
				}
				return 0;
			}
		}
		fd_set rfds;
		struct timeval tv;
		int retval, maxfd = 0;
		FD_ZERO(&rfds);
		for (tcpip_mci_t pi = tcpip_pipe2socket_in.begin();
			pi != tcpip_pipe2socket_in.end(); ++pi)
		{
			if (pi->first != thisidx)
			{
				FD_SET(pi->second, &rfds);
				if (pi->second > maxfd)
					maxfd = pi->second;
			}
		}
		for (tcpip_mci_t pi = tcpip_broadcast_pipe2socket_in.begin();
			pi != tcpip_broadcast_pipe2socket_in.end(); ++pi)
		{
			if (pi->first != thisidx)
			{
				FD_SET(pi->second, &rfds);
				if (pi->second > maxfd)
					maxfd = pi->second;
			}
		}
		for (size_t i = 0; i < peers.size(); i++)
		{
			if (i != thisidx)
			{
				FD_SET(pipefd[thisidx][i][0], &rfds);
				if (pipefd[thisidx][i][0] > maxfd)
					maxfd = pipefd[thisidx][i][0];
				FD_SET(broadcast_pipefd[thisidx][i][0], &rfds);
				if (broadcast_pipefd[thisidx][i][0] > maxfd)
					maxfd = broadcast_pipefd[thisidx][i][0];
			}
		}
		tv.tv_sec = 1;
		tv.tv_usec = 0;
		retval = select((maxfd + 1), &rfds, NULL, NULL, &tv);
		if (retval < 0)
		{
			if ((errno == EAGAIN) || (errno == EINTR))
			{
				if (errno == EAGAIN)
					perror("WARNING: dkg-tcpip-common (select)");
				continue;
			}
			else
			{
				perror("ERROR: dkg-tcpip-common (select)");
				tcpip_close();
				tcpip_done();
				exit(-1);
			}
		}
		if (retval == 0)
			continue; // timeout
		for (tcpip_mci_t pi = tcpip_pipe2socket_in.begin();
			pi != tcpip_pipe2socket_in.end(); ++pi)
		{
			if ((pi->first != thisidx) && FD_ISSET(pi->second, &rfds))
			{
				char buf[tcpip_pipe_buffer_size];
				ssize_t len = read(pi->second, buf, sizeof(buf));
				if (len < 0)
				{
					if ((errno == EWOULDBLOCK) || (errno == EINTR))
					{
						continue;
					}
					else if (errno == EAGAIN)
					{
						perror("WARNING: dkg-tcpip-common (read)");
						continue;
					}
					else
					{
						perror("ERROR: dkg-tcpip-common (read)");
						tcpip_close();
						tcpip_done();
						exit(-1);
					}
				}
				else if (len == 0)
				{
					std::cerr << "WARNING: connection collapsed for" <<
						" P/D/R/S_" << pi->first << std::endl;
					tcpip_pipe2socket_out.erase(pi->first);
					tcpip_pipe2socket_in.erase(pi->first);
					break;
				}
				else
				{
					if (opt_verbose > 1)
						std::cerr << "INFO: received " << len << " bytes on " <<
							"connection for P/D/R/S_" << pi->first << std::endl;
					ssize_t wnum = 0;
					do
					{
						ssize_t num = write(pipefd[pi->first][thisidx][1],
								buf + wnum, len - wnum);
						if (num < 0)
						{
							if ((errno == EWOULDBLOCK) || (errno == EINTR))
							{
								if (opt_verbose)
									std::cerr << "INFO: sleeping for write" <<
										" into pipe ..." << std::endl;
								sleep(1);
								continue;
							}
							else if (errno == EAGAIN)
							{
								perror("WARNING: dkg-tcpip-common (write)");
								if (opt_verbose)
									std::cerr << "INFO: sleeping for write" <<
										" into pipe ..." << std::endl;
								sleep(1);
								continue;
							}
							else
							{
								perror("ERROR: dkg-tcpip-common (write)");
								tcpip_close();
								tcpip_done();
								exit(-1);
							}
						}
						else
							wnum += num;
					}
					while (wnum < len);
				}
			}
		}
		for (tcpip_mci_t pi = tcpip_broadcast_pipe2socket_in.begin();
			pi != tcpip_broadcast_pipe2socket_in.end(); ++pi)
		{
			if ((pi->first != thisidx) && FD_ISSET(pi->second, &rfds))
			{
				char buf[tcpip_pipe_buffer_size];
				ssize_t len = read(pi->second, buf, sizeof(buf));
				if (len < 0)
				{
					if ((errno == EWOULDBLOCK) || (errno == EINTR))
					{
						continue;
					}
					else if (errno == EAGAIN)
					{
						perror("WARNING: dkg-tcpip-common (read)");
						continue;
					}
					else
					{
						perror("ERROR: dkg-tcpip-common (read)");
						tcpip_close();
						tcpip_done();
						exit(-1);
					}
				}
				else if (len == 0)
				{
					std::cerr << "WARNING: broadcast connection collapsed" <<
						" for P/D/R/S_" << pi->first << std::endl;
					tcpip_broadcast_pipe2socket_out.erase(pi->first);
					tcpip_broadcast_pipe2socket_in.erase(pi->first);
					break;
				}
				else
				{
					if (opt_verbose > 1)
						std::cerr << "INFO: received " << len << " bytes on" <<
							" broadcast connection for P/D/R/S_" <<
							pi->first << std::endl;
					ssize_t wnum = 0;
					do
					{
						ssize_t num = write(
							broadcast_pipefd[pi->first][thisidx][1], buf + wnum,
							len - wnum);
						if (num < 0)
						{
							if ((errno == EWOULDBLOCK) || (errno == EINTR))
							{
								if (opt_verbose)
									std::cerr << "INFO: sleeping for write" <<
										" into pipe ..." << std::endl;
								sleep(1);
								continue;
							}
							else if (errno == EAGAIN)
							{
								perror("WARNING: dkg-tcpip-common (write)");
								if (opt_verbose)
									std::cerr << "INFO: sleeping for write" <<
										" into pipe ..." << std::endl;
								sleep(1);
								continue;
							}
							else
							{
								perror("ERROR: dkg-tcpip-common (write)");
								tcpip_close();
								tcpip_done();
								exit(-1);
							}
						}
						else
							wnum += num;
					}
					while (wnum < len);
				}
			}
		}
		for (size_t i = 0; i < peers.size(); i++)
		{
			if ((i != thisidx) && FD_ISSET(pipefd[thisidx][i][0], &rfds))
			{
				char buf[tcpip_pipe_buffer_size];
				ssize_t len = read(pipefd[thisidx][i][0], buf, sizeof(buf));
				if (len < 0)
				{
					if ((errno == EWOULDBLOCK) || (errno == EINTR))
					{
						continue;
					}
					else if (errno == EAGAIN)
					{
						perror("WARNING: dkg-tcpip-common (read)");
						continue;
					}
					else
					{
						perror("ERROR: dkg-tcpip-common (read)");
						tcpip_close();
						tcpip_done();
						exit(-1);
					}
				}
				else if (len == 0)
				{
					std::cerr << "ERROR: pipe to child collapsed" << std::endl;
					continue;
				}
				else if (tcpip_pipe2socket_out.count(i))
				{
					if (opt_verbose > 1)
						std::cerr << "INFO: sending " << len << " bytes on" <<
							" connection to P/D/R/S_" << i << std::endl;
					ssize_t wnum = 0;
					do
					{
						ssize_t num = write(tcpip_pipe2socket_out[i],
							buf + wnum, len - wnum);
						if (num < 0)
						{
							if ((errno == EWOULDBLOCK) || (errno == EINTR))
							{
								if (opt_verbose)
									std::cerr << "INFO: sleeping for write" <<
										" into socket ..." << std::endl;
								sleep(1);
								continue;
							}
							else if (errno == EAGAIN)
							{
								perror("WARNING: dkg-tcpip-common (write)");
								if (opt_verbose)
									std::cerr << "INFO: sleeping for write" <<
										" into socket ..." << std::endl;
								sleep(1);
								continue;
							}
							else if (errno == ECONNRESET)
							{
								std::cerr << "WARNING: connection collapsed" <<
									" for P/D/R/S_" << i << std::endl;
								tcpip_broadcast_pipe2socket_out.erase(i);
								tcpip_broadcast_pipe2socket_in.erase(i);
								break;
							}
							else
							{
								perror("ERROR: dkg-tcpip-common (write)");
								tcpip_close();
								tcpip_done();
								exit(-1);
							}
						}
						else
							wnum += num;
					}
					while (wnum < len);
				}
				else
				{
					if (opt_verbose > 1)
						std::cerr << "INFO: discarding " << len << " bytes" <<
							" for P/D/R/S_" << i << std::endl;
				}
			}
			if ((i != thisidx) &&
				FD_ISSET(broadcast_pipefd[thisidx][i][0], &rfds))
			{
				char buf[tcpip_pipe_buffer_size];
				ssize_t len = read(broadcast_pipefd[thisidx][i][0], buf,
					sizeof(buf));
				if (len < 0)
				{
					if ((errno == EWOULDBLOCK) || (errno == EINTR))
					{
						continue;
					}
					else if (errno == EAGAIN)
					{
						perror("WARNING: dkg-tcpip-common (read)");
						continue;
					}
					else
					{
						perror("ERROR: dkg-tcpip-common (read)");
						tcpip_close();
						tcpip_done();
						exit(-1);
					}
				}
				else if (len == 0)
				{
					continue;
				}
				else if (tcpip_broadcast_pipe2socket_out.count(i))
				{
					if (opt_verbose > 1)
						std::cerr << "INFO: sending " << len << " bytes on" <<
							" broadcast connection to P/D/R/S_" << i <<
							std::endl;
					ssize_t wnum = 0;
					do
					{
						ssize_t num = write(tcpip_broadcast_pipe2socket_out[i],
							buf + wnum, len - wnum);
						if (num < 0)
						{
							if ((errno == EWOULDBLOCK) || (errno == EINTR))
							{
								if (opt_verbose)
									std::cerr << "INFO: sleeping for write" <<
										" into socket ..." << std::endl;
								sleep(1);
								continue;
							}
							else if (errno == EAGAIN)
							{
								perror("WARNING: dkg-tcpip-common (write)");
								if (opt_verbose)
									std::cerr << "INFO: sleeping for write" <<
										" into socket ..." << std::endl;
								sleep(1);
								continue;
							}
							else if (errno == ECONNRESET)
							{
								std::cerr << "WARNING: broadcast connection" <<
									" collapsed for P/D/R/S_" << i << std::endl;
								tcpip_broadcast_pipe2socket_out.erase(i);
								tcpip_broadcast_pipe2socket_in.erase(i);
								break;
							}
							else
							{
								perror("ERROR: dkg-tcpip-common (write)");
								tcpip_close();
								tcpip_done();
								exit(-1);
							}
						}
						else
							wnum += num;
					}
					while (wnum < len);
				}
				else
				{
					if (opt_verbose > 1)
						std::cerr << "INFO: discarding " << len << " bytes" <<
							" for P/D/R/S_" << i << std::endl;
				}
			}
		}
	}
}

void tcpip_close
	()
{
	for (tcpip_mci_t pi = tcpip_pipe2socket_in.begin();
		pi != tcpip_pipe2socket_in.end(); ++pi)
	{
		if (close(pi->second) < 0)
			perror("ERROR: dkg-tcpip-common (close)");
	}
	for (tcpip_mci_t pi = tcpip_pipe2socket_out.begin();
		pi != tcpip_pipe2socket_out.end(); ++pi)
	{
		if (close(pi->second) < 0)
			perror("ERROR: dkg-tcpip-common (close)");
	}
	for (tcpip_mci_t pi = tcpip_broadcast_pipe2socket_in.begin();
		pi != tcpip_broadcast_pipe2socket_in.end(); ++pi)
	{
		if (close(pi->second) < 0)
			perror("ERROR: dkg-tcpip-common (close)");
	}
	for (tcpip_mci_t pi = tcpip_broadcast_pipe2socket_out.begin();
		pi != tcpip_broadcast_pipe2socket_out.end(); ++pi)
	{
		if (close(pi->second) < 0)
			perror("ERROR: dkg-tcpip-common (close)");
	}
	for (tcpip_mci_t pi = tcpip_pipe2socket.begin();
		pi != tcpip_pipe2socket.end(); ++pi)
	{
		if (close(pi->second) < 0)
			perror("ERROR: dkg-tcpip-common (close)");
	}
	for (tcpip_mci_t pi = tcpip_broadcast_pipe2socket.begin();
		pi != tcpip_broadcast_pipe2socket.end(); ++pi)
	{
		if (close(pi->second) < 0)
			perror("ERROR: dkg-tcpip-common (close)");
	}
}

void tcpip_done
	()
{
	if (instance_forked)
	{
		int thispid = pid[tcpip_peer2pipe[tcpip_thispeer]];
		if (opt_verbose)
			std::cerr << "INFO: kill(" << thispid << ", SIGTERM)" << std::endl;
		if(kill(thispid, SIGTERM))
			perror("ERROR: dkg-tcpip-common (kill)");
		if (opt_verbose)
			std::cerr << "INFO: waitpid(" << thispid << ", NULL, 0)" << std::endl;
		if (waitpid(thispid, NULL, 0) != thispid)
			perror("ERROR: dkg-tcpip-common (waitpid)");
	}
	for (size_t i = 0; i < peers.size(); i++)
	{
		for (size_t j = 0; j < peers.size(); j++)
		{
			if ((close(pipefd[i][j][0]) < 0) || (close(pipefd[i][j][1]) < 0))
				perror("ERROR: dkg-tcpip-common (close)");
			if ((close(broadcast_pipefd[i][j][0]) < 0) ||
				(close(broadcast_pipefd[i][j][1]) < 0))
				perror("ERROR: dkg-tcpip-common (close)");
		}
	}
}

