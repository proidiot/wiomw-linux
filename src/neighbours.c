#include <config.h>
#include "neighbours.h"
#include "print_error.h"
#include "sockaddr_helpers.h"
#include <stdio.h>
#include <netlink/netlink.h>
#include <netlink/route/neighbour.h>
#include <netlink/route/link.h>
#include <netlink/route/addr.h>
#include <sysexits.h>
#include <regex.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>

static void print_rtnl_addr(struct rtnl_addr* addr, FILE* fd)
{
	int errcode = 0;
	struct rtnl_link* link = rtnl_addr_get_link(addr);
	struct nl_addr* ipaddr = rtnl_addr_get_local(addr);
	if (ipaddr != NULL && nl_addr_get_family(ipaddr) == AF_INET) {
		char str_temp[BUFSIZ];
		struct sockaddr_in saddr;
		socklen_t slen = sizeof(struct sockaddr_in);
		memset(&saddr, 0, slen);
		fprintf(fd, "{\"agent\":1,");
		nl_addr2str(rtnl_link_get_addr(link), str_temp, BUFSIZ);
		fprintf(fd, "\"mac\":\"%s\",", str_temp);
		errcode = nl_addr_fill_sockaddr(ipaddr, (struct sockaddr*)&saddr, &slen);
		if (errcode < 0) {
			print_error("Unable to parse address: %s", nl_geterror(-errcode));
		} else if (inet_ntop(AF_INET, &saddr.sin_addr.s_addr, str_temp, slen) ==  NULL) {
			print_syserror("Unable to parse address");
		} else {
			fprintf(fd, "\"ip\":\"%s\",", str_temp);
		}
		fprintf(fd, "\"iface\":\"%s\",", rtnl_link_get_name(link));
		fprintf(fd, "\"state\":\"reachable\"}");
	} else if (ipaddr != NULL && nl_addr_get_family(ipaddr) == AF_INET6) {
		char str_temp[BUFSIZ];
		struct sockaddr_in6 saddr;
		socklen_t slen = sizeof(struct sockaddr_in6);
		memset(&saddr, 0, slen);
		fprintf(fd, "{\"agent\":1,");
		nl_addr2str(rtnl_link_get_addr(link), str_temp, BUFSIZ);
		fprintf(fd, "\"mac\":\"%s\",", str_temp);
		errcode = nl_addr_fill_sockaddr(ipaddr, (struct sockaddr*)&saddr, &slen);
		if (errcode < 0) {
			print_error("Unable to parse address: %s", nl_geterror(-errcode));
		} else if (inet_ntop(AF_INET6, &saddr.sin6_addr.s6_addr, str_temp, slen) ==  NULL) {
			print_syserror("Unable to parse address");
		} else {
			fprintf(fd, "\"ip6\":\"%s\",", str_temp);
		}
		fprintf(fd, "\"iface\":\"%s\",", rtnl_link_get_name(link));
		fprintf(fd, "\"state\":\"reachable\"}");
	}
}

static void print_rtnl_neigh(struct rtnl_neigh* neighbor, struct rtnl_link* link, FILE* fd)
{
	char str_temp[BUFSIZ];
	fprintf(fd, "{");
	nl_addr2str(rtnl_neigh_get_lladdr(neighbor), str_temp, BUFSIZ);
	fprintf(fd, "\"mac\":\"%s\",", str_temp);
	nl_addr2str(rtnl_neigh_get_dst(neighbor), str_temp, BUFSIZ);
	fprintf(fd, "\"ip\":\"%s\",", str_temp);
	rtnl_neigh_state2str(rtnl_neigh_get_state(neighbor), str_temp, BUFSIZ);
	fprintf(fd, "\"state\":\"%s\",", str_temp);
	fprintf(fd, "\"iface\":\"%s\"", rtnl_link_get_name(link));
	fprintf(fd, "}");
}

void print_neighbours(FILE* fd)
{
	struct nl_cache* cache_neighborhood;
	struct nl_cache* cache_links;
	struct nl_cache* cache_addresses;
	struct rtnl_addr* addr;
	int errcode;
	regex_t compiled_regex;
	struct nl_sock* nlsock_connection = nl_socket_alloc();

	nl_connect(nlsock_connection, NETLINK_ROUTE);

	errcode = rtnl_link_alloc_cache(nlsock_connection, AF_UNSPEC, &cache_links);
	if (errcode < 0) {
		print_error("Unable to get links: %s", nl_geterror(-errcode));
	} else {
		nl_cache_mngt_provide(cache_links);
	}

	errcode = rtnl_addr_alloc_cache(nlsock_connection, &cache_addresses);
	if (errcode < 0) {
		print_error("Unable to get addresses: %s", nl_geterror(-errcode));
	}

	errcode = regcomp(&compiled_regex, "^(lo|virbr[0-9]+)$", REG_EXTENDED | REG_ICASE);
	if (errcode != 0) {
		char str_temp[BUFSIZ];
		regerror(errcode, &compiled_regex, str_temp, BUFSIZ);
		print_error("Unable to prepare the network interface regex: %s", str_temp);
	}

	errcode = rtnl_neigh_alloc_cache(nlsock_connection, &cache_neighborhood);
	if (errcode < 0) {
		print_error("Unable to get neighborhood: %s", nl_geterror(-errcode));
		exit(EX_SOFTWARE);
	}

	fprintf(fd, "[%d", 12345);
	if ((addr = (struct rtnl_addr*)nl_cache_get_first(cache_addresses)) != NULL) {
		do {
			struct rtnl_link* link = rtnl_addr_get_link(addr);
			char* str_link_name = rtnl_link_get_name(link);
			errcode = regexec(&compiled_regex, str_link_name, 0, NULL, 0);
			if (errcode == REG_NOMATCH) {
				if (rtnl_addr_get_family(addr) == AF_INET || rtnl_addr_get_family(addr) == AF_INET6) {
					struct nl_addr* ipaddr = rtnl_addr_get_local(addr);
					uint8_t prefix = nl_addr_get_prefixlen(ipaddr);
					struct sockaddr* local_addr;
					socklen_t socklen_local_addr;
					if (rtnl_addr_get_family(addr) == AF_INET) {
						socklen_local_addr = sizeof(struct sockaddr_in);
					} else if (rtnl_addr_get_family(addr) == AF_INET6) {
						socklen_local_addr = sizeof(struct sockaddr_in6);
					}
					local_addr = (struct sockaddr*)malloc(socklen_local_addr);
					memset(local_addr, 0, socklen_local_addr);
					nl_addr_fill_sockaddr(ipaddr, local_addr, &socklen_local_addr);
					fprintf(fd, ",");
					print_rtnl_addr(addr, fd);
					if (check_scannable_range(local_addr, socklen_local_addr, prefix) > 0) {
						socklen_t socklen_remote_addr = socklen_local_addr;
						struct sockaddr* remote_addr = (struct sockaddr*)malloc(socklen_remote_addr);
						memset(remote_addr, 0, socklen_remote_addr);
						while (increment_addr(local_addr, socklen_local_addr, prefix, remote_addr, socklen_remote_addr) > 0) {
							int sockfd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
							/*
							struct rtnl_neigh* neighbor;
							struct nl_addr* mac_addr;
							struct nl_addr* neigh_addr;
							if (remote_addr->sa_family == AF_INET) {
								neigh_addr = nl_addr_build(AF_INET, &((struct sockaddr_in*)remote_addr)->sin_addr.s_addr, sizeof(((struct sockaddr_in*)remote_addr)->sin_addr.s_addr));
								nl_addr_set_prefixlen(neigh_addr, 32);
							} else {
								neigh_addr = nl_addr_build(AF_INET6, &((struct sockaddr_in6*)remote_addr)->sin6_addr.s6_addr, sizeof(((struct sockaddr_in6*)remote_addr)->sin6_addr.s6_addr));
								nl_addr_set_prefixlen(neigh_addr, 128);
							}
							*/
							if (sockfd == -1) {
								print_syserror("Unable to create socket");
							} else {
								char str_temp[BUFSIZ];
								if (remote_addr->sa_family == AF_INET) {
									struct sockaddr_in* remote_ip4 = (struct sockaddr_in*)remote_addr;
									if (NULL == inet_ntop(
											AF_INET,
											&remote_ip4->sin_addr.s_addr,
											str_temp,
											sizeof(struct sockaddr_in))) {
										print_syserror("Unable to parse IP address");
									}
									remote_ip4->sin_port = htons(9);
								} else {
									struct sockaddr_in6* remote_ip6 = (struct sockaddr_in6*)remote_addr;
									if (NULL == inet_ntop(
											AF_INET,
											&remote_ip6->sin6_addr.s6_addr,
											str_temp,
											sizeof(struct sockaddr_in6))) {
										print_syserror("Unable to parse IP address");
									}
									remote_ip6->sin6_port = htons(9);
								}
								errcode = connect(sockfd, remote_addr, socklen_remote_addr);
								if (errcode == -1) {
									if (errno != EINPROGRESS) {
										print_syserror("Unable to connect to %s", str_temp);
									}
								}
							}
							close(sockfd);
							/*
							errcode = nl_addr_parse("00:00:00:00:00:00", AF_LLC, &mac_addr);
							if (errcode < 0) {
								print_error("Unable to allocate MAC address: %s", nl_geterror(-errcode));
							}
							neighbor = rtnl_neigh_alloc();
							rtnl_neigh_set_ifindex(neighbor, rtnl_link_get_ifindex(link));
							rtnl_neigh_set_dst(neighbor, neigh_addr);
							rtnl_neigh_set_state(neighbor, NUD_INCOMPLETE);
							rtnl_neigh_set_lladdr(neighbor, mac_addr);
							errcode = rtnl_neigh_add(nlsock_connection, neighbor, 0);
							if (errcode < 0) {
								print_error("Unable to add: %s (%d)", nl_geterror(-errcode), errcode);
							}
							*/
						}
						sleep(5);
						memset(remote_addr, 0, socklen_remote_addr);
						while (increment_addr(local_addr, socklen_local_addr, prefix, remote_addr, socklen_remote_addr) > 0) {
							struct rtnl_neigh* neighbor;
							struct nl_addr* neigh_addr;
							if (remote_addr->sa_family == AF_INET) {
								neigh_addr = nl_addr_build(AF_INET, &((struct sockaddr_in*)remote_addr)->sin_addr.s_addr, sizeof(((struct sockaddr_in*)remote_addr)->sin_addr.s_addr));
								nl_addr_set_prefixlen(neigh_addr, 32);
							} else {
								neigh_addr = nl_addr_build(AF_INET6, &((struct sockaddr_in6*)remote_addr)->sin6_addr.s6_addr, sizeof(((struct sockaddr_in6*)remote_addr)->sin6_addr.s6_addr));
								nl_addr_set_prefixlen(neigh_addr, 128);
							}
							neighbor = rtnl_neigh_get(cache_neighborhood, rtnl_link_get_ifindex(link), neigh_addr);
							if (neighbor != NULL) {
								int state = rtnl_neigh_get_state(neighbor);
								if (state != NUD_FAILED && state != NUD_NOARP && state != 0) {
									fprintf(fd, ",");
									print_rtnl_neigh(neighbor, link, fd);
								}
							}
						}
						free(remote_addr);
					}
					free(local_addr);
				}
			} else if (errcode != 0) {
				char str_temp[BUFSIZ];
				regerror(errcode, &compiled_regex, str_temp, BUFSIZ);
				print_error("Unable to evaluate the regex for a network interface (%s): %s", str_link_name, str_temp);
			}
		} while ((addr = (struct rtnl_addr*)nl_cache_get_next((struct nl_object*)addr)) != NULL);
	}
	fprintf(fd, "]");

	regfree(&compiled_regex);
	nl_socket_free(nlsock_connection);
}

