#include <config.h>
#include "neighbours.h"
#include "print_error.h"
#include <stdio.h>
#include <netlink/netlink.h>
#include <netlink/route/neighbour.h>
#include <netlink/route/link.h>
#include <netlink/route/addr.h>
#include <sysexits.h>
#include <regex.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

void print_rtnl_addr(struct rtnl_addr* addr)
{
	int errcode = 0;
	struct rtnl_link* link = rtnl_addr_get_link(addr);
	struct nl_addr* ipaddr = rtnl_addr_get_local(addr);
	if (ipaddr != NULL && nl_addr_get_family(ipaddr) == AF_INET) {
		char str_temp[BUFSIZ];
		struct sockaddr_in saddr;
		socklen_t slen = sizeof(struct sockaddr_in);
		memset(&saddr, 0, slen);
		printf("{\"agent\":1,");
		nl_addr2str(rtnl_link_get_addr(link), str_temp, BUFSIZ);
		printf("\"mac\":\"%s\",", str_temp);
		errcode = nl_addr_fill_sockaddr(ipaddr, (struct sockaddr*)&saddr, &slen);
		if (errcode < 0) {
			print_error("Unable to parse address: %s", nl_geterror(-errcode));
		} else if (inet_ntop(AF_INET, &saddr.sin_addr.s_addr, str_temp, slen) ==  NULL) {
			print_syserror("Unable to parse address");
		} else {
			printf("\"ip\":\"%s\",", str_temp);
		}
		printf("\"iface\":\"%s\",", rtnl_link_get_name(link));
		printf("\"state\":\"reachable\"}");
	} else if (ipaddr != NULL && nl_addr_get_family(ipaddr) == AF_INET6) {
		char str_temp[BUFSIZ];
		struct sockaddr_in6 saddr;
		socklen_t slen = sizeof(struct sockaddr_in6);
		memset(&saddr, 0, slen);
		printf("{\"agent\":1,");
		nl_addr2str(rtnl_link_get_addr(link), str_temp, BUFSIZ);
		printf("\"mac\":\"%s\",", str_temp);
		errcode = nl_addr_fill_sockaddr(ipaddr, (struct sockaddr*)&saddr, &slen);
		if (errcode < 0) {
			print_error("Unable to parse address: %s", nl_geterror(-errcode));
		} else if (inet_ntop(AF_INET6, &saddr.sin6_addr.s6_addr, str_temp, slen) ==  NULL) {
			print_syserror("Unable to parse address");
		} else {
			printf("\"ip6\":\"%s\",", str_temp);
		}
		printf("\"iface\":\"%s\",", rtnl_link_get_name(link));
		printf("\"state\":\"reachable\"}");
	}
}

void print_rtnl_neigh(struct rtnl_neigh* neighbor, struct rtnl_link* link)
{
	char str_temp[BUFSIZ];
	printf("{");
	nl_addr2str(rtnl_neigh_get_lladdr(neighbor), str_temp, BUFSIZ);
	printf("\"mac\":\"%s\",", str_temp);
	nl_addr2str(rtnl_neigh_get_dst(neighbor), str_temp, BUFSIZ);
	printf("\"ip\":\"%s\",", str_temp);
	rtnl_neigh_state2str(rtnl_neigh_get_state(neighbor), str_temp, BUFSIZ);
	printf("\"state\":\"%s\",", str_temp);
	printf("\"iface\":\"%s\"", rtnl_link_get_name(link));
	printf("}");
}

int increment_addr(
		struct sockaddr* addr_base,
		socklen_t size_base,
		uint8_t prefix,
		struct sockaddr* addr_to_increment,
		socklen_t size_sock)
{
	if (addr_base == NULL) {
		return -1;
	} else if (size_base == 0) {
		return -2;
	} else if (addr_to_increment == NULL) {
		return -3;
	} else if (size_sock < size_base) {
		return -4;
	} else if (addr_base->sa_family != AF_INET && addr_base->sa_family != AF_INET6) {
		return -5;
	} else if (prefix > 32 && addr_base->sa_family == AF_INET) {
		return -6;
	} else if (prefix > 128 && addr_base->sa_family == AF_INET6) {
		return -7;
	} else if (prefix == 32 && addr_base->sa_family == AF_INET) {
		return -8;
	} else if (prefix == 128 && addr_base->sa_family == AF_INET6) {
		return -9;
	} else if (prefix == 0 && addr_base->sa_family == AF_INET) {
		print_error("Full rage IP enumeration is currently not allowed");
		return -999;
	} else if (prefix == 0 && addr_base->sa_family == AF_INET6) {
		print_error("Full rage IP enumeration is currently not allowed");
		return -999;
	} else if (addr_base->sa_family == AF_INET) {
		struct sockaddr_in* base = (struct sockaddr_in*)addr_base;
		struct sockaddr_in* addr = (struct sockaddr_in*)addr_to_increment;
		uint8_t suffix = 32 - prefix;
		unsigned long base_ip = (ntohl(base->sin_addr.s_addr) >> suffix) << suffix;
		unsigned long bcast_ip = (((ntohl(base->sin_addr.s_addr) >> suffix) + 1) << suffix) - 1;
		unsigned long ip = ntohl(addr->sin_addr.s_addr);

		if (ip == 0) {
			ip = base_ip + 1;
		} else if (ip > base_ip && ip < bcast_ip) {
			ip++;
		} else {
			return -10;
		}

		addr->sin_family = AF_INET;
		addr->sin_addr.s_addr = htonl(ip);

		return bcast_ip - ip;
	} else {
		/* TODO: fixme */
		print_error("The code for IPv6 enumeration has not yet been completed");
		return -999;
	}
}

int check_addr_range(
		struct sockaddr* addr_base,
		socklen_t size_base,
		uint8_t prefix,
		struct sockaddr* addr_to_check,
		socklen_t size_sock)
{
	if (addr_base == NULL) {
		return -1;
	} else if (size_base == 0) {
		return -2;
	} else if (addr_to_check == NULL) {
		return -3;
	} else if (size_sock == 0) {
		return -4;
	} else if (addr_base->sa_family != AF_INET && addr_base->sa_family != AF_INET6) {
		return -5;
	} else if (addr_base->sa_family != addr_to_check->sa_family) {
		return -8;
	} else if (prefix > 32 && addr_base->sa_family == AF_INET) {
		return -6;
	} else if (prefix > 128 && addr_base->sa_family == AF_INET6) {
		return -7;
	} else if (addr_base->sa_family != addr_to_check->sa_family) {
		return -8;
	} else if (prefix == 32 && addr_base->sa_family == AF_INET) {
		return ((struct sockaddr_in*)addr_base)->sin_addr.s_addr == ((struct sockaddr_in*)addr_to_check)->sin_addr.s_addr;
	} else if (prefix == 128 && addr_base->sa_family == AF_INET6) {
		/* TODO: fixme */
		print_error("The code for IPv6 comparison has not yet been completed");
		return -999;
	} else if (prefix == 0) {
		return (1==1);
	} else if (addr_base->sa_family == AF_INET) {
		struct sockaddr_in* base = (struct sockaddr_in*)addr_base;
		struct sockaddr_in* addr = (struct sockaddr_in*)addr_to_check;
		uint8_t suffix = 32 - prefix;
		unsigned long base_ip = (ntohl(base->sin_addr.s_addr) >> suffix) << suffix;
		unsigned long bcast_ip = (((ntohl(base->sin_addr.s_addr) >> suffix) + 1) << suffix) - 1;
		unsigned long ip = ntohl(addr->sin_addr.s_addr);

		if (ip > base_ip && ip < bcast_ip) {
			return (1==1);
		} else {
			return (1==0);
		}
	} else {
		/* TODO: fixme */
		print_error("The code for IPv6 comparison has not yet been completed");
		return -999;
	}
}

int check_scannable_range(struct sockaddr* addr, socklen_t slen, uint8_t prefix)
{
	if (addr == NULL) {
		return -1;
	} else if (slen == 0) {
		return -2;
	} else if (addr->sa_family == AF_INET) {
		struct sockaddr_in safe_addr;
		socklen_t safe_len = sizeof(struct sockaddr_in);
		memset(&safe_addr, 0, safe_len);
		safe_addr.sin_family = AF_INET;

		inet_pton(AF_INET, "10.0.0.0", &safe_addr.sin_addr.s_addr);
		if (check_addr_range((struct sockaddr*)&safe_addr, safe_len, 8, addr, slen) && prefix >= 8) {
			return (1==1);
		}

		inet_pton(AF_INET, "172.16.0.0", &safe_addr.sin_addr.s_addr);
		if (check_addr_range((struct sockaddr*)&safe_addr, safe_len, 12, addr, slen) && prefix >= 12) {
			return (1==1);
		}

		inet_pton(AF_INET, "192.168.0.0", &safe_addr.sin_addr.s_addr);
		if (check_addr_range((struct sockaddr*)&safe_addr, safe_len, 16, addr, slen) && prefix >= 16) {
			return (1==1);
		}

		return (1==0);
	} else if (addr->sa_family == AF_INET6) {
		/* TODO: fixme */
		print_error("The code for IPv6 acceptable range checking has not yet been completed");
		return -999;
	} else {
		print_error("Unable to check if address is within an acceptable range: Unknown address family");
		return -1;
	}
}

void print_neighbours()
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

	printf("[%d", 12345);
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
					printf(",");
					print_rtnl_addr(addr);
					if (check_scannable_range(local_addr, socklen_local_addr, prefix) > 0) {
						socklen_t socklen_remote_addr = socklen_local_addr;
						struct sockaddr* remote_addr = (struct sockaddr*)malloc(socklen_remote_addr);
						memset(remote_addr, 0, socklen_remote_addr);
						while (increment_addr(local_addr, socklen_local_addr, prefix, remote_addr, socklen_remote_addr) > 0) {
							/*
							int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
							if (sockfd == -1) {
								print_syserror("Unable to create socket");
							} else {
								errcode = connect(sockfd, (struct sockaddr*)remote_addr, socklen_remote_addr);
								if (errcode == -1) {
									print_syserror("Unable to send on socket");
								}
							}
							close(sockfd);
							*/
							struct rtnl_neigh* neighbor;
							struct nl_addr* neigh_addr;
							struct nl_addr* mac_addr;
							if (remote_addr->sa_family == AF_INET) {
								neigh_addr = nl_addr_build(AF_INET, &((struct sockaddr_in*)remote_addr)->sin_addr.s_addr, sizeof(((struct sockaddr_in*)remote_addr)->sin_addr.s_addr));
								nl_addr_set_prefixlen(neigh_addr, 32);
							} else {
								neigh_addr = nl_addr_build(AF_INET6, &((struct sockaddr_in6*)remote_addr)->sin6_addr.s6_addr, sizeof(((struct sockaddr_in6*)remote_addr)->sin6_addr.s6_addr));
								nl_addr_set_prefixlen(neigh_addr, 128);
							}
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
								print_error("Unable to add: %s", nl_geterror(-errcode));
							}
							neighbor = rtnl_neigh_get(cache_neighborhood, rtnl_link_get_ifindex(link), neigh_addr);
							if (neighbor != NULL) {
								printf(",");
								print_rtnl_neigh(neighbor, link);
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
	printf("]");

	regfree(&compiled_regex);
	nl_socket_free(nlsock_connection);
	
	/*
	if (tempy != 0) {
		int sockfd = socket(AF_INET, SOCK_STREAM, 0);
		struct nl_addr* temp_addr;
		nl_addr_parse("10.0.1.180", AF_INET, &temp_addr);
		if (sockfd == -1) {
			print_syserror("Unable to create socket");
		} else {
			struct sockaddr_in sockaddr;
			socklen_t socklen = sizeof(struct sockaddr_in);
			memset(&sockaddr, 0, socklen);
			sockaddr.sin_family = AF_INET;
			sockaddr.sin_port = htons(9);
			inet_aton("10.0.1.180", (struct in_addr*)&sockaddr.sin_addr.s_addr);
			errcode = connect(sockfd, (struct sockaddr*)&sockaddr, socklen);
			if (errcode == -1) {
				print_syserror("Unable to send on socket");
			}
		}
		neighbor = rtnl_neigh_alloc();
		rtnl_neigh_set_ifindex(neighbor, tempy);
		rtnl_neigh_set_dst(neighbor, temp_addr);
		rtnl_neigh_set_state(neighbor, NUD_PROBE);
		errcode = rtnl_neigh_add(nlsock_connection, neighbor, 0);
		if (errcode < 0) {
			print_error("Unable to add: %s", nl_geterror(-errcode));
		}
		neighbor = rtnl_neigh_get(cache_neighborhood, tempy, temp_addr);
		if (neighbor != NULL) {
			printf(",");
			print_rtnl_neigh(neighbor, rtnl_link_get(cache_links, tempy));
		} else  {
			print_error("No neighbor found at: %s");
		}
	} else if ((neighbor = (struct rtnl_neigh*)nl_cache_get_first(cache_neighborhood)) != NULL) {
		do {
			printf(",");
			print_rtnl_neigh(neighbor, rtnl_link_get(cache_links, rtnl_neigh_get_ifindex(neighbor)));
		} while ((neighbor = (struct rtnl_neigh*)nl_cache_get_next((struct nl_object*)neighbor)) != NULL);
	}
	*/
}

