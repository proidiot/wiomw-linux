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

void ipv42str(struct nl_addr* addr, char* str_result, size_t size_bufsiz)
{
	uint8_t* binary_addr = (uint8_t*)nl_addr_get_binary_addr(addr);
	snprintf(str_result, size_bufsiz, "%u.%u.%u.%u", binary_addr[0], binary_addr[1], binary_addr[2], binary_addr[3]);
}

void ipv62str(struct nl_addr* addr, char* str_result, size_t size_bufsiz)
{
	uint16_t* binary_addr = (uint16_t*)nl_addr_get_binary_addr(addr);
	snprintf(
			str_result,
			size_bufsiz,
			"%hx:%hx:%hx:%hx:%hx:%hx:%hx:%hx",
			binary_addr[0],
			binary_addr[1],
			binary_addr[2],
			binary_addr[3],
			binary_addr[4],
			binary_addr[5],
			binary_addr[6],
			binary_addr[7]);
}

void print_neighbours()
{
	struct nl_cache* cache_neighborhood;
	struct nl_cache* cache_links;
	struct nl_cache* cache_addresses;
	struct rtnl_neigh* neighbor;
	struct rtnl_addr* addr;
	int errcode;
	regex_t compiled_regex;
	/*TODO: remove!!!!!! */
	int tempy = 0;
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

	printf("[%d", 12345);
	if ((addr = (struct rtnl_addr*)nl_cache_get_first(cache_addresses)) != NULL) {
		do {
			struct rtnl_link* link = rtnl_addr_get_link(addr);
			char* str_link_name = rtnl_link_get_name(link);
			errcode = regexec(&compiled_regex, str_link_name, 0, NULL, 0);
			if (errcode == REG_NOMATCH) {
				struct nl_addr* ipaddr = rtnl_addr_get_local(addr);
				if (ipaddr != NULL && nl_addr_get_family(ipaddr) == AF_INET) {
					char str_temp[BUFSIZ];
					printf(",{\"local\":true,");
					nl_addr2str(rtnl_link_get_addr(link), str_temp, BUFSIZ);
					printf("\"mac\":\"%s\",", str_temp);
					ipv42str(ipaddr, str_temp, BUFSIZ);
					printf("\"ip\":\"%s\",", str_temp);
					printf("\"iface\":\"%s\",", rtnl_link_get_name(link));
					printf("\"state\":\"reachable\"}");
					tempy = rtnl_link_get_ifindex(link);
				} else if (ipaddr != NULL && nl_addr_get_family(ipaddr) == AF_INET6) {
					char str_temp[BUFSIZ];
					printf(",{\"local\":true,");
					nl_addr2str(rtnl_link_get_addr(link), str_temp, BUFSIZ);
					printf("\"mac\":\"%s\",", str_temp);
					ipv62str(ipaddr, str_temp, BUFSIZ);
					printf("\"ip6\":\"%s\",", str_temp);
					printf("\"iface\":\"%s\",", rtnl_link_get_name(link));
					printf("\"state\":\"reachable\"}");
				}
			} else if (errcode != 0) {
				char str_temp[BUFSIZ];
				regerror(errcode, &compiled_regex, str_temp, BUFSIZ);
				print_error("Unable to evaluate the regex for a network interface (%s): %s", str_link_name, str_temp);
			}
		} while ((addr = (struct rtnl_addr*)nl_cache_get_next((struct nl_object*)addr)) != NULL);
	}
	
	errcode = rtnl_neigh_alloc_cache(nlsock_connection, &cache_neighborhood);
	if (errcode < 0) {
		print_error("Unable to get neighborhood: %s", nl_geterror(-errcode));
		exit(EX_SOFTWARE);
	}

	if (tempy != 0) {
		char str_temp[BUFSIZ];
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
		/*
		neighbor = rtnl_neigh_alloc();
		rtnl_neigh_set_ifindex(neighbor, tempy);
		rtnl_neigh_set_dst(neighbor, temp_addr);
		rtnl_neigh_set_state(neighbor, NUD_PROBE);
		errcode = rtnl_neigh_add(nlsock_connection, neighbor, 0);
		if (errcode < 0) {
			print_error("Unable to add: %s", nl_geterror(-errcode));
		}
		*/
		neighbor = rtnl_neigh_get(cache_neighborhood, tempy, temp_addr);
		if (neighbor != NULL) {
			printf(",{");
			nl_addr2str(rtnl_neigh_get_lladdr(neighbor), str_temp, BUFSIZ);
			printf("\"mac\":\"%s\",", str_temp);
			nl_addr2str(rtnl_neigh_get_dst(neighbor), str_temp, BUFSIZ);
			printf("\"ip\":\"%s\",", str_temp);
			rtnl_neigh_state2str(rtnl_neigh_get_state(neighbor), str_temp, BUFSIZ);
			printf("\"state\":\"%s\",", str_temp);
			printf("\"iface\":\"%s\"", rtnl_link_get_name(rtnl_link_get(cache_links, rtnl_neigh_get_ifindex(neighbor))));
			printf("}");
		} else  {
			print_error("No such luck, charlie!");
		}
	} else if ((neighbor = (struct rtnl_neigh*)nl_cache_get_first(cache_neighborhood)) != NULL) {
		do {
			char str_temp[BUFSIZ];
			printf(",{");
			nl_addr2str(rtnl_neigh_get_lladdr(neighbor), str_temp, BUFSIZ);
			printf("\"mac\":\"%s\",", str_temp);
			nl_addr2str(rtnl_neigh_get_dst(neighbor), str_temp, BUFSIZ);
			printf("\"ip\":\"%s\",", str_temp);
			rtnl_neigh_state2str(rtnl_neigh_get_state(neighbor), str_temp, BUFSIZ);
			printf("\"state\":\"%s\",", str_temp);
			printf("\"iface\":\"%s\"", rtnl_link_get_name(rtnl_link_get(cache_links, rtnl_neigh_get_ifindex(neighbor))));
			printf("}");
		} while ((neighbor = (struct rtnl_neigh*)nl_cache_get_next((struct nl_object*)neighbor)) != NULL);
	}
	printf("]");

	regfree(&compiled_regex);
	nl_socket_free(nlsock_connection);
}

