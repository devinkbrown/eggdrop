/*
 * test_net.c - Tests for IP address handling
 *
 * Uses standard inet_pton/inet_ntop directly rather than pulling in
 * the full eggdrop net.c dependency graph.
 */

#include "test_harness.h"
#include <string.h>
#include <arpa/inet.h>

/* --- Helper matching eggdrop's iptostr logic --- */

static char *iptostr(struct sockaddr *sa)
{
  static char s[INET6_ADDRSTRLEN] = "";
  void *addr;

  if (sa->sa_family == AF_INET6)
    addr = &((struct sockaddr_in6 *)sa)->sin6_addr;
  else
    addr = &((struct sockaddr_in *)sa)->sin_addr;

  inet_ntop(sa->sa_family, addr, s, sizeof(s));
  return s;
}

/* --- Tests --- */

TEST(iptostr_localhost) {
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);

    char *result = iptostr((struct sockaddr *)&addr);
    ASSERT_STR_EQ(result, "127.0.0.1");
}

TEST(iptostr_zero_address) {
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    inet_pton(AF_INET, "0.0.0.0", &addr.sin_addr);

    char *result = iptostr((struct sockaddr *)&addr);
    ASSERT_STR_EQ(result, "0.0.0.0");
}

TEST(iptostr_broadcast) {
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    inet_pton(AF_INET, "255.255.255.255", &addr.sin_addr);

    char *result = iptostr((struct sockaddr *)&addr);
    ASSERT_STR_EQ(result, "255.255.255.255");
}

TEST(iptostr_common_addresses) {
    struct sockaddr_in addr;
    const char *test_ips[] = {
        "192.168.1.1",
        "10.0.0.1",
        "172.16.0.1",
        "8.8.8.8",
        "1.1.1.1"
    };

    for (size_t i = 0; i < sizeof(test_ips) / sizeof(test_ips[0]); i++) {
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        inet_pton(AF_INET, test_ips[i], &addr.sin_addr);

        char *result = iptostr((struct sockaddr *)&addr);
        ASSERT_STR_EQ(result, test_ips[i]);
    }
}

TEST(iptostr_ipv6_localhost) {
    struct sockaddr_in6 addr6;
    memset(&addr6, 0, sizeof(addr6));
    addr6.sin6_family = AF_INET6;
    inet_pton(AF_INET6, "::1", &addr6.sin6_addr);

    char *result = iptostr((struct sockaddr *)&addr6);
    ASSERT_STR_EQ(result, "::1");
}

TEST(iptostr_ipv6_zero) {
    struct sockaddr_in6 addr6;
    memset(&addr6, 0, sizeof(addr6));
    addr6.sin6_family = AF_INET6;
    inet_pton(AF_INET6, "::", &addr6.sin6_addr);

    char *result = iptostr((struct sockaddr *)&addr6);
    ASSERT_STR_EQ(result, "::");
}

TEST(inet_ntop_round_trip) {
    struct sockaddr_in addr;
    const char *test_ip = "192.168.100.50";

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    int result = inet_pton(AF_INET, test_ip, &addr.sin_addr);
    ASSERT_EQ(result, 1);

    char *converted = iptostr((struct sockaddr *)&addr);
    ASSERT_STR_EQ(converted, test_ip);
}

TEST(inet_pton_invalid_addresses) {
    struct sockaddr_in addr;
    const char *invalid_ips[] = {
        "256.256.256.256",
        "not.an.ip.addr",
        ""
    };

    for (size_t i = 0; i < sizeof(invalid_ips) / sizeof(invalid_ips[0]); i++) {
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        int result = inet_pton(AF_INET, invalid_ips[i], &addr.sin_addr);
        ASSERT_EQ(result, 0);
    }
}

int main(void) {
    TEST_MAIN_BEGIN;

    RUN_TEST(iptostr_localhost);
    RUN_TEST(iptostr_zero_address);
    RUN_TEST(iptostr_broadcast);
    RUN_TEST(iptostr_common_addresses);
    RUN_TEST(iptostr_ipv6_localhost);
    RUN_TEST(iptostr_ipv6_zero);
    RUN_TEST(inet_ntop_round_trip);
    RUN_TEST(inet_pton_invalid_addresses);

    TEST_MAIN_END;
}
