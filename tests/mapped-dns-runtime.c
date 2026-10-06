/* Real Hev gateway callbacks + lwIP IP/UDP + socketpair output. No device,
 * system routes, DNS servers, or cooperative task scheduler are started. */
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <lwip/init.h>
#include "hev-utils.h"
#include "../src/hev-socks5-tunnel.c"

unsigned int lwip_port_rand (void) { return 123456789U; }
static int bridge[2];
static uint8_t reply[8192];
static const char *domain = "df-test.dobytech.cn";

static void put16 (uint8_t *p, unsigned n) { p[0] = n >> 8; p[1] = n; }
static unsigned get16 (const uint8_t *p) { return (p[0] << 8) | p[1]; }

static int configure (const char *dns, const char *port, const char *network,
                      const char *mask, const char *name, const char *fake,
                      const char *extra)
{
    char config[2048];
    int n = snprintf (config, sizeof (config),
        "mapdns:\n  address: %s\n  port: %s\n  network: %s\n  netmask: %s\n"
        "  static-domain: %s\n  static-address: %s\n%s",
        dns, port, network, mask, name, fake, extra);
    assert (n > 0 && (size_t)n < sizeof (config));
    return hev_config_init_from_str ((const unsigned char *)config, n);
}

static void good_config (void)
{
    assert (configure ("198.18.0.1", "53", "198.18.0.0", "255.255.255.0",
                       "DF-Test.Dobytech.CN.", "198.18.0.10", "") == 0);
}

static void test_config (void)
{
    good_config ();
    assert (!strcmp (hev_config_get_mapdns_static ()->name, domain));
    const char *bad_ports[] = { "0", "65536", "-1", "53x", "999999999999999999999999" };
    for (unsigned i = 0; i < sizeof (bad_ports) / sizeof (*bad_ports); i++)
        assert (configure ("198.18.0.1", bad_ports[i], "198.18.0.0", "255.255.255.0",
                           domain, "198.18.0.10", "") < 0);
    const char *bad_ips[] = { "invalid", "198.18.0.1", "198.18.0.0", "198.18.0.255", "198.19.0.10" };
    for (unsigned i = 0; i < sizeof (bad_ips) / sizeof (*bad_ips); i++)
        assert (configure ("198.18.0.1", "53", "198.18.0.0", "255.255.255.0",
                           domain, bad_ips[i], "") < 0);
    assert (configure ("198.18.0.1", "53", "198.18.0.0", "255.0.255.0", domain, "198.18.0.10", "") < 0);
    assert (configure ("198.18.0.1", "53", "198.18.0.7", "255.255.255.0", domain, "198.18.0.10", "") < 0);
    assert (configure ("198.18.0.1", "53", "198.18.0.0", "255.255.255.0", "'*.example'", "198.18.0.10", "") < 0);
    assert (configure ("198.18.0.1", "53", "198.18.0.0", "255.255.255.0", domain, "198.18.0.10", "  cache-size: 10\n") < 0);
    assert (configure ("198.18.0.1", "53", "198.18.0.0", "255.255.255.0", domain, "198.18.0.10", "  port: 53\n") < 0);
    assert (configure ("198.18.0.1", "53", "198.18.0.0", "255.255.255.0", domain, "198.18.0.10", "mapdns: {}\n") < 0);
    const char *partial = "mapdns:\n  static-domain: df-test.dobytech.cn\n";
    assert (hev_config_init_from_str ((const unsigned char *)partial, strlen (partial)) < 0);
    good_config ();
    assert (hev_config_init_from_str ((const unsigned char *)"tunnel: {}", 10) == 0);
    assert (!hev_config_get_mapdns_static ());
    assert (mapped_dns_init () == 0 && !hev_mapped_dns_get ());
    puts ("PASS strict static configuration, duplicate rejection and reset to disabled");
}

static size_t query (uint8_t *p, const char *name, unsigned type)
{
    size_t n = 12;
    memset (p, 0, 512);
    put16 (p, 0x1234); put16 (p + 2, 0x0100); put16 (p + 4, 1);
    while (*name) {
        const char *dot = strchr (name, '.');
        size_t length = dot ? (size_t)(dot - name) : strlen (name);
        p[n++] = length;
        memcpy (p + n, name, length); n += length; name += length;
        if (*name == '.') name++;
    }
    p[n++] = 0; put16 (p + n, type); put16 (p + n + 2, 1);
    return n + 4;
}

static unsigned checksum (const uint8_t *p, size_t n, unsigned sum)
{
    for (; n > 1; n -= 2, p += 2) sum += get16 (p);
    if (n) sum += *p << 8;
    while (sum >> 16) sum = (sum & 65535) + (sum >> 16);
    return (~sum) & 65535;
}

static ssize_t exchange (const uint8_t *q, size_t length, size_t split)
{
    uint8_t packet[5000] = { 0 };
    size_t size = 28 + length;
    const uint8_t src[] = { 192, 0, 2, 2 }, dst[] = { 198, 18, 0, 1 };
    assert (size <= sizeof (packet));
    packet[0] = 0x45; put16 (packet + 2, size); packet[8] = 64; packet[9] = 17;
    memcpy (packet + 12, src, 4); memcpy (packet + 16, dst, 4);
    put16 (packet + 10, checksum (packet, 20, 0));
    put16 (packet + 20, 53000); put16 (packet + 22, 53); put16 (packet + 24, length + 8);
    memcpy (packet + 28, q, length);
    unsigned pseudo = get16 (src) + get16 (src + 2) + get16 (dst) + get16 (dst + 2) + 17 + length + 8;
    unsigned check = checksum (packet + 20, length + 8, pseudo);
    put16 (packet + 26, check ? check : 65535);
    if (!split) split = size;
    assert (split <= size);
    struct pbuf *p = pbuf_alloc (PBUF_RAW, split, PBUF_RAM);
    assert (p && pbuf_take (p, packet, split) == ERR_OK);
    if (split < size) {
        struct pbuf *tail = pbuf_alloc (PBUF_RAW, size - split, PBUF_RAM);
        assert (tail && pbuf_take (tail, packet + split, size - split) == ERR_OK);
        pbuf_cat (p, tail);
    }
    assert (netif->input (p, netif) == ERR_OK);
    ssize_t n = recv (bridge[1], reply, sizeof (reply), MSG_DONTWAIT);
    if (n < 0) {
        assert (errno == EAGAIN || errno == EWOULDBLOCK);
        return n;
    }
    assert (n >= 32 + 12 && get16 (reply + 2) == AF_INET);
    const uint8_t *ip = reply + 4;
    assert (get16 (ip + 2) == n - 4 && checksum (ip, 20, 0) == 0);
    assert (!memcmp (ip + 12, dst, 4) && !memcmp (ip + 16, src, 4));
    assert (ip[9] == 17 && get16 (ip + 20) == 53 && get16 (ip + 22) == 53000);
    assert (get16 (ip + 24) == n - 24);
    if (get16 (ip + 26)) {
        pseudo = get16 (src) + get16 (src + 2) + get16 (dst) + get16 (dst + 2) + 17 + n - 24;
        assert (checksum (ip + 20, n - 24, pseudo) == 0);
    }
    return n - 32;
}

static void test_udp (void)
{
    uint8_t q[512];
    size_t n = query (q, "DF-Test.Dobytech.CN", 1);
    const uint8_t fake[] = { 198, 18, 0, 10 };
    for (unsigned i = 0; i < 100; i++) {
        assert (exchange (q, n, i & 1 ? 38 : 0) == (ssize_t)n + 16);
        assert (get16 (reply + 32) == 0x1234 && get16 (reply + 34) == 0x8100);
        assert (get16 (reply + 38) == 1);
        assert (!memcmp (reply + 32 + n + 12, fake, 4));
        assert (hev_mapped_dns_get ()->use == 0);
    }
    n = query (q, "other.example", 1);
    assert (exchange (q, n, 38) == (ssize_t)n && (reply[35] & 15) == 5);
    assert (get16 (reply + 36) == 1 && !memcmp (reply + 44, q + 12, n - 12));
    unsigned types[] = { 28, 65, 64, 255 };
    for (unsigned i = 0; i < sizeof (types) / sizeof (*types); i++) {
        n = query (q, domain, types[i]);
        assert (exchange (q, n, 38) == (ssize_t)n && (reply[35] & 15) == 4);
    }
    n = query (q, domain, 1);
    assert (exchange (q, n - 1, 38) == 12 && (reply[35] & 15) == 1);
    q[2] |= 0x80;
    assert (exchange (q, n, 38) < 0); /* No response loops. */
    assert (exchange (q, 5, 0) < 0);
    assert (udp_pcbs == udp && !udp->next); /* No per-query PCB leak. */
    puts ("PASS real gateway UDP replies, chained pbufs, errors, repeated queries and cleanup");
}

static void test_reverse (void)
{
    HevSocks5Addr address;
    ip_addr_t ip;
    assert (ipaddr_aton ("198.18.0.10", &ip));
    assert (hev_socks5_addr_from_lwip (&address, &ip, 18081) == 0);
    assert (address.atype == HEV_SOCKS5_ADDR_TYPE_NAME);
    assert (address.domain.len == strlen (domain));
    assert (!memcmp (address.domain.addr, domain, strlen (domain)));
    assert (get16 (address.domain.addr + address.domain.len) == 18081);
    const char *unknown[] = { "198.18.0.1", "198.18.0.11", "198.18.0.255" };
    for (unsigned i = 0; i < sizeof (unknown) / sizeof (*unknown); i++) {
        assert (ipaddr_aton (unknown[i], &ip));
        assert (hev_socks5_addr_from_lwip (&address, &ip, 443) < 0);
    }
    assert (ipaddr_aton ("120.26.147.9", &ip));
    assert (hev_socks5_addr_from_lwip (&address, &ip, 18081) == 0);
    assert (address.atype == HEV_SOCKS5_ADDR_TYPE_IPV4);
    assert (!memcmp (address.ipv4.addr, &ip.u_addr.ip4.addr, 4));
    assert (ntohs (address.ipv4.port) == 18081);
    puts ("PASS shared mapping to SOCKS domain, port preservation and unknown Fake IP rejection");
}

static void test_tcp_rejection (void)
{
    struct tcp_pcb *pcb = tcp_new ();
    assert (pcb);
    IP_ADDR4 (&pcb->local_ip, 198, 18, 0, 1);
    IP_ADDR4 (&pcb->remote_ip, 192, 0, 2, 2);
    pcb->local_port = 53; pcb->remote_port = 53000; pcb->state = ESTABLISHED;
    TCP_REG_ACTIVE (pcb);
    assert (tcp_accept_handler (NULL, pcb, ERR_OK) == ERR_ABRT);
    assert (!tcp_active_pcbs && !session_count);
    ssize_t n = recv (bridge[1], reply, sizeof (reply), MSG_DONTWAIT);
    assert (n >= 44 && reply[13] == 6 && (reply[37] & 4)); /* TCP RST */
    puts ("PASS DNS TCP explicitly reset, no SOCKS session created (DNS TCP not implemented)");
}

static void test_adapter (void)
{
    uint8_t q[512], before[512], out[512];
    size_t n = query (q, domain, 1);
    HevMappedDNS *dns = hev_mapped_dns_get ();
    memcpy (before, q, sizeof (q));
    memset (out, 0xa5, sizeof (out));
    assert (hev_mapped_dns_handle (dns, q, n, out, 11) < 0);
    assert (out[0] == 0xa5);
    assert (hev_mapped_dns_handle (dns, q, n, q, sizeof (q)) < 0);
    assert (!memcmp (q, before, sizeof (q)));
    assert (hev_mapped_dns_handle (dns, NULL, n, out, sizeof (out)) < 0);
    assert (hev_mapped_dns_handle (dns, q, n, NULL, 512) < 0);
    assert (hev_mapped_dns_handle (dns, q, -1, out, 512) < 0);
    /* Error adapter must not fabricate data, RA, AA or authenticated AD. */
    n = query (q, domain, 28); put16 (q + 2, 0x0130);
    assert (hev_mapped_dns_handle (dns, q, n, out, sizeof (out)) == (int)n);
    assert (get16 (out + 2) == 0x8114 && get16 (out + 4) == 1);
    assert (!memcmp (out + 12, q + 12, n - 12) && out[n] == 0xa5);
    put16 (q + 2, 0x0900);
    assert (hev_mapped_dns_handle (dns, q, n, out, sizeof (out)) == (int)n);
    assert (get16 (out + 2) == 0x8904);
    puts ("PASS adapter buffer guards and explicit error flags");
}

static void test_legacy (void)
{
    const char *config = "mapdns:\n  address: 198.18.0.1\n  port: 53\n"
                         "  network: 100.64.0.0\n  netmask: 255.192.0.0\n  cache-size: 10\n";
    assert (hev_config_init_from_str ((const unsigned char *)config, strlen (config)) == 0);
    assert (!hev_config_get_mapdns_static ());
    assert (mapped_dns_init () == 0);
    uint8_t q[512], out[512];
    size_t n = query (q, domain, 1);
    HevMappedDNS *dns = hev_mapped_dns_get ();
    assert (hev_mapped_dns_handle (dns, q, n, out, sizeof (out)) == (int)n + 16);
    assert (!strcmp (hev_mapped_dns_lookup (dns, 0x64400000), domain));
    assert (!hev_mapped_dns_is_reserved (dns, 0x64400001));
    mapped_dns_fini ();
    puts ("PASS legacy dynamic mode still opt-in and functional for a valid A query");
}

int main (void)
{
    setbuf (stdout, NULL);
    test_config ();
    lwip_init ();
    assert (socketpair (AF_UNIX, SOCK_DGRAM, 0, bridge) == 0);
    tun_fd = bridge[0]; run = 1;
    for (unsigned round = 0; round < 2; round++) {
        good_config ();
        assert (mapped_dns_init () == 0);
        assert (gateway_init () == 0);
        test_udp ();
        test_reverse ();
        test_adapter ();
        test_tcp_rejection ();
        gateway_fini ();
        mapped_dns_fini ();
        assert (!hev_mapped_dns_get ());
    }
    test_legacy ();
    close (bridge[0]); close (bridge[1]);
    puts ("PASS mapping/gateway stop and recreation (not device cache or active connection recovery)");
    return 0;
}
