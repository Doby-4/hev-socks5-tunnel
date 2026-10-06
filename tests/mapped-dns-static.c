#include "hev-mapped-dns-static.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static const uint8_t fake[4] = { 198, 18, 0, 10 }; /* Fixture, not a route. */
static HevMappedDNSStatic policy;
static unsigned tests;

static void
put16 (uint8_t *p, unsigned n)
{
    p[0] = n >> 8;
    p[1] = n;
}

static unsigned
get16 (const uint8_t *p)
{
    return ((unsigned)p[0] << 8) | p[1];
}

static size_t
query (uint8_t *p, const char *name, unsigned type)
{
    size_t n = 12;
    memset (p, 0, 512);
    put16 (p, 0x1234);
    put16 (p + 2, 0x0100);
    put16 (p + 4, 1);
    while (*name) {
        const char *dot = strchr (name, '.');
        size_t length = dot ? (size_t)(dot - name) : strlen (name);
        assert (length <= 63);
        p[n++] = (uint8_t)length;
        memcpy (p + n, name, length);
        n += length;
        name += length;
        if (*name == '.')
            name++;
    }
    p[n++] = 0;
    put16 (p + n, type);
    put16 (p + n + 2, 1);
    return n + 4;
}

static void
no_reply (const uint8_t *q, size_t n, HevMappedDNSStaticResult expected)
{
    uint8_t response[1024], before[1024];
    size_t length = 999;
    memset (response, 0xa5, sizeof (response));
    memcpy (before, response, sizeof (before));
    assert (hev_mapped_dns_static_reply (&policy, q, n, response,
                                         sizeof (response), &length) == expected);
    assert (length == 0);
    assert (memcmp (response, before, sizeof (response)) == 0);
}

static void
test_configuration (void)
{
    char name[] = "DF-Test.Dobytech.CN.";
    uint8_t address[] = { 198, 18, 0, 10 };
    assert (hev_mapped_dns_static_init (&policy, name, address) == 0);
    name[0] = 'x';
    address[3] = 11;
    assert (strcmp (policy.name, "df-test.dobytech.cn") == 0);
    assert (memcmp (policy.address, fake, 4) == 0);
    assert (hev_mapped_dns_static_matches (&policy, "DF-TEST.DOBYTECH.CN."));
    const char *misses[] = { "dobytech.cn", "www.df-test.dobytech.cn",
                            "df-test.dobytech.cn.evil.example", "xdf-test.dobytech.cn",
                            "df-test.dobytech.cn..", "", NULL };
    for (size_t i = 0; i < sizeof (misses) / sizeof (*misses); i++)
        assert (!hev_mapped_dns_static_matches (&policy, misses[i]));
    assert (strcmp (hev_mapped_dns_static_lookup (&policy, fake), policy.name) == 0);
    assert (!hev_mapped_dns_static_lookup (&policy, address));
    assert (!hev_mapped_dns_static_lookup (&policy, NULL));
    assert (!hev_mapped_dns_static_lookup (NULL, fake));
}

static void
test_invalid_configuration (void)
{
    HevMappedDNSStatic saved = policy;
    const char *bad[] = { "", ".", "a..b", "a..", "-a.test", "a-.test",
                         "*.test", "a_b.test", "a/b.test", "a\xff.test", NULL };
    for (size_t i = 0; i < sizeof (bad) / sizeof (*bad); i++) {
        assert (hev_mapped_dns_static_init (&policy, bad[i], fake) < 0);
        assert (memcmp (&policy, &saved, sizeof (policy)) == 0);
    }
    const uint8_t invalid[][4] = { { 0, 0, 0, 0 }, { 127, 0, 0, 1 },
                                  { 224, 0, 0, 1 }, { 255, 255, 255, 255 } };
    for (size_t i = 0; i < sizeof (invalid) / sizeof (*invalid); i++) {
        assert (hev_mapped_dns_static_init (&policy, "df-test.dobytech.cn", invalid[i]) < 0);
        assert (memcmp (&policy, &saved, sizeof (policy)) == 0);
    }
    assert (hev_mapped_dns_static_init (NULL, "a.test", fake) < 0);
    assert (hev_mapped_dns_static_init (&policy, "a.test", NULL) < 0);
}

static void
test_name_limits (void)
{
    char longest[256];
    HevMappedDNSStatic local;
    size_t n = 0;
    for (unsigned i = 0; i < 4; i++) {
        size_t length = i == 3 ? 61 : 63;
        memset (longest + n, 'a' + i, length);
        n += length;
        if (i != 3)
            longest[n++] = '.';
    }
    assert (n == 253);
    longest[n] = 0;
    assert (hev_mapped_dns_static_init (&local, longest, fake) == 0);
    uint8_t q[512], response[512];
    size_t size = query (q, longest, 1), answer;
    assert (hev_mapped_dns_static_reply (&local, q, size, response,
                                         sizeof (response), &answer) == HEV_MAPPED_DNS_STATIC_REPLY);
    assert (answer == size + 16);
    longest[n++] = '.';
    longest[n] = 0;
    assert (hev_mapped_dns_static_init (&local, longest, fake) == 0);
    longest[n - 1] = 'a'; /* 254 characters without final root dot. */
    assert (hev_mapped_dns_static_init (&local, longest, fake) < 0);
    memset (longest, 'a', 64);
    longest[64] = 0;
    assert (hev_mapped_dns_static_init (&local, longest, fake) < 0);
}

static void
test_answer (void)
{
    uint8_t q[512], saved[512], response[512];
    size_t n = query (q, "DF-Test.Dobytech.CN", 1), length;
    memcpy (saved, q, sizeof (q));
    memset (response, 0xa5, sizeof (response));
    assert (hev_mapped_dns_static_reply (&policy, q, n, response,
                                         sizeof (response), &length) == HEV_MAPPED_DNS_STATIC_REPLY);
    assert (length == n + 16);
    assert (get16 (response) == 0x1234);
    assert (get16 (response + 2) == 0x8100);
    assert (get16 (response + 4) == 1 && get16 (response + 6) == 1);
    assert (get16 (response + 8) == 0 && get16 (response + 10) == 0);
    assert (memcmp (q + 12, response + 12, n - 12) == 0);
    const uint8_t answer[] = { 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 1,
                               0, 4, 198, 18, 0, 10 };
    assert (memcmp (response + n, answer, sizeof (answer)) == 0);
    assert (response[length] == 0xa5);
    assert (memcmp (q, saved, sizeof (q)) == 0);
    put16 (q + 2, 0x0130); /* RD + AD + CD: never echo authenticated AD. */
    assert (hev_mapped_dns_static_reply (&policy, q, n, response,
                                         sizeof (response), &length) == HEV_MAPPED_DNS_STATIC_REPLY);
    assert (get16 (response + 2) == 0x8110);
    put16 (q + 2, 0);
    assert (hev_mapped_dns_static_reply (&policy, q, n, response,
                                         sizeof (response), &length) == HEV_MAPPED_DNS_STATIC_REPLY);
    assert (get16 (response + 2) == 0x8000);
}

static void
test_pass_and_types (void)
{
    uint8_t q[512];
    const char *names[] = { "dobytech.cn", "www.df-test.dobytech.cn",
                            "df-test.dobytech.cn.evil.example", "other.example", "" };
    for (size_t i = 0; i < sizeof (names) / sizeof (*names); i++)
        no_reply (q, query (q, names[i], 1), HEV_MAPPED_DNS_STATIC_PASS);
    unsigned types[] = { 28, 5, 64, 65, 255 }; /* AAAA, CNAME, SVCB, HTTPS, ANY. */
    for (size_t i = 0; i < sizeof (types) / sizeof (*types); i++) {
        no_reply (q, query (q, "df-test.dobytech.cn", types[i]), HEV_MAPPED_DNS_STATIC_UNSUPPORTED);
        no_reply (q, query (q, "other.example", types[i]), HEV_MAPPED_DNS_STATIC_PASS);
    }
    size_t n = query (q, "df-test.dobytech.cn", 1);
    put16 (q + n - 2, 3); /* CH, not IN. */
    no_reply (q, n, HEV_MAPPED_DNS_STATIC_UNSUPPORTED);
}

static void
test_truncation_and_headers (void)
{
    uint8_t q[512];
    size_t n = query (q, "df-test.dobytech.cn", 1);
    for (size_t i = 0; i < n; i++)
        no_reply (q, i, HEV_MAPPED_DNS_STATIC_INVALID);
    unsigned flags[] = { 0x8000, 0x0200, 0x0400, 0x0800, 0x0080, 0x0040, 1 };
    for (size_t i = 0; i < sizeof (flags) / sizeof (*flags); i++) {
        put16 (q + 2, flags[i]);
        no_reply (q, n, HEV_MAPPED_DNS_STATIC_INVALID);
    }
    put16 (q + 2, 0x0100);
    put16 (q + 4, 0);
    no_reply (q, n, HEV_MAPPED_DNS_STATIC_INVALID);
    put16 (q + 4, 2);
    no_reply (q, n, HEV_MAPPED_DNS_STATIC_INVALID);
    put16 (q + 4, 1);
    for (size_t i = 6; i <= 8; i += 2) {
        put16 (q + i, 1);
        no_reply (q, n, HEV_MAPPED_DNS_STATIC_INVALID);
        put16 (q + i, 0);
    }
    no_reply (q, n + 1, HEV_MAPPED_DNS_STATIC_INVALID);
}

static void
test_wire_names (void)
{
    uint8_t q[512];
    size_t n = query (q, "df-test.dobytech.cn", 1);
    q[12] = 0xc0; q[13] = 12; /* Cyclic compression pointer: not traversed. */
    no_reply (q, n, HEV_MAPPED_DNS_STATIC_UNSUPPORTED);
    query (q, "df-test.dobytech.cn", 1);
    q[12] = 63; /* Label exceeds remaining message. */
    no_reply (q, n, HEV_MAPPED_DNS_STATIC_INVALID);
    unsigned chars[] = { 0, '.', 0xff, '/', '_' };
    for (size_t i = 0; i < sizeof (chars) / sizeof (*chars); i++) {
        query (q, "df-test.dobytech.cn", 1);
        q[13] = (uint8_t)chars[i];
        no_reply (q, n, HEV_MAPPED_DNS_STATIC_UNSUPPORTED);
    }
    /* Four 63-byte labels are longer than the DNS name limit. */
    memset (q + 12, 0, 500);
    size_t off = 12;
    for (int i = 0; i < 4; i++) {
        q[off++] = 63;
        memset (q + off, 'a', 63);
        off += 63;
    }
    no_reply (q, off + 5, HEV_MAPPED_DNS_STATIC_INVALID);
}

static void
test_edns (void)
{
    uint8_t q[512], response[512];
    size_t n = query (q, "df-test.dobytech.cn", 1), length;
    put16 (q + 10, 1);
    put16 (q + n + 1, 41);
    put16 (q + n + 3, 4096);
    assert (hev_mapped_dns_static_reply (&policy, q, n + 11, response,
                                         sizeof (response), &length) == HEV_MAPPED_DNS_STATIC_REPLY);
    assert (length == n + 16 + 11 && get16 (response + 10) == 1);
    const uint8_t opt[] = { 0, 0, 41, 4, 208, 0, 0, 0, 0, 0, 0 };
    assert (memcmp (response + n + 16, opt, sizeof (opt)) == 0);
    for (size_t i = n; i < n + 11; i++)
        no_reply (q, i, HEV_MAPPED_DNS_STATIC_INVALID);
    q[n + 6] = 1; /* EDNS version 1. */
    no_reply (q, n + 11, HEV_MAPPED_DNS_STATIC_UNSUPPORTED);
    q[n + 6] = 0;
    q[n + 7] = 0x80; /* DO: no DNSSEC semantics are implemented. */
    no_reply (q, n + 11, HEV_MAPPED_DNS_STATIC_UNSUPPORTED);
    q[n + 7] = 0;
    put16 (q + n + 9, 4); /* Well-framed option: recognized as unsupported. */
    put16 (q + n + 11, 10);
    no_reply (q, n + 15, HEV_MAPPED_DNS_STATIC_UNSUPPORTED);
    put16 (q + n + 13, 1); /* Option content truncated. */
    no_reply (q, n + 15, HEV_MAPPED_DNS_STATIC_INVALID);
    no_reply (q, n + 14, HEV_MAPPED_DNS_STATIC_INVALID);
    put16 (q + 10, 2);
    no_reply (q, n + 15, HEV_MAPPED_DNS_STATIC_UNSUPPORTED);
}

static void
test_buffers_and_nulls (void)
{
    uint8_t q[512], response[512], saved[512];
    size_t n = query (q, "df-test.dobytech.cn", 1), length;
    memset (response, 0xa5, sizeof (response));
    memcpy (saved, response, sizeof (saved));
    for (size_t cap = 0; cap < n + 16; cap++) {
        assert (hev_mapped_dns_static_reply (&policy, q, n, response, cap, &length) ==
                HEV_MAPPED_DNS_STATIC_NO_SPACE);
        assert (length == 0 && memcmp (saved, response, sizeof (saved)) == 0);
    }
    assert (hev_mapped_dns_static_reply (&policy, q, n, response, n + 16, &length) ==
            HEV_MAPPED_DNS_STATIC_REPLY);
    assert (response[n + 16] == 0xa5);
    memcpy (saved, q, sizeof (q));
    assert (hev_mapped_dns_static_reply (&policy, q, n, q, sizeof (q), &length) ==
            HEV_MAPPED_DNS_STATIC_INVALID);
    assert (memcmp (q, saved, sizeof (q)) == 0);
    assert (hev_mapped_dns_static_reply (&policy, q, n, q + 1, sizeof (q) - 1, &length) ==
            HEV_MAPPED_DNS_STATIC_INVALID);
    uint8_t overlap[1024];
    memcpy (overlap + 64, q, n);
    assert (hev_mapped_dns_static_reply (&policy, overlap + 64, n, overlap + 63, 512, &length) ==
            HEV_MAPPED_DNS_STATIC_INVALID);
    assert (hev_mapped_dns_static_reply (NULL, q, n, response, 512, &length) == HEV_MAPPED_DNS_STATIC_INVALID);
    assert (hev_mapped_dns_static_reply (&policy, NULL, n, response, 512, &length) == HEV_MAPPED_DNS_STATIC_INVALID);
    assert (hev_mapped_dns_static_reply (&policy, q, n, NULL, 512, &length) == HEV_MAPPED_DNS_STATIC_INVALID);
    assert (hev_mapped_dns_static_reply (&policy, q, n, response, 512, NULL) == HEV_MAPPED_DNS_STATIC_INVALID);
    HevMappedDNSStatic empty = { 0 };
    assert (hev_mapped_dns_static_reply (&empty, q, n, response, 512, &length) == HEV_MAPPED_DNS_STATIC_INVALID);
}

static void
test_no_eviction_and_restart (void)
{
    uint8_t q[512];
    HevMappedDNSStatic saved = policy, recreated;
    for (int i = 0; i < 1000; i++) {
        char name[64];
        snprintf (name, sizeof (name), "other-%d.example", i);
        no_reply (q, query (q, name, 1), HEV_MAPPED_DNS_STATIC_PASS);
        assert (memcmp (&policy, &saved, sizeof (policy)) == 0);
    }
    assert (hev_mapped_dns_static_init (&recreated, "df-test.dobytech.cn", fake) == 0);
    assert (memcmp (&policy, &recreated, sizeof (policy)) == 0);
    /* This proves recreation from the same config, not persistence or recovery
     * of iOS DNS caches, TCP connections, or arbitrary later config changes. */
}

static uint32_t rng = 0x12345678;
static uint32_t
random_u32 (void)
{
    rng ^= rng << 13;
    rng ^= rng >> 17;
    rng ^= rng << 5;
    return rng;
}

static void
test_deterministic_mutations (void)
{
    uint8_t q[1024], saved[1024], response[1024], untouched[1024];
    HevMappedDNSStatic original = policy;
    for (unsigned trial = 0; trial < 20000; trial++) {
        size_t n;
        memset (q, 0, sizeof (q));
        if (trial & 1) {
            n = query (q, "df-test.dobytech.cn", 1);
            for (unsigned i = 0; i < 1 + trial % 4; i++)
                q[random_u32 () % n] ^= (uint8_t)random_u32 ();
        } else {
            n = random_u32 () % sizeof (q);
            for (size_t i = 0; i < n; i++)
                q[i] = (uint8_t)random_u32 ();
        }
        memcpy (saved, q, sizeof (q));
        memset (response, 0xa5, sizeof (response));
        memcpy (untouched, response, sizeof (response));
        size_t length = 999, cap = random_u32 () % sizeof (response);
        HevMappedDNSStaticResult result = hev_mapped_dns_static_reply (
            &policy, q, n, response, cap, &length);
        assert (memcmp (q, saved, sizeof (q)) == 0);
        assert (memcmp (&policy, &original, sizeof (policy)) == 0);
        if (result == HEV_MAPPED_DNS_STATIC_REPLY) {
            assert (length <= cap && length >= 28);
            assert (get16 (response + 6) == 1);
            assert (!(get16 (response + 2) & 0x04a0)); /* no AA/RA/AD */
            assert (memcmp (response + length, untouched + length, sizeof (response) - length) == 0);
        } else {
            assert (length == 0);
            assert (memcmp (response, untouched, sizeof (response)) == 0);
        }
    }
}

#define RUN(test) do { test (); tests++; puts ("PASS " #test); } while (0)
int
main (void)
{
    RUN (test_configuration);
    RUN (test_invalid_configuration);
    RUN (test_name_limits);
    RUN (test_answer);
    RUN (test_pass_and_types);
    RUN (test_truncation_and_headers);
    RUN (test_wire_names);
    RUN (test_edns);
    RUN (test_buffers_and_nulls);
    RUN (test_no_eviction_and_restart);
    RUN (test_deterministic_mutations);
    printf ("%u static mapped-DNS test groups passed (including 20000 deterministic mutations)\n", tests);
    return 0;
}
