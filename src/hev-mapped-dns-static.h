/* Offline, single-domain policy for the first selective mapped-DNS experiment.
 * Not yet connected to the tunnel's legacy mapped-DNS handler. */
#ifndef __HEV_MAPPED_DNS_STATIC_H__
#define __HEV_MAPPED_DNS_STATIC_H__

#include <stddef.h>
#include <stdint.h>

typedef struct
{
    char name[254];
    uint8_t address[4]; /* IPv4 bytes in network order. */
} HevMappedDNSStatic;

typedef enum
{
    HEV_MAPPED_DNS_STATIC_INVALID = -1,
    HEV_MAPPED_DNS_STATIC_NO_SPACE = -2,
    HEV_MAPPED_DNS_STATIC_UNSUPPORTED = -3,
    HEV_MAPPED_DNS_STATIC_PASS = 0,
    HEV_MAPPED_DNS_STATIC_REPLY = 1,
} HevMappedDNSStaticResult;

/* Initialize before publishing; do not reinitialize while queries/connections
 * use it. Copies both inputs. An invalid initialization leaves self unchanged.
 * Hostnames are ASCII LDH / IDNA A-labels, case-insensitive, exact matches;
 * one trailing dot is accepted. No suffix rules or wildcard expansion.
 * The caller must reserve a non-conflicting Fake IP for this domain across
 * restarts. This object never allocates, evicts, expires or reuses addresses. */
int hev_mapped_dns_static_init (HevMappedDNSStatic *self, const char *name,
                                const uint8_t address[4]);
int hev_mapped_dns_static_matches (const HevMappedDNSStatic *self,
                                   const char *name);
/* NULL means unknown, not permission to connect to that address as a real IP.
 * The returned string lives as long as the immutable policy object. */
const char *hev_mapped_dns_static_lookup (const HevMappedDNSStatic *self,
                                         const uint8_t address[4]);

/* DNS message only (no IP/UDP headers or TCP length prefix).
 * Supports one uncompressed IN/A question, optionally one empty EDNS(0) OPT
 * without DNSSEC flags. Other record types are unsupported for a matched name;
 * unsupported question encodings or EDNS options/flags are deferred regardless
 * of name. PASS means the caller must resolve normally,
 * not that this function has performed an upstream query or returned NXDOMAIN.
 * Compression in the question is unsupported. Malformed input produces no reply.
 * No network, heap allocation, global singleton or input mutation. Separate,
 * non-overlapping query/response buffers are required. On non-REPLY, response
 * is unchanged and *response_length is zero. TTL=1 does NOT guarantee cache
 * eviction by clients, nor does it control this object's mapping lifetime.
 * The response sets QR, echoes RD/CD, and never claims RA, AA or validated AD.
 * This is not a recursive resolver or a complete DNS server. */
HevMappedDNSStaticResult hev_mapped_dns_static_reply (
    const HevMappedDNSStatic *self, const uint8_t *query, size_t query_length,
    uint8_t *response, size_t response_capacity, size_t *response_length);

#endif
