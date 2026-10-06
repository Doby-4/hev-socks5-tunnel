#include "hev-mapped-dns-static.h"

#include <string.h>

static uint16_t
read_u16 (const uint8_t *p)
{
    return ((uint16_t)p[0] << 8) | p[1];
}

static void
write_u16 (uint8_t *p, uint16_t n)
{
    p[0] = n >> 8;
    p[1] = n;
}

static unsigned char
lower_ascii (unsigned char c)
{
    return (c >= 'A' && c <= 'Z') ? c + ('a' - 'A') : c;
}

static int
host_character (unsigned char c)
{
    c = lower_ascii (c);
    return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-';
}

static int
normalize_name (const char *name, char result[254])
{
    size_t length = 0, label = 0;

    if (!name)
        return -1;
    /* At most 253 characters plus one optional root dot. */
    while (length < 255 && name[length])
        length++;
    if (length == 0 || length == 255)
        return -1;
    if (name[length - 1] == '.')
        length--;
    if (length == 0 || length > 253)
        return -1;

    for (size_t i = 0; i < length; i++) {
        unsigned char c = (unsigned char)name[i];
        if (c == '.') {
            if (!label || name[i - 1] == '-')
                return -1;
            label = 0;
        } else {
            if (!host_character (c) || (!label && c == '-') || ++label > 63)
                return -1;
        }
        result[i] = (char)lower_ascii (c);
    }
    if (!label || name[length - 1] == '-')
        return -1;
    result[length] = 0;
    return 0;
}

int
hev_mapped_dns_static_init (HevMappedDNSStatic *self, const char *name,
                            const uint8_t address[4])
{
    HevMappedDNSStatic next = { 0 };

    if (!self || !address || normalize_name (name, next.name) < 0)
        return -1;
    /* Basic unicast check, not a routing/conflict check. */
    if (address[0] == 0 || address[0] == 127 || address[0] >= 224)
        return -1;
    memcpy (next.address, address, 4);
    *self = next;
    return 0;
}

int
hev_mapped_dns_static_matches (const HevMappedDNSStatic *self, const char *name)
{
    char normalized[254];

    return self && self->name[0] && normalize_name (name, normalized) == 0 &&
           strcmp (self->name, normalized) == 0;
}

const char *
hev_mapped_dns_static_lookup (const HevMappedDNSStatic *self,
                              const uint8_t address[4])
{
    if (!self || !self->name[0] || !address ||
        memcmp (self->address, address, 4) != 0)
        return NULL;
    return self->name;
}

HevMappedDNSStaticResult
hev_mapped_dns_static_reply (const HevMappedDNSStatic *self,
                             const uint8_t *query, size_t query_length,
                             uint8_t *response, size_t response_capacity,
                             size_t *response_length)
{
    char name[254];
    size_t offset = 12, name_length = 0, question_end, needed;
    uint16_t flags, type, klass, additional;
    int edns = 0, unsupported = 0;

    if (!response_length)
        return HEV_MAPPED_DNS_STATIC_INVALID;
    *response_length = 0;
    if (!self || !self->name[0] || !query || !response || query_length < 12 ||
        query_length > 4096)
        return HEV_MAPPED_DNS_STATIC_INVALID;

    flags = read_u16 (query + 2);
    /* Standard QUERY only. Permit RD, AD and CD; reject responses, truncation,
     * reserved bits, nonzero RCODE and unexpected answer/authority sections. */
    if ((flags & ~0x0130u) || read_u16 (query + 4) != 1 ||
        read_u16 (query + 6) != 0 || read_u16 (query + 8) != 0)
        return HEV_MAPPED_DNS_STATIC_INVALID;
    additional = read_u16 (query + 10);
    if (additional > 1)
        return HEV_MAPPED_DNS_STATIC_UNSUPPORTED;

    for (;;) {
        size_t label;
        if (offset >= query_length)
            return HEV_MAPPED_DNS_STATIC_INVALID;
        label = query[offset++];
        if (label & 0xc0)
            return HEV_MAPPED_DNS_STATIC_UNSUPPORTED;
        if (!label)
            break;
        if (label > query_length - offset ||
            name_length + (name_length ? 1 : 0) + label > 253)
            return HEV_MAPPED_DNS_STATIC_INVALID;
        if (name_length)
            name[name_length++] = '.';
        for (size_t i = 0; i < label; i++) {
            unsigned char c = query[offset + i];
            /* Do not confuse a literal dot/NUL in a wire label with a label
             * boundary in a configured hostname. Other name forms are deferred. */
            if (!host_character (c))
                unsupported = 1;
            name[name_length++] = (char)lower_ascii (c);
        }
        offset += label;
    }
    name[name_length] = 0;
    if (query_length - offset < 4)
        return HEV_MAPPED_DNS_STATIC_INVALID;
    type = read_u16 (query + offset);
    klass = read_u16 (query + offset + 2);
    offset += 4;
    question_end = offset;

    if (additional) {
        size_t option_length, option_end;
        if (query_length - offset < 11)
            return HEV_MAPPED_DNS_STATIC_INVALID;
        /* One uncompressed root-name OPT; no other additional RR is supported. */
        if (query[offset] != 0 || read_u16 (query + offset + 1) != 41)
            return HEV_MAPPED_DNS_STATIC_UNSUPPORTED;
        edns = 1;
        if (query[offset + 5] || query[offset + 6] ||
            read_u16 (query + offset + 7))
            unsupported = 1; /* Extended RCODE, version, DO/unknown flags. */
        option_length = read_u16 (query + offset + 9);
        offset += 11;
        if (option_length != query_length - offset)
            return HEV_MAPPED_DNS_STATIC_INVALID;
        option_end = offset + option_length;
        if (option_length)
            unsupported = 1; /* Cookies, ECS etc. need an explicit future policy. */
        while (offset < option_end) {
            size_t length;
            if (option_end - offset < 4)
                return HEV_MAPPED_DNS_STATIC_INVALID;
            length = read_u16 (query + offset + 2);
            offset += 4;
            if (length > option_end - offset)
                return HEV_MAPPED_DNS_STATIC_INVALID;
            offset += length;
        }
    }
    if (offset != query_length)
        return HEV_MAPPED_DNS_STATIC_INVALID;
    if (unsupported)
        return HEV_MAPPED_DNS_STATIC_UNSUPPORTED;
    if (!hev_mapped_dns_static_matches (self, name))
        return HEV_MAPPED_DNS_STATIC_PASS;
    if (type != 1 || klass != 1)
        return HEV_MAPPED_DNS_STATIC_UNSUPPORTED;

    needed = question_end + 16 + (edns ? 11 : 0);
    if (response_capacity < needed)
        return HEV_MAPPED_DNS_STATIC_NO_SPACE;
    /* Avoid both exact and partially overlapping buffers. */
    if (((uintptr_t)response >= (uintptr_t)query &&
         (uintptr_t)response - (uintptr_t)query < query_length) ||
        ((uintptr_t)query > (uintptr_t)response &&
         (uintptr_t)query - (uintptr_t)response < needed))
        return HEV_MAPPED_DNS_STATIC_INVALID;

    memcpy (response, query, question_end);
    write_u16 (response + 2, 0x8000 | (flags & 0x0110));
    write_u16 (response + 6, 1);
    offset = question_end;
    write_u16 (response + offset, 0xc00c); /* Original QNAME. */
    write_u16 (response + offset + 2, 1);
    write_u16 (response + offset + 4, 1);
    memset (response + offset + 6, 0, 3);
    response[offset + 9] = 1; /* TTL one second, not a mapping expiry. */
    write_u16 (response + offset + 10, 4);
    memcpy (response + offset + 12, self->address, 4);
    offset += 16;
    if (edns) {
        memset (response + offset, 0, 11);
        write_u16 (response + offset + 1, 41);
        write_u16 (response + offset + 3, 1232);
    }
    *response_length = needed;
    return HEV_MAPPED_DNS_STATIC_REPLY;
}
