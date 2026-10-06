/*
 ============================================================================
 Name        : hev-mapped-dns.c
 Author      : hev <r@hev.cc>
 Copyright   : Copyright (c) 2025 hev
 Description : Mapped DNS
 ============================================================================
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include <hev-compiler.h>
#include <hev-memory-allocator.h>

#include "hev-logger.h"

#include "hev-mapped-dns.h"

static HevMappedDNS *singleton;

typedef struct _DNSHdr DNSHdr;

struct _DNSHdr
{
    uint16_t id;
    uint16_t fl;
    uint16_t qd;
    uint16_t an;
    uint16_t ns;
    uint16_t ar;
};

struct _HevMappedDNSNode
{
    HevRBTreeNode tree;
    HevListNode list;
    char *name;
    int idx;
};

HevMappedDNS *
hev_mapped_dns_new (int net, int mask, int max)
{
    HevMappedDNS *self;
    int res;

    self = hev_malloc0 (sizeof (HevMappedDNS) + sizeof (void *) * max);
    if (!self)
        return NULL;

    res = hev_mapped_dns_construct (self, net, mask, max);
    if (res < 0) {
        hev_free (self);
        return NULL;
    }

    LOG_D ("%p mapped dns new", self);

    return self;
}

HevMappedDNS *
hev_mapped_dns_get (void)
{
    return singleton;
}

HevMappedDNS *
hev_mapped_dns_new_static (int net, int mask, const HevMappedDNSStatic *policy)
{
    HevMappedDNSStatic checked;
    HevMappedDNS *self;
    uint32_t address;
    uint32_t hostmask = ~(uint32_t)mask;

    if (!policy || !mask || (hostmask & (hostmask + 1)) ||
        ((uint32_t)net & hostmask) ||
        hev_mapped_dns_static_init (&checked, policy->name, policy->address) < 0)
        return NULL;
    memcpy (&address, checked.address, 4);
    address = ntohl (address);
    if ((address & (uint32_t)mask) != (uint32_t)net ||
        address == (uint32_t)net || address == ((uint32_t)net | hostmask))
        return NULL;

    self = hev_mapped_dns_new (net, mask, 0);
    if (self)
        self->policy = checked;
    return self;
}

int
hev_mapped_dns_is_reserved (const HevMappedDNS *self, int ip)
{
    return self && self->policy.name[0] && (ip & self->mask) == self->net;
}

void
hev_mapped_dns_put (HevMappedDNS *self)
{
    singleton = self;
}

static HevMappedDNSNode *
hev_mapped_dns_node_alloc (const char *name)
{
    HevMappedDNSNode *node;

    node = hev_malloc0 (sizeof (HevMappedDNSNode));
    if (!node)
        return NULL;

    node->name = strdup (name);
    if (!node->name) {
        free (node);
        return NULL;
    }

    return node;
}

static void
hev_mapped_dns_node_free (HevMappedDNSNode *node)
{
    free (node->name);
    hev_free (node);
}

static int
hev_mapped_dns_find (HevMappedDNS *self, const char *name)
{
    HevRBTreeNode **new = &self->tree.root, *parent = NULL;
    HevMappedDNSNode *node;
    int idx = self->use;

    while (*new) {
        int res;

        node = container_of (*new, HevMappedDNSNode, tree);
        res = strcmp (node->name, name);
        parent = *new;

        if (res < 0) {
            new = &((*new)->left);
        } else if (res > 0) {
            new = &((*new)->right);
        } else {
            hev_list_del (&self->list, &node->list);
            hev_list_add_tail (&self->list, &node->list);
            return node->idx;
        }
    }

    node = hev_mapped_dns_node_alloc (name);
    if (!node)
        return -1;

    hev_rbtree_node_link (&node->tree, parent, new);
    hev_rbtree_insert_color (&self->tree, &node->tree);
    hev_list_add_tail (&self->list, &node->list);

    if (self->use < self->max) {
        self->use++;
    } else {
        HevMappedDNSNode *nf;
        HevListNode *nl;

        nl = hev_list_first (&self->list);
        nf = container_of (nl, HevMappedDNSNode, list);

        idx = nf->idx;
        hev_rbtree_erase (&self->tree, &nf->tree);
        hev_list_del (&self->list, &nf->list);
        hev_mapped_dns_node_free (nf);
    }

    self->records[idx] = node;
    node->idx = idx;

    return node->idx;
}

static inline uint16_t
read_u16 (const uint8_t *p)
{
    return ((uint16_t)p[0] << 8) | p[1];
}

static inline void
write_u16 (uint8_t *p, uint16_t v)
{
    p[0] = v >> 8;
    p[1] = v;
}

static inline void
write_u32 (uint8_t *p, uint32_t v)
{
    p[0] = v >> 24;
    p[1] = v >> 16;
    p[2] = v >> 8;
    p[3] = v;
}

/* Locate only a bounded, self-contained uncompressed question to echo in an
 * error. Do not chase compression pointers or copy unvalidated extra records. */
static size_t
static_question_end (const uint8_t *query, size_t length)
{
    size_t offset = 12;
    if (read_u16 (query + 4) != 1)
        return 12;
    while (offset < length) {
        unsigned label = query[offset++];
        if (!label)
            return offset - 12 <= 255 && length - offset >= 4 ? offset + 4 : 12;
        if (label > 63 || label > length - offset || offset + label - 12 > 254)
            return 12;
        offset += label;
    }
    return 12;
}

int
hev_mapped_dns_handle (HevMappedDNS *self, void *req, int qlen, void *res,
                       int slen)
{
    DNSHdr *qhdr = req;
    DNSHdr *shdr = res;
    uint8_t *rb = req;
    uint8_t *sb = res;
    int ips[32];
    int ipo[32];
    int ipn = 0;
    int off;
    int i;

    if (!self || !req || !res || qlen < 0 || slen < 0)
        return -1;

    if (self->policy.name[0]) {
        size_t length;
        HevMappedDNSStaticResult result;
        unsigned rcode;

        if (((uintptr_t)res >= (uintptr_t)req &&
             (uintptr_t)res - (uintptr_t)req < (size_t)qlen) ||
            ((uintptr_t)req > (uintptr_t)res &&
             (uintptr_t)req - (uintptr_t)res < (size_t)slen))
            return -1;
        result = hev_mapped_dns_static_reply (&self->policy, req, qlen, res,
                                              slen, &length);
        if (result == HEV_MAPPED_DNS_STATIC_REPLY)
            return (int)length;
        /* Experimental UDP endpoint, not an upstream resolver. Return
         * FORMERR / NOTIMP / REFUSED instead of silently turning PASS or
         * UNSUPPORTED into a timeout. Never answer an incoming reply.
         * Caller provides separate request/response buffers. */
        if (qlen < 12 || qlen > 4096 || slen < 12 || (rb[2] & 0x80) ||
            result == HEV_MAPPED_DNS_STATIC_NO_SPACE)
            return -1;
        rcode = result == HEV_MAPPED_DNS_STATIC_PASS ? 5 :
                result == HEV_MAPPED_DNS_STATIC_UNSUPPORTED ? 4 : 1;
        if (read_u16 (rb + 2) & 0x7800)
            rcode = 4; /* Unsupported opcode. */
        length = static_question_end (rb, qlen);
        if (length > (size_t)slen)
            return -1;
        memset (sb, 0, 12);
        memcpy (sb, rb, 2);
        write_u16 (sb + 2, 0x8000 | (read_u16 (rb + 2) & 0x7910) | rcode);
        if (length > 12) {
            write_u16 (sb + 4, 1);
            memcpy (sb + 12, rb + 12, length - 12);
        }
        return (int)length;
    }

    if (slen < qlen)
        return -1;
    if (qlen < sizeof (DNSHdr))
        return -1;

    memcpy (res, req, qlen);
    qhdr->qd = ntohs (qhdr->qd);
    shdr->fl = ntohs (shdr->fl);
    shdr->ns = 0;
    shdr->an = 0;
    shdr->ar = 0;

    if (qhdr->qd > 32)
        return -1;

    off = sizeof (DNSHdr);
    for (i = 0; i < qhdr->qd; i++) {
        ipo[ipn] = off;

        if (off >= qlen)
            return -1;

        while (rb[off]) {
            int poff = off;

            off += 1 + rb[off];
            if (off >= qlen)
                return -1;

            rb[poff] = '.';
        }

        off++;
        if ((off + 3) >= qlen)
            return -1;

        if ((read_u16 (&rb[off + 0]) == 1) && (read_u16 (&rb[off + 2]) == 1)) {
            int idx;

            idx = hev_mapped_dns_find (self, (char *)&rb[ipo[ipn] + 1]);
            if (idx >= 0) {
                ips[ipn] = self->net | idx;
                ipn++;
            }
        }

        off += 4;
    }

    for (i = 0; i < ipn; i++) {
        if ((off + 15) >= slen)
            return -1;

        write_u16 (&sb[off + 0], 0xc000 | ipo[i]);
        write_u16 (&sb[off + 2], 1);
        write_u16 (&sb[off + 4], 1);
        write_u32 (&sb[off + 6], 1);
        write_u16 (&sb[off + 10], 4);
        write_u32 (&sb[off + 12], ips[i]);

        off += 16;
    }

    shdr->fl = htons (shdr->fl | 0x8000 | ((shdr->fl & 0x100) >> 1));
    shdr->an = htons (ipn);

    return off;
}

const char *
hev_mapped_dns_lookup (HevMappedDNS *self, int ip)
{
    HevMappedDNSNode *node;
    int idx;

    if (self->policy.name[0]) {
        uint32_t address = htonl ((uint32_t)ip);
        return hev_mapped_dns_static_lookup (&self->policy,
                                             (const uint8_t *)&address);
    }

    if ((ip & self->mask) != self->net)
        return NULL;

    idx = ip & ~self->mask;
    if (idx >= self->max)
        return NULL;

    node = self->records[idx];
    if (!node)
        return NULL;

    hev_list_del (&self->list, &node->list);
    hev_list_add_tail (&self->list, &node->list);

    return node->name;
}

int
hev_mapped_dns_construct (HevMappedDNS *self, int net, int mask, int max)
{
    int res;

    res = hev_object_construct (&self->base);
    if (res < 0)
        return res;

    LOG_D ("%p mapped dns construct", self);

    HEV_OBJECT (self)->klass = HEV_MAPPED_DNS_TYPE;

    if (max > ~mask)
        return -1;

    self->max = max;
    self->net = net;
    self->mask = mask;

    return 0;
}

static void
hev_mapped_dns_destruct (HevObject *base)
{
    HevMappedDNS *self = HEV_MAPPED_DNS (base);
    HevListNode *n;

    LOG_D ("%p mapped dns destruct", self);

    n = hev_list_first (&self->list);
    while (n) {
        HevMappedDNSNode *t;

        t = container_of (n, HevMappedDNSNode, list);
        n = hev_list_node_next (n);
        hev_mapped_dns_node_free (t);
    }

    HEV_OBJECT_TYPE->destruct (base);
    hev_free (base);
}

HevObjectClass *
hev_mapped_dns_class (void)
{
    static HevMappedDNSClass klass;
    HevMappedDNSClass *kptr = &klass;
    HevObjectClass *okptr = HEV_OBJECT_CLASS (kptr);

    if (!okptr->name) {
        memcpy (kptr, HEV_OBJECT_TYPE, sizeof (HevObjectClass));

        okptr->name = "HevMappedDNS";
        okptr->destruct = hev_mapped_dns_destruct;
    }

    return okptr;
}
