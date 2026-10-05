/*
 ============================================================================
 Name        : hev-socks5-session-tcp.c
 Author      : hev <r@hev.cc>
 Copyright   : Copyright (c) 2017 - 2023 hev
 Description : Socks5 Session TCP
 ============================================================================
 */

#include <errno.h>
#include <string.h>
#include <time.h>

#include <lwip/tcp.h>

#include <hev-task.h>
#include <hev-task-io.h>
#include <hev-task-io-socket.h>
#include <hev-task-mutex.h>
#include <hev-memory-allocator.h>
#include <hev-socks5-misc.h>

#include "hev-utils.h"
#include "hev-config.h"
#include "hev-logger.h"
#include "hev-config-const.h"
#include "hev-socks5-tunnel.h"

#include "hev-socks5-session-tcp.h"

static int
task_io_yielder (HevTaskYieldType type, void *data)
{
    HevSocks5Session *self = data;
    HevListNode *node;
    int res;

    res = hev_socks5_task_io_yielder (type, data);
    node = hev_socks5_session_get_node (self);
    hev_socks5_tunnel_update_session (node);

    return res;
}

static int
tcp_splice_f (HevSocks5SessionTCP *self)
{
    struct iovec iov[64];
    struct pbuf *p;
    int iovc = 0;
    int res = 1;

    if (self->queue) {
        for (p = self->queue; p && (iovc < 64); p = p->next, iovc++) {
            iov[iovc].iov_base = p->payload;
            iov[iovc].iov_len = p->len;
        }
    } else if (self->pcb_eof) {
        res = -1;
    } else {
        res = 0;
    }

    if (iovc) {
        ssize_t s = writev (HEV_SOCKS5 (self)->fd, iov, iovc);
        if (0 >= s) {
            if ((0 > s) && (EAGAIN == errno))
                res = 0;
            else
                res = -1;
        } else {
            hev_task_mutex_lock (self->mutex);
            self->queue = pbuf_free_header (self->queue, s);
            if (self->pcb)
                tcp_recved (self->pcb, s);
            hev_task_mutex_unlock (self->mutex);
            res = 1;
        }
    } else if (res < 0) {
        shutdown (HEV_SOCKS5 (self)->fd, SHUT_WR);
    }

    return res;
}

static uint64_t
tcp_monotonic_ms (void)
{
    struct timespec ts;
    clock_gettime (CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static int
tcp_retry_expired (HevSocks5SessionTCP *self)
{
    int timeout = HEV_SOCKS5 (self)->timeout;
    return timeout == 0 ||
           (self->retry_pending && timeout > 0 &&
            tcp_monotonic_ms () - self->retry_started_ms >= (uint64_t)timeout);
}

/* Called by the existing lwIP slow timer, under the core mutex. It only
 * wakes the session; socket reads and coroutine waits never run in lwIP. */
static err_t
tcp_retry_poll (void *arg, struct tcp_pcb *pcb)
{
    HevSocks5SessionTCP *self = arg;
    (void)pcb;
    if (self->retry_pending) {
        if (tcp_retry_expired (self))
            self->tcp_failed = 1;
        hev_task_wakeup (self->data.task);
    }
    return ERR_OK;
}

static int
tcp_splice_b (HevSocks5SessionTCP *self)
{
    struct iovec iov[2];
    int res = 0, iovc, retry = 0;

    if (self->tcp_failed || tcp_retry_expired (self)) {
        self->tcp_failed = 1;
        return -1;
    }

    iovc = hev_ring_buffer_writing (self->buffer, iov);
    if (iovc && !self->socks_eof) {
        ssize_t s = readv (HEV_SOCKS5 (self)->fd, iov, iovc);
        if (s < 0) {
            if (errno == EINTR)
                retry = 1;
            else if (errno != EAGAIN && errno != EWOULDBLOCK) {
                self->tcp_failed = 1;
                return -1;
            }
        } else if (s == 0) {
            self->socks_eof = 1;
        } else {
            hev_ring_buffer_write_finish (self->buffer, s);
            res = 1;
        }
    }

    hev_task_mutex_lock (self->mutex);
    if (self->pcb) {
        err_t err;
        int i, submitted = 0;
        iovc = hev_ring_buffer_reading (self->buffer, iov);
        for (i = 0; i < iovc; i++) {
            size_t len = iov[i].iov_len;
            if (len > tcp_sndbuf (self->pcb))
                len = tcp_sndbuf (self->pcb);
            if (!len) {
                retry = 1;
                break;
            }
            err = tcp_write (self->pcb, iov[i].iov_base, len, 0);
            if (err != ERR_OK) {
                if (err == ERR_MEM)
                    retry = 1;
                else
                    self->tcp_failed = 1;
                break;
            }
            /* No-copy: submitted bytes stay allocated until tcp_sent_handler.
             * A rejected tcp_write consumes nothing, including across wrap. */
            hev_ring_buffer_read_finish (self->buffer, len);
            submitted = 1;
            res = 1;
            if (len < iov[i].iov_len) {
                retry = 1;
                break;
            }
        }
        if (!self->tcp_failed && (submitted || self->retry_pending)) {
            err = tcp_output (self->pcb);
            if (err == ERR_WOULDBLOCK || err == ERR_MEM)
                retry = 1;
            else if (err != ERR_OK)
                self->tcp_failed = 1;
        }
        if (!self->tcp_failed && !retry && self->socks_eof &&
            !hev_ring_buffer_reading (self->buffer, iov)) {
            err = tcp_shutdown (self->pcb, 0, 1);
            if (err == ERR_OK)
                res = -1; /* EOF, not a failure: drain submitted bytes below. */
            else if (err == ERR_MEM)
                retry = 1;
            else
                self->tcp_failed = 1;
        }
    } else {
        self->tcp_failed = 1;
    }
    if (retry && !self->retry_pending)
        self->retry_started_ms = tcp_monotonic_ms ();
    self->retry_pending = retry;
    hev_task_mutex_unlock (self->mutex);

    return self->tcp_failed ? -1 : res;
}

static err_t
tcp_recv_handler (void *arg, struct tcp_pcb *pcb, struct pbuf *p, err_t err)
{
    HevSocks5SessionTCP *self = arg;

    if (p) {
        if (self->queue)
            pbuf_cat (self->queue, p);
        else
            self->queue = p;
    } else {
        self->pcb_eof = 1;
    }

    hev_task_wakeup (self->data.task);
    return ERR_OK;
}

static err_t
tcp_sent_handler (void *arg, struct tcp_pcb *pcb, u16_t len)
{
    HevSocks5SessionTCP *self = arg;

    hev_ring_buffer_read_release (self->buffer, len);
    /* Only real progress refreshes the retry deadline, never poll wakeups. */
    if (len && self->retry_pending)
        self->retry_started_ms = tcp_monotonic_ms ();
    hev_task_wakeup (self->data.task);

    return ERR_OK;
}

static void
tcp_err_handler (void *arg, err_t err)
{
    HevSocks5SessionTCP *self = arg;

    self->pcb = NULL;
    hev_socks5_session_terminate (HEV_SOCKS5_SESSION (self));
}

HevSocks5SessionTCP *
hev_socks5_session_tcp_new (struct tcp_pcb *pcb, HevTaskMutex *mutex)
{
    HevSocks5SessionTCP *self;
    int res;

    self = hev_malloc0 (sizeof (HevSocks5SessionTCP));
    if (!self)
        return NULL;

    res = hev_socks5_session_tcp_construct (self, pcb, mutex);
    if (res < 0) {
        hev_free (self);
        return NULL;
    }

    LOG_D ("%p socks5 session tcp new", self);

    return self;
}

static void
hev_socks5_session_tcp_splice (HevSocks5Session *base)
{
    HevSocks5SessionTCP *self = HEV_SOCKS5_SESSION_TCP (base);
    int tcp_buffer_size;
    int res_f = 1;
    int res_b = 1;

    LOG_D ("%p socks5 session tcp splice", self);

    if (!self->pcb)
        return;

    tcp_buffer_size = hev_config_get_misc_tcp_buffer_size ();
    self->buffer = hev_ring_buffer_alloca (tcp_buffer_size);
    if (!self->buffer)
        return;

    hev_task_mutex_lock (self->mutex);
    if (self->pcb)
        tcp_poll (self->pcb, tcp_retry_poll, 1);
    hev_task_mutex_unlock (self->mutex);

    for (;;) {
        HevTaskYieldType type;

        if (self->tcp_failed || !self->pcb || HEV_SOCKS5 (self)->timeout == 0)
            break;
        if (res_f >= 0)
            res_f = tcp_splice_f (self);
        if (res_b >= 0)
            res_b = tcp_splice_b (self);
        if (self->tcp_failed)
            break;

        if (res_f > 0 || res_b > 0)
            type = HEV_TASK_YIELD;
        else if ((res_f & res_b) == 0)
            type = HEV_TASK_WAITIO;
        else
            break;

        if (task_io_yielder (type, base) < 0) {
            self->tcp_failed = 1;
            break;
        }
    }

    while (self->pcb && !self->tcp_failed && HEV_SOCKS5 (self)->timeout != 0) {
        if (hev_ring_buffer_get_use_size (self->buffer) == 0)
            break;

        if (task_io_yielder (HEV_TASK_WAITIO, base) < 0)
            break;
    }

    /* buffer lives on this coroutine's stack. Drop lwIP's no-copy references
     * and callbacks BEFORE returning (also on cancellation/fatal errors). */
    hev_task_mutex_lock (self->mutex);
    if (self->pcb) {
        tcp_recv (self->pcb, NULL);
        tcp_sent (self->pcb, NULL);
        tcp_err (self->pcb, NULL);
        tcp_poll (self->pcb, NULL, 0);
        tcp_abort (self->pcb);
        self->pcb = NULL;
    }
    self->buffer = NULL;
    self->retry_pending = 0;
    hev_task_mutex_unlock (self->mutex);
}

static HevTask *
hev_socks5_session_tcp_get_task (HevSocks5Session *base)
{
    HevSocks5SessionTCP *self = HEV_SOCKS5_SESSION_TCP (base);

    return self->data.task;
}

static void
hev_socks5_session_tcp_set_task (HevSocks5Session *base, HevTask *task)
{
    HevSocks5SessionTCP *self = HEV_SOCKS5_SESSION_TCP (base);

    self->data.task = task;
}

static HevListNode *
hev_socks5_session_tcp_get_node (HevSocks5Session *base)
{
    HevSocks5SessionTCP *self = HEV_SOCKS5_SESSION_TCP (base);

    return &self->data.node;
}

int
hev_socks5_session_tcp_construct (HevSocks5SessionTCP *self,
                                  struct tcp_pcb *pcb, HevTaskMutex *mutex)
{
    HevSocks5Addr addr;
    int res;

    res = hev_socks5_addr_from_lwip (&addr, &pcb->local_ip, pcb->local_port);
    if (res < 0)
        return -1;

    res = hev_socks5_client_tcp_construct (&self->base, &addr);
    if (res < 0)
        return -1;

    LOG_D ("%p socks5 session tcp construct", self);

    HEV_OBJECT (self)->klass = HEV_SOCKS5_SESSION_TCP_TYPE;

    tcp_arg (pcb, self);
    tcp_recv (pcb, tcp_recv_handler);
    tcp_sent (pcb, tcp_sent_handler);
    tcp_err (pcb, tcp_err_handler);

    self->pcb = pcb;
    self->mutex = mutex;
    self->data.self = self;

    return 0;
}

void
hev_socks5_session_tcp_destruct (HevObject *base)
{
    HevSocks5SessionTCP *self = HEV_SOCKS5_SESSION_TCP (base);

    LOG_D ("%p socks5 session tcp destruct", self);

    hev_task_mutex_lock (self->mutex);
    if (self->pcb) {
        tcp_recv (self->pcb, NULL);
        tcp_sent (self->pcb, NULL);
        tcp_err (self->pcb, NULL);
        tcp_poll (self->pcb, NULL, 0);
        tcp_abort (self->pcb);
    }

    if (self->queue)
        pbuf_free (self->queue);
    hev_task_mutex_unlock (self->mutex);

    HEV_SOCKS5_CLIENT_TCP_TYPE->destruct (base);
}

static void *
hev_socks5_session_tcp_iface (HevObject *base, void *type)
{
    if (type == HEV_SOCKS5_SESSION_TYPE) {
        HevSocks5SessionTCPClass *klass = HEV_OBJECT_GET_CLASS (base);
        return &klass->session;
    }

    return HEV_SOCKS5_CLIENT_TCP_TYPE->iface (base, type);
}

HevObjectClass *
hev_socks5_session_tcp_class (void)
{
    static HevSocks5SessionTCPClass klass;
    HevSocks5SessionTCPClass *kptr = &klass;
    HevObjectClass *okptr = HEV_OBJECT_CLASS (kptr);

    if (!okptr->name) {
        HevSocks5Class *skptr;
        HevSocks5SessionIface *siptr;
        void *ptr;

        ptr = HEV_SOCKS5_CLIENT_TCP_TYPE;
        memcpy (kptr, ptr, sizeof (HevSocks5ClientTCPClass));

        okptr->name = "HevSocks5SessionTCP";
        okptr->destruct = hev_socks5_session_tcp_destruct;
        okptr->iface = hev_socks5_session_tcp_iface;

        skptr = HEV_SOCKS5_CLASS (kptr);
        skptr->binder = hev_socks5_session_bind;

        siptr = &kptr->session;
        siptr->splicer = hev_socks5_session_tcp_splice;
        siptr->get_task = hev_socks5_session_tcp_get_task;
        siptr->set_task = hev_socks5_session_tcp_set_task;
        siptr->get_node = hev_socks5_session_tcp_get_node;
    }

    return okptr;
}
