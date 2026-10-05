/* Exercise the real Hev splice loop and lwIP, without a network or device.
 * Only the socket input, cooperative scheduler, clock and mutex are fakes.
 * netif output and tcp_write can fail deterministically. */
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <sys/uio.h>
#include <lwip/init.h>
#include <lwip/ip4.h>
#include <lwip/tcp.h>
#include <lwip/priv/tcp_priv.h>
#include <lwip/prot/ip4.h>
#include <lwip/prot/tcp.h>
#include <hev-task.h>
#include <hev-task-mutex.h>
#include "hev-socks5-session-tcp.h"
#include "hev-tunnel-output.h"

static ssize_t test_readv(int, const struct iovec *, int);
static err_t test_tcp_write(struct tcp_pcb *, const void *, u16_t, u8_t);
static int test_lock(HevTaskMutex *m) { (void)m; return 0; }
static void test_wakeup(HevTask *task);
static int test_yielder(HevTaskYieldType, void *);
static HevListNode *test_node(HevSocks5Session *p) { return &((HevSocks5SessionTCP *)p)->data.node; }
static void test_update(HevListNode *n) { (void)n; }
static int test_buffer_size(void) { return 8192; }
static int test_clock(clockid_t, struct timespec *);

#define readv test_readv
#define tcp_write test_tcp_write
#define hev_task_mutex_lock test_lock
#define hev_task_mutex_unlock test_lock
#define hev_task_wakeup test_wakeup
#define hev_socks5_task_io_yielder test_yielder
#define hev_socks5_session_get_node test_node
#define hev_socks5_tunnel_update_session test_update
#define hev_config_get_misc_tcp_buffer_size test_buffer_size
#define clock_gettime test_clock
#include "../src/hev-socks5-session-tcp.c"
#undef readv
#undef tcp_write
#undef clock_gettime
#include "hev-tunnel.h"

unsigned int lwip_port_rand(void) { return 123456789U; }
static struct netif iface;
static HevSocks5SessionTCP session;
static unsigned char seen[256 * 1024];
static size_t input_size, input_offset, delivered;
static unsigned attempts, failures, successes, write_calls, yields, wakes, eof_reads;
static int output_failures, fail_after, write_failures, write_fail_call;
static int cancel_at, no_acks, output_error, input_error;
static uint64_t now_ms;
static const u32_t initial_seq = 10000;

static int test_clock(clockid_t id, struct timespec *ts) {
    (void)id; ts->tv_sec = now_ms / 1000; ts->tv_nsec = (now_ms % 1000) * 1000000;
    return 0;
}
static void test_wakeup(HevTask *task) { (void)task; wakes++; }
static ssize_t test_readv(int fd, const struct iovec *iov, int count) {
    (void)fd;
    if (input_error) { errno = input_error; return -1; }
    size_t copied = 0;
    for (int i = 0; i < count && input_offset < input_size; i++) {
        size_t n = iov[i].iov_len;
        if (n > input_size - input_offset) n = input_size - input_offset;
        if (n > 4096 - copied) n = 4096 - copied;
        for (size_t j = 0; j < n; j++)
            ((unsigned char *)iov[i].iov_base)[j] = (input_offset + j) % 251;
        copied += n; input_offset += n;
    }
    if (!copied) { eof_reads++; assert(eof_reads == 1); }
    return copied;
}
static err_t test_tcp_write(struct tcp_pcb *pcb, const void *data, u16_t len, u8_t flags) {
    write_calls++;
    if (write_failures && (!write_fail_call || (int)write_calls >= write_fail_call)) {
        if (write_failures > 0) write_failures--;
        return ERR_MEM;
    }
    return tcp_write(pcb, data, len, flags);
}
static err_t output(struct netif *n, struct pbuf *p, const ip4_addr_t *dst) {
    (void)n; (void)dst;
    unsigned char bytes[2000];
    assert(p->tot_len <= sizeof(bytes));
    pbuf_copy_partial(p, bytes, p->tot_len, 0);
    unsigned ihl = (bytes[0] & 15) * 4;
    struct tcp_hdr tcp;
    memcpy(&tcp, bytes + ihl, sizeof(tcp));
    unsigned hlen = TCPH_HDRLEN(&tcp) * 4;
    unsigned len = p->tot_len - ihl - hlen;
    if (!len) return ERR_OK;
    attempts++;
    if (output_failures && (int)successes >= fail_after) {
        if (output_failures > 0) output_failures--;
        failures++;
        return output_error;
    }
    successes++;
    unsigned offset = lwip_ntohl(tcp.seqno) - initial_seq;
    assert(offset + len <= input_size); /* catches duplicate tcp_write */
    for (unsigned i = 0; i < len; i++) {
        assert(bytes[ihl + hlen + i] == (unsigned char)((offset + i) % 251));
        if (!seen[offset + i]) { seen[offset + i] = 1; delivered++; }
    }
    return ERR_OK;
}
static err_t netinit(struct netif *n) {
    n->name[0] = 't'; n->name[1] = 's'; n->mtu = 1500; n->output = output;
    return ERR_OK;
}
static void ack(struct tcp_pcb *pcb) {
    if (pcb->snd_nxt == pcb->lastack) return;
    struct pbuf *p = pbuf_alloc(PBUF_RAW, IP_HLEN + TCP_HLEN, PBUF_RAM);
    assert(p); memset(p->payload, 0, p->len);
    struct ip_hdr *ip = p->payload;
    IPH_VHL_SET(ip, 4, 5); IPH_LEN_SET(ip, lwip_htons(p->len));
    IPH_TTL_SET(ip, 64); IPH_PROTO_SET(ip, IP_PROTO_TCP);
    ip4_addr_copy(ip->src, *ip_2_ip4(&pcb->remote_ip));
    ip4_addr_copy(ip->dest, *ip_2_ip4(&pcb->local_ip));
    struct tcp_hdr *tcp = (void *)((unsigned char *)p->payload + IP_HLEN);
    tcp->src = lwip_htons(pcb->remote_port); tcp->dest = lwip_htons(pcb->local_port);
    tcp->seqno = lwip_htonl(pcb->rcv_nxt); tcp->ackno = lwip_htonl(pcb->snd_nxt);
    TCPH_HDRLEN_FLAGS_SET(tcp, 5, TCP_ACK); tcp->wnd = lwip_htons(65535);
    /* Repository lwIP configuration disables incoming checksum verification. */
    assert(ip4_input(p, &iface) == ERR_OK);
}
static int test_yielder(HevTaskYieldType type, void *data) {
    (void)data;
    yields++;
    assert(yields < 2000); /* bounded test; catches a permanently disabled direction */
    if (cancel_at && yields >= (unsigned)cancel_at) HEV_SOCKS5(&session)->timeout = 0;
    unsigned before = wakes;
    uint64_t start = now_ms;
    do {
        now_ms += type == HEV_TASK_WAITIO ? 250 : 1;
        tcp_tmr();
        if (!no_acks && session.pcb) ack(session.pcb);
        /* Browser half-closes only after the response FIN in this variant. */
        if (session.pcb && session.socks_eof && !session.pcb_eof &&
            session.pcb->state != ESTABLISHED)
            tcp_recv_handler(&session, session.pcb, NULL, ERR_OK);
        if (type != HEV_TASK_WAITIO || wakes != before) break;
        /* An idle wait with no real wake event expires, like hev_task_sleep. */
        if (now_ms - start >= (uint64_t)HEV_SOCKS5(&session)->timeout) return -1;
    } while (HEV_SOCKS5(&session)->timeout != 0);
    return HEV_SOCKS5(&session)->timeout == 0 ? -1 : 0;
}
static void setup(void) {
    memset(&session, 0, sizeof(session)); memset(seen, 0, sizeof(seen));
    input_size = sizeof(seen); input_offset = delivered = 0;
    attempts = failures = successes = write_calls = yields = wakes = eof_reads = 0;
    output_failures = fail_after = write_failures = write_fail_call = 0;
    cancel_at = no_acks = input_error = 0; output_error = ERR_WOULDBLOCK; now_ms = 1000;
    struct tcp_pcb *pcb = tcp_new(); assert(pcb);
    IP_ADDR4(&pcb->local_ip, 192,0,2,1); IP_ADDR4(&pcb->remote_ip, 192,0,2,2);
    pcb->local_port = 18081; pcb->remote_port = 55555; pcb->state = ESTABLISHED;
    pcb->mss = 1460; pcb->snd_wnd = pcb->snd_wnd_max = pcb->cwnd = 65535;
    pcb->snd_lbb = pcb->snd_nxt = pcb->lastack = initial_seq; pcb->rcv_nxt = 50000;
    TCP_REG_ACTIVE(pcb);
    session.pcb = pcb; session.pcb_eof = 1;
    session.data.task = (HevTask *)&session;
    HEV_SOCKS5(&session)->fd = -1; HEV_SOCKS5(&session)->timeout = 2000;
    tcp_arg(pcb, &session); tcp_sent(pcb, tcp_sent_handler); tcp_err(pcb, tcp_err_handler);
}
static void run_success(const char *name) {
    hev_socks5_session_tcp_splice(&session);
    assert(delivered == input_size && input_offset == input_size);
    assert(session.pcb == NULL && session.buffer == NULL);
    assert(!session.tcp_failed && !session.retry_pending);
    printf("PASS %s: %zu bytes, %u failures, %u scheduler yields\n", name, delivered, failures, yields);
    if (session.pcb) { tcp_err(session.pcb, NULL); tcp_abort(session.pcb); }
}
static void run_failure(const char *name) {
    hev_socks5_session_tcp_splice(&session);
    assert(delivered < input_size);
    assert(session.pcb == NULL && session.buffer == NULL && !session.retry_pending);
    assert(now_ms < 10000 && yields < 50);
    unsigned before = wakes;
    for (int i = 0; i < 20; i++) tcp_tmr();
    assert(wakes == before); /* no callback into the expired coroutine stack */
    printf("PASS %s: bounded exit, %u yields, no callback after cleanup\n", name, yields);
}

static void wrapped_partial_write(void) {
    setup(); input_size = 7000;
    HevRingBuffer *ring = calloc(1, sizeof(*ring) + 8192); assert(ring);
    ring->max_size = 8192; ring->rp = ring->wp = 7000;
    session.buffer = ring; input_error = EAGAIN;
    /* 1192 bytes at the end, then 5808 at the beginning. */
    for (unsigned i = 0; i < input_size; i++) ring->data[(7000 + i) % 8192] = i % 251;
    hev_ring_buffer_write_finish(ring, input_size);
    write_fail_call = 2; write_failures = 1;
    assert(tcp_splice_b(&session) == 1);
    assert(ring->rda_size == 5808 && ring->use_size == 7000);
    assert(session.pcb->snd_lbb == initial_seq + 1192);
    assert(session.retry_pending);
    ack(session.pcb);
    assert(ring->use_size == 5808); /* only the successful first iov was released */
    assert(tcp_splice_b(&session) == 1);
    assert(ring->rda_size == 0 && session.pcb->snd_lbb == initial_seq + input_size);
    for (int i = 0; i < 20 && ring->use_size; i++) { tcp_tmr(); ack(session.pcb); }
    assert(delivered == input_size && ring->use_size == 0);
    tcp_err(session.pcb, NULL); tcp_abort(session.pcb); free(ring);
    puts("PASS wrapped ring: second iov rejected, retained, retried exactly once");
}

static void bridge_pressure(void) {
    assert(hev_tunnel_output_error(ENOBUFS) == ERR_WOULDBLOCK);
    assert(hev_tunnel_output_error(EAGAIN) == ERR_WOULDBLOCK);
    assert(hev_tunnel_output_error(EINTR) == ERR_WOULDBLOCK);
    assert(hev_tunnel_output_error(EBADF) == ERR_IF);
    assert(hev_tunnel_output_error(EIO) == ERR_IF);
    int sockets[2]; assert(socketpair(AF_UNIX, SOCK_DGRAM, 0, sockets) == 0);
    assert(fcntl(sockets[1], F_SETFL, O_NONBLOCK) == 0);
    int size = 4096;
    assert(setsockopt(sockets[0], SOL_SOCKET, SO_RCVBUF, &size, sizeof(size)) == 0);
    struct pbuf *p = pbuf_alloc(PBUF_RAW, 1500, PBUF_RAM); assert(p);
    memset(p->payload, 0x45, 1500);
    unsigned sent = 0;
    while (hev_tunnel_write(sockets[1], p) > 0) { sent++; assert(sent < 10000); }
    int error = errno;
    assert(hev_tunnel_output_error(error) == ERR_WOULDBLOCK);
    unsigned char bytes[2000]; assert(recv(sockets[0], bytes, sizeof(bytes), 0) == 1504);
    assert(hev_tunnel_write(sockets[1], p) == 1504);
    close(sockets[1]);
    assert(hev_tunnel_write(sockets[1], p) == -1 && errno == EBADF);
    close(sockets[0]); pbuf_free(p);
    printf("PASS real datagram socket pressure: errno %d, recover after read\n", error);
}

static void limited_send_buffer(void) {
    setup(); input_size = 4096;
    HevRingBuffer *ring = calloc(1, sizeof(*ring) + 8192); assert(ring);
    ring->max_size = 8192; session.buffer = ring;
    session.pcb->snd_buf = 1000;
    assert(tcp_splice_b(&session) == 1);
    assert(session.pcb->snd_lbb == initial_seq + 1000);
    assert(ring->rda_size == 3096 && ring->use_size == 4096);
    input_error = EAGAIN;
    for (int i = 0; i < 20 && ring->use_size; i++) {
        tcp_tmr(); ack(session.pcb); tcp_splice_b(&session);
    }
    assert(delivered == input_size && ring->use_size == 0);
    tcp_err(session.pcb, NULL); tcp_abort(session.pcb); free(ring);
    puts("PASS small snd_buf: partial submission, ACK credit, exact remaining bytes");
}
int main(void) {
    setbuf(stdout, NULL); lwip_init();
    ip4_addr_t local, mask, gateway;
    IP4_ADDR(&local,192,0,2,1); IP4_ADDR(&mask,255,255,255,0); ip4_addr_set_zero(&gateway);
    assert(netif_add(&iface,&local,&mask,&gateway,NULL,netinit,ip4_input));
    netif_set_default(&iface); netif_set_up(&iface); netif_set_link_up(&iface);
    setup(); run_success("baseline");
    setup(); output_failures = 1; run_success("first output failure");
    setup(); output_failures = 3; run_success("three output failures");
    setup(); output_failures = 3; fail_after = 2; run_success("partial output then failure");
    setup(); write_failures = 3; run_success("tcp_write ERR_MEM before any ACK");
    setup(); output_failures = 3; output_error = ERR_MEM; run_success("netif ERR_MEM");
    setup(); output_failures = 3; output_error = hev_tunnel_output_error(ENOBUFS);
    run_success("bridge ENOBUFS mapping");
    setup(); input_size = 4096; write_failures = 3; run_success("EOF while enqueue retry pending");
    setup(); input_size = 4096; output_failures = 3; run_success("EOF while output retry pending");
    setup(); input_size = 0; run_success("empty response EOF");
    setup(); session.pcb_eof = 0; output_failures = 3; run_success("browser half-close after response");
    setup(); output_failures = -1; run_failure("permanent pressure timeout");
    setup(); write_failures = -1; run_failure("permanent enqueue pressure timeout");
    setup(); output_failures = -1; cancel_at = 3; run_failure("stop during retry");
    setup(); HEV_SOCKS5(&session)->timeout = 0; run_failure("stop before first read");
    setup(); output_failures = 1; output_error = ERR_IF; run_failure("fatal interface failure");
    setup(); input_error = ECONNRESET; run_failure("fatal socket read");
    setup(); no_acks = 1; run_failure("no ACK idle timeout");
    wrapped_partial_write();
    limited_send_buffer();
    bridge_pressure();
    return 0;
}
