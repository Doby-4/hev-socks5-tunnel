#ifndef HEV_TUNNEL_OUTPUT_H
#define HEV_TUNNEL_OUTPUT_H

#include <errno.h>
#include <lwip/err.h>

/* A failed nonblocking packet write did not consume the packet. Keep it in
 * lwIP's unsent queue. Do not hide permanent descriptor/interface failures. */
static inline err_t
hev_tunnel_output_error (int error)
{
    if (error == EAGAIN || error == EWOULDBLOCK || error == ENOBUFS ||
        error == EINTR)
        return ERR_WOULDBLOCK;
    return ERR_IF;
}

#endif
