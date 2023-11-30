#include <errno.h>
#include <netdb.h>
#include <nss.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include "buffer.h"

#define LOG(fmt, ...) \
    do { \
        if (getenv("NSS_DNSMASQ_LOG")) \
            fprintf(stderr, "%s: " fmt "\n", __func__, __VA_ARGS__); \
    } while(0)

struct result
{
    int af;
    union
    {
        struct in_addr ipv4;
        struct in6_addr ipv6;
    } address;
};

static int populate_result(const char *name, struct buffer *buf, const struct result *in, struct hostent *out)
{
    out->h_name = buffer_strdup(buf, name);
    if (!out->h_name)
    {
        LOG("allocation failed: %s", "h_name");
        return 0;
    }
    out->h_aliases = buffer_alloc(buf, sizeof(char *)); // empty list
    if (!out->h_aliases)
    {
        LOG("allocation failed: %s", "h_aliases");
        return 0;
    }
    out->h_addrtype = in->af;
    if (in->af == AF_INET)
        out->h_length = sizeof(in->address.ipv4.s_addr);
    else
        out->h_length = sizeof(in->address.ipv6.__in6_u.__u6_addr8);
    out->h_addr_list = buffer_alloc(buf, 2 * sizeof(char *)); // 1 element + terminating NULL
    if (!out->h_addr_list)
    {
        LOG("allocation failed: %s", "h_addr_list");
        return 0;
    }
    out->h_addr_list[0] = buffer_alloc(buf, out->h_length);
    if (!out->h_addr_list[0])
    {
        LOG("allocation failed: %s", "h_addr_list[0]");
        return 0;
    }
    memcpy(out->h_addr_list[0], &in->address, out->h_length);
    return 1;
}

// https://www.gnu.org/software/libc/manual/html_node/NSS-Modules-Interface.html
enum nss_status _nss_dnsmasq_gethostbyname2_r(const char *name, int af, struct hostent *result_buf, char *buf, size_t buflen, int *errnop, int *h_errnop)
{
    enum nss_status status;

    LOG("query: name=%s af=%s buflen=%ld", name, af == AF_INET ? "AF_INET" : af == AF_INET6 ? "AF_INET6" : "?", buflen);

    if (af != AF_INET && af != AF_INET6)
    {
        LOG("incompatible address family: %d", af);
        *errnop = ENOENT;
        *h_errnop = HOST_NOT_FOUND;
        status = NSS_STATUS_NOTFOUND;
        goto out;
    }

    struct buffer buffer;
    buffer_init(&buffer, buf, buflen);

    size_t linebuf_size = 256;
    char *linebuf = malloc(linebuf_size);
    if (!linebuf)
    {
        LOG("malloc failed: %s", strerror(errno));
        *errnop = errno;
        *errnop = NETDB_INTERNAL;
        status = NSS_STATUS_UNAVAIL;
        goto out;
    }

    FILE *fp = fopen("/var/lib/misc/dnsmasq.leases", "r");
    if (!fp)
    {
        LOG("opening leases file failed: %s", strerror(errno));
        *errnop = errno;
        *errnop = NETDB_INTERNAL;
        status = NSS_STATUS_UNAVAIL;
        goto free_linebuf;
    }

    result_buf->h_addrtype = af;

    while (getline(&linebuf, &linebuf_size, fp) != -1)
    {
        if (strncmp(linebuf, "duid ", 5) == 0)
            continue;
        const char *ip = NULL;
        for (int i = 0; i < 4; i++)
        {
            const char *tok = strtok(i == 0 ? linebuf : NULL, " ");
            if (!tok)
                break;
            switch (i)
            {
            case 2:
                ip = tok;
                break;
            case 3:
                LOG("lease: ip=%s hostname=%s", ip, tok);
                if (strcmp(tok, "*") != 0 && strcmp(tok, name) == 0)
                {
                    struct result res = {.af = af};
                    if (inet_pton(af, ip, &res.address) && populate_result(name, &buffer, &res, result_buf))
                    {
                        LOG("match: %s -> %s", name, ip);
                        status = NSS_STATUS_SUCCESS;
                        goto close_fp;
                    }
                }
                break;
            }
        }
    }

    *errnop = ENOENT;
    *h_errnop = HOST_NOT_FOUND;
    status = NSS_STATUS_NOTFOUND;

close_fp:
    fclose(fp);
free_linebuf:
    free(linebuf);
out:
    return status;
}
