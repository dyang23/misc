#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <stddef.h>
#include <time.h>
#include <poll.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/route.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>

/* Standard DHCP protocol constants */
#define DHCP_SERVER_PORT 67
#define DHCP_CLIENT_PORT 68
#define DHCP_MAGIC_COOKIE 0x63825363
#define MAC_LEN 6
#define BUFFER_SIZE 2048

/* RFC 2131 client state machine */
typedef enum {
    STATE_INIT = 0,
    STATE_SELECTING,
    STATE_REQUESTING,
    STATE_BOUND,
    STATE_RENEWING,
    STATE_REBINDING
} dhcp_state_t;

/* DHCP message types */
#define DHCP_DISCOVER 1
#define DHCP_OFFER    2
#define DHCP_REQUEST  3
#define DHCP_DECLINE  4
#define DHCP_ACK      5
#define DHCP_NAK      6
#define DHCP_RELEASE  7

/* DHCP options (RFC 2132) */
#define OPT_SUBNET_MASK     1
#define OPT_ROUTER          3
#define OPT_REQUESTED_IP    50
#define OPT_LEASE_TIME      51
#define OPT_MESSAGE_TYPE    53
#define OPT_SERVER_ID       54
#define OPT_PARAM_REQUEST   55
#define OPT_END             255

#pragma pack(push, 1)

struct eth_hdr {
    uint8_t  h_dest[ETH_ALEN];
    uint8_t  h_source[ETH_ALEN];
    uint16_t h_proto;
};

struct ip_hdr {
    uint8_t  ihl:4, version:4;
    uint8_t  tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t check;
    uint32_t saddr;
    uint32_t daddr;
};

struct udp_hdr {
    uint16_t source;
    uint16_t dest;
    uint16_t len;
    uint16_t check;
};

struct dhcp_packet {
    uint8_t  op;
    uint8_t  htype;
    uint8_t  hlen;
    uint8_t  hops;
    uint32_t xid;
    uint16_t secs;
    uint16_t flags;
    uint32_t ciaddr;
    uint32_t yiaddr;
    uint32_t siaddr;
    uint32_t giaddr;
    uint8_t  chaddr[16];
    uint8_t  sname[64];
    uint8_t  file[128];
    uint32_t magic;
    uint8_t  options[312];
};

struct raw_packet {
    struct eth_hdr eth;
    struct ip_hdr ip;
    struct udp_hdr udp;
    struct dhcp_packet dhcp;
};

#pragma pack(pop)

/* Client global context */
struct {
    char ifname[IFNAMSIZ];
    int ifindex;
    uint8_t mac[ETH_ALEN];
    uint32_t xid;
    uint32_t offered_ip;
    uint32_t server_ip;
    uint32_t subnet_mask;
    uint32_t router_ip;
    uint32_t lease_time;
    dhcp_state_t state;
    int raw_sock;
} ctx;

/* IP header checksum (16-bit one's complement) */
uint16_t checksum(void *b, int len) {
    uint16_t *buf = (uint16_t *)b;
    uint32_t sum = 0;

    for (; len > 1; len -= 2)
        sum += *buf++;
    if (len == 1)
        sum += *(uint8_t *)buf;

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return (uint16_t)~sum;
}

/* UDP checksum with pseudo header */
uint16_t udp_checksum(struct ip_hdr *ip, struct udp_hdr *udp, uint16_t payload_len) {
    uint32_t sum = 0;
    uint16_t *ptr = (uint16_t *)udp;
    int len = sizeof(struct udp_hdr) + payload_len;
    int i;

    /* Pseudo header */
    sum += (ip->saddr >> 16) & 0xFFFF;
    sum += (ip->saddr & 0xFFFF);
    sum += (ip->daddr >> 16) & 0xFFFF;
    sum += (ip->daddr & 0xFFFF);
    sum += htons(IPPROTO_UDP);
    sum += htons(len);

    /* UDP header and payload */
    for (i = 0; i < len; i += 2) {
        if (i == len - 1)
            sum += htons(((uint8_t *)ptr)[i] << 8);
        else
            sum += ptr[i / 2];
    }

    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    return (uint16_t)~sum;
}

/* Apply network configuration via ioctl */
void apply_network_config(void) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct ifreq ifr;
    struct rtentry rt;
    struct sockaddr_in *addr;

    if (fd < 0) {
        perror("socket");
        return;
    }

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ctx.ifname, IFNAMSIZ - 1);

    /* Set IP address */
    addr = (struct sockaddr_in *)&ifr.ifr_addr;
    addr->sin_family = AF_INET;
    addr->sin_addr.s_addr = ctx.offered_ip;
    if (ioctl(fd, SIOCSIFADDR, &ifr) < 0)
        perror("SIOCSIFADDR");

    /* Set netmask */
    addr->sin_addr.s_addr = ctx.subnet_mask;
    if (ioctl(fd, SIOCSIFNETMASK, &ifr) < 0)
        perror("SIOCSIFNETMASK");

    /* Bring interface up */
    if (ioctl(fd, SIOCGIFFLAGS, &ifr) < 0)
        perror("SIOCGIFFLAGS");
    ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
    if (ioctl(fd, SIOCSIFFLAGS, &ifr) < 0)
        perror("SIOCSIFFLAGS");

    /* Add default gateway */
    if (ctx.router_ip != 0) {
        memset(&rt, 0, sizeof(rt));
        addr = (struct sockaddr_in *)&rt.rt_gateway;
        addr->sin_family = AF_INET;
        addr->sin_addr.s_addr = ctx.router_ip;

        addr = (struct sockaddr_in *)&rt.rt_dst;
        addr->sin_family = AF_INET;
        addr->sin_addr.s_addr = INADDR_ANY;

        addr = (struct sockaddr_in *)&rt.rt_genmask;
        addr->sin_family = AF_INET;
        addr->sin_addr.s_addr = INADDR_ANY;

        rt.rt_flags = RTF_UP | RTF_GATEWAY;
        rt.rt_dev = ctx.ifname;

        ioctl(fd, SIOCDELRT, &rt);   /* ignore error if not exists */
        if (ioctl(fd, SIOCADDRT, &rt) < 0)
            perror("SIOCADDRT");
    }

    close(fd);
    printf(">> Network configured: IP %s\n",
           inet_ntoa(*(struct in_addr *)&ctx.offered_ip));
}

/* Build and send a DHCP message using raw socket */
void send_dhcp_message(uint8_t msg_type) {
    struct raw_packet pkt;
    struct sockaddr_ll dest;
    uint8_t *opt;
    int dhcp_options_len;
    int dhcp_total_len;
    int total_len;

    memset(&pkt, 0, sizeof(pkt));

    /* Ethernet header: broadcast MAC */
    memset(pkt.eth.h_dest, 0xff, ETH_ALEN);
    memcpy(pkt.eth.h_source, ctx.mac, ETH_ALEN);
    pkt.eth.h_proto = htons(ETH_P_IP);

    /* IP header */
    pkt.ip.version = 4;
    pkt.ip.ihl = 5;
    pkt.ip.tos = 0;
    pkt.ip.ttl = 64;
    pkt.ip.protocol = IPPROTO_UDP;
    pkt.ip.saddr = INADDR_ANY;
    pkt.ip.daddr = inet_addr("255.255.255.255");
    pkt.ip.check = 0; /* will compute later */

    /* UDP header */
    pkt.udp.source = htons(DHCP_CLIENT_PORT);
    pkt.udp.dest = htons(DHCP_SERVER_PORT);
    pkt.udp.len = 0;       /* will fill later */
    pkt.udp.check = 0;

    /* DHCP payload */
    pkt.dhcp.op = 1;               /* BOOTREQUEST */
    pkt.dhcp.htype = 1;            /* Ethernet */
    pkt.dhcp.hlen = ETH_ALEN;
    pkt.dhcp.hops = 0;
    pkt.dhcp.xid = htonl(ctx.xid);
    pkt.dhcp.secs = 0;

    if (ctx.state == STATE_RENEWING || ctx.state == STATE_BOUND) {
        pkt.dhcp.ciaddr = ctx.offered_ip;
        pkt.dhcp.flags = htons(0x0000);   /* unicast */
    } else {
        pkt.dhcp.flags = htons(0x8000);   /* broadcast */
    }

    pkt.dhcp.yiaddr = 0;
    pkt.dhcp.siaddr = 0;
    pkt.dhcp.giaddr = 0;
    memcpy(pkt.dhcp.chaddr, ctx.mac, ETH_ALEN);
    memset(pkt.dhcp.chaddr + ETH_ALEN, 0, sizeof(pkt.dhcp.chaddr) - ETH_ALEN);
    memset(pkt.dhcp.sname, 0, sizeof(pkt.dhcp.sname));
    memset(pkt.dhcp.file, 0, sizeof(pkt.dhcp.file));
    pkt.dhcp.magic = htonl(DHCP_MAGIC_COOKIE);

    /* Build DHCP options */
    opt = pkt.dhcp.options;

    *opt++ = OPT_MESSAGE_TYPE;
    *opt++ = 1;
    *opt++ = msg_type;

    if (msg_type == DHCP_REQUEST && ctx.state == STATE_SELECTING) {
        /* Option 50: requested IP */
        *opt++ = OPT_REQUESTED_IP;
        *opt++ = 4;
        memcpy(opt, &ctx.offered_ip, 4);
        opt += 4;

        /* Option 54: server identifier */
        *opt++ = OPT_SERVER_ID;
        *opt++ = 4;
        memcpy(opt, &ctx.server_ip, 4);
        opt += 4;
    }

    /* Option 55: parameter request list */
    *opt++ = OPT_PARAM_REQUEST;
    *opt++ = 3;
    *opt++ = OPT_SUBNET_MASK;
    *opt++ = OPT_ROUTER;
    *opt++ = OPT_LEASE_TIME;

    *opt++ = OPT_END;

    /* Calculate lengths */
    dhcp_options_len = opt - pkt.dhcp.options;
    dhcp_total_len = offsetof(struct dhcp_packet, options) + dhcp_options_len;

    pkt.udp.len = htons(sizeof(struct udp_hdr) + dhcp_total_len);
    pkt.ip.tot_len = htons(sizeof(struct ip_hdr) + ntohs(pkt.udp.len));

    /* Checksums */
    pkt.ip.check = checksum(&pkt.ip, sizeof(struct ip_hdr));
    pkt.udp.check = udp_checksum(&pkt.ip, &pkt.udp, dhcp_total_len);

    /* Send raw packet */
    memset(&dest, 0, sizeof(dest));
    dest.sll_family = AF_PACKET;
    dest.sll_ifindex = ctx.ifindex;
    dest.sll_halen = ETH_ALEN;
    memset(dest.sll_addr, 0xff, ETH_ALEN);

    total_len = sizeof(struct eth_hdr) + ntohs(pkt.ip.tot_len);
    if (sendto(ctx.raw_sock, &pkt, total_len, 0,
               (struct sockaddr *)&dest, sizeof(dest)) < 0)
        perror("sendto");
}

/* Parse DHCP options, extract message type and parameters */
void parse_dhcp_options(struct dhcp_packet *dhcp, int options_len, uint8_t *msg_type) {
    uint8_t *opt = dhcp->options;
    uint8_t *end = opt + options_len;

    while (opt < end && *opt != OPT_END) {
        if (*opt == 0) {
            opt++;
            continue;
        }

        uint8_t tag = *opt++;
        uint8_t len = *opt++;

        if (opt + len > end) break;   /* malformed */

        switch (tag) {
            case OPT_MESSAGE_TYPE:
                if (len >= 1)
                    *msg_type = *opt;
                break;
            case OPT_SERVER_ID:
                if (len >= 4)
                    memcpy(&ctx.server_ip, opt, 4);
                break;
            case OPT_SUBNET_MASK:
                if (len >= 4)
                    memcpy(&ctx.subnet_mask, opt, 4);
                break;
            case OPT_ROUTER:
                if (len >= 4)
                    memcpy(&ctx.router_ip, opt, 4);
                break;
            case OPT_LEASE_TIME:
                if (len >= 4) {
                    memcpy(&ctx.lease_time, opt, 4);
                    ctx.lease_time = ntohl(ctx.lease_time);
                }
                break;
        }
        opt += len;
    }
}

int main(int argc, char **argv) {
    struct ifreq ifr;
    struct sockaddr_ll sll;
    struct pollfd pfd;
    uint8_t buffer[BUFFER_SIZE];
    int timeout;
    int ret;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <interface>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    strncpy(ctx.ifname, argv[1], IFNAMSIZ - 1);
    ctx.ifname[IFNAMSIZ - 1] = '\0';

    /* Initialize transaction ID */
    srand(time(NULL));
    ctx.xid = rand();

    /* Create raw socket */
    ctx.raw_sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));
    if (ctx.raw_sock < 0) {
        perror("socket AF_PACKET (root required)");
        exit(EXIT_FAILURE);
    }

    /* Get interface index */
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ctx.ifname, IFNAMSIZ - 1);
    if (ioctl(ctx.raw_sock, SIOCGIFINDEX, &ifr) < 0) {
        perror("SIOCGIFINDEX");
        exit(EXIT_FAILURE);
    }
    ctx.ifindex = ifr.ifr_ifindex;

    /* Get MAC address */
    if (ioctl(ctx.raw_sock, SIOCGIFHWADDR, &ifr) < 0) {
        perror("SIOCGIFHWADDR");
        exit(EXIT_FAILURE);
    }
    memcpy(ctx.mac, ifr.ifr_hwaddr.sa_data, ETH_ALEN);

    /* Bind socket to interface */
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_IP);
    sll.sll_ifindex = ctx.ifindex;
    if (bind(ctx.raw_sock, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        perror("bind");
        exit(EXIT_FAILURE);
    }

    /* Start DHCP discovery */
    ctx.state = STATE_INIT;
    send_dhcp_message(DHCP_DISCOVER);
    ctx.state = STATE_SELECTING;
    printf(">> Sent DHCP DISCOVER\n");

    pfd.fd = ctx.raw_sock;
    pfd.events = POLLIN;
    timeout = 4000;   /* initial timeout (ms) */

    while (1) {
        ret = poll(&pfd, 1, timeout);

        if (ret == 0) {
            /* Timeout handling */
            if (ctx.state == STATE_SELECTING) {
                printf(">> Timeout: no OFFER, retransmit DISCOVER (backoff)\n");
                send_dhcp_message(DHCP_DISCOVER);
                if (timeout == 4000)
                    timeout = 8000;
                else if (timeout < 64000)
                    timeout <<= 1;
            } else if (ctx.state == STATE_BOUND) {
                printf(">> T1 timeout: entering RENEWING state\n");
                ctx.state = STATE_RENEWING;
                send_dhcp_message(DHCP_REQUEST);
                timeout = 4000;
            } else if (ctx.state == STATE_RENEWING) {
                printf(">> Renewal timeout: entering REBINDING state\n");
                ctx.state = STATE_REBINDING;
                send_dhcp_message(DHCP_REQUEST);
                timeout = 4000;
            } else if (ctx.state == STATE_REBINDING) {
                /* Rebind timeout: restart discovery */
                printf(">> Rebind timeout: restarting discovery\n");
                ctx.state = STATE_INIT;
                send_dhcp_message(DHCP_DISCOVER);
                ctx.state = STATE_SELECTING;
                timeout = 4000;
            }
            continue;
        }

        /* Receive packet */
        int len = recv(ctx.raw_sock, buffer, BUFFER_SIZE, 0);
        if (len < (int)(sizeof(struct eth_hdr) +
                        sizeof(struct ip_hdr) +
                        sizeof(struct udp_hdr))) {
            continue;
        }

        struct raw_packet *pkt = (struct raw_packet *)buffer;

        /* Validate protocol and destination port */
        if (pkt->ip.protocol != IPPROTO_UDP ||
            ntohs(pkt->udp.dest) != DHCP_CLIENT_PORT) {
            continue;
        }

        /* Match transaction ID */
        if (ntohl(pkt->dhcp.xid) != ctx.xid)
            continue;

        uint8_t msg_type = 0;
        int dhcp_fixed_len = offsetof(struct dhcp_packet, options);
        int options_len = ntohs(pkt->udp.len) - sizeof(struct udp_hdr) - dhcp_fixed_len;
        if (options_len < 0) continue;
        parse_dhcp_options(&pkt->dhcp, options_len, &msg_type);

        /* State machine */
        switch (ctx.state) {
            case STATE_SELECTING:
                if (msg_type == DHCP_OFFER) {
                    ctx.offered_ip = pkt->dhcp.yiaddr;
                    printf(">> Received DHCP OFFER: offered IP %s\n",
                           inet_ntoa(*(struct in_addr *)&ctx.offered_ip));
                    send_dhcp_message(DHCP_REQUEST);
                    ctx.state = STATE_REQUESTING;
                    timeout = 4000;
                }
                break;

            case STATE_REQUESTING:
            case STATE_RENEWING:
            case STATE_REBINDING:
                if (msg_type == DHCP_ACK) {
                    printf(">> Received DHCP ACK, applying configuration\n");
                    apply_network_config();
                    ctx.state = STATE_BOUND;
                    if (ctx.lease_time == 0)
                        ctx.lease_time = 3600;   /* fallback 1 hour */
                    timeout = (ctx.lease_time / 2) * 1000;   /* T1 = 50% */
                    printf(">> Lease time %u sec, T1 timer set to %u sec\n",
                           ctx.lease_time, ctx.lease_time / 2);
                } else if (msg_type == DHCP_NAK) {
                    printf(">> DHCP NAK received, restarting\n");
                    ctx.state = STATE_INIT;
                    send_dhcp_message(DHCP_DISCOVER);
                    ctx.state = STATE_SELECTING;
                    timeout = 4000;
                }
                break;

            default:
                break;
        }
    }

    close(ctx.raw_sock);
    return 0;
}
