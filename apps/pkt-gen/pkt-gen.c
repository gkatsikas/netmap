/*
 * Copyright (C) 2015 Georgios Katsikas - KTH Royal Institute of Technology. All rights reserved.
 * Copyright (C) 2011-2014 Matteo Landi, Luigi Rizzo. All rights reserved.
 * Copyright (C) 2013-2015 Universita` di Pisa. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *   1. Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *   2. Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * $FreeBSD$
 * $Id: pkt-gen.c 12346 2013-06-12 17:36:25Z luigi $
 *
 * Example program to show how to build a multithreaded packet
 * source/sink using the netmap device.
 * Extended by Georgios Katsikas to support pcap trace replay.
 *
 * In this example we create a programmable number of threads
 * to take care of all the queues of the interface used to
 * send or receive traffic.
 *
 */

#define _GNU_SOURCE	/* for CPU_SET() */
#include <stdio.h>
#define NETMAP_WITH_LIBS
#include <net/netmap_user.h>


#include <ctype.h>	// isprint()
#include <unistd.h>	// sysconf()
#include <sys/poll.h>
#include <arpa/inet.h>	/* ntohs */
#ifndef _WIN32
#include <sys/sysctl.h>	/* sysctl */
#endif
#include <ifaddrs.h>	/* getifaddrs */
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>

#include <pthread.h>
#include <signal.h>

//#ifndef NO_PCAP
#include <math.h>
#include <pcap/pcap.h>
#include "packet.h"
#include "huge_vector.h"
#define GB 1000000000
#define TRUE  1
#define FALSE 0
//#endif

#ifdef _WIN32
#define cpuset_t        DWORD_PTR   //uint64_t
static inline void CPU_ZERO(cpuset_t *p) {
	*p = 0;
}

static inline void CPU_SET(uint32_t i, cpuset_t *p) {
	*p |= 1<< (i & 0x3f);
}

#define pthread_setaffinity_np(a, b, c) !SetThreadAffinityMask(a, *c)    //((void)a, 0)
#define TAP_CLONEDEV	"/dev/tap"
#define AF_LINK	18	//defined in winsocks.h
#define CLOCK_REALTIME_PRECISE CLOCK_REALTIME
#include <net/if_dl.h>

/*
 * Convert an ASCII representation of an ethernet address to
 * binary form.
 */
struct ether_addr *
ether_aton(const char *a) {
	int i;
	static struct ether_addr o;
	unsigned int o0, o1, o2, o3, o4, o5;

	i = sscanf(a, "%x:%x:%x:%x:%x:%x", &o0, &o1, &o2, &o3, &o4, &o5);

	if (i != 6)
		return (NULL);

	o.octet[0]=o0;
	o.octet[1]=o1;
	o.octet[2]=o2;
	o.octet[3]=o3;
	o.octet[4]=o4;
	o.octet[5]=o5;

	return ((struct ether_addr *)&o);
}

/*
 * Convert a binary representation of an ethernet address to
 * an ASCII string.
 */
char *
ether_ntoa(const struct ether_addr *n) {
	int i;
	static char a[18];

	i = sprintf(a, "%02x:%02x:%02x:%02x:%02x:%02x",
				n->octet[0], n->octet[1], n->octet[2],
				n->octet[3], n->octet[4], n->octet[5]);
	return (i < 17 ? NULL : (char *)&a);
}
#endif /* _WIN32 */

#ifdef linux

#define cpuset_t        cpu_set_t

#define ifr_flagshigh  ifr_flags          /* only the low 16 bits here */
#define IFF_PPROMISC   IFF_PROMISC      /* IFF_PPROMISC does not exist */
#include <linux/ethtool.h>
#include <linux/sockios.h>

#define CLOCK_REALTIME_PRECISE CLOCK_REALTIME
#include <netinet/ether.h>        /* ether_aton */
#include <linux/if_packet.h>     /* sockaddr_ll */
#endif  /* linux */

#ifdef __FreeBSD__
#include <sys/endian.h> /* le64toh */
#include <machine/param.h>

#include <pthread_np.h> /* pthread w/ affinity */
#include <sys/cpuset.h> /* cpu_set */
#include <net/if_dl.h>  /* LLADDR */
#endif  /* __FreeBSD__ */

#ifdef __APPLE__

#define cpuset_t        uint64_t        // XXX
static inline void CPU_ZERO(cpuset_t *p) {
	*p = 0;
}

static inline void CPU_SET(uint32_t i, cpuset_t *p) {
	*p |= 1<< (i & 0x3f);
}

#define pthread_setaffinity_np(a, b, c) ((void)a, 0)

#define ifr_flagshigh  ifr_flags        // XXX
#define IFF_PPROMISC   IFF_PROMISC
#include <net/if_dl.h>  /* LLADDR */
#define clock_gettime(a,b) \
	do {struct timespec t0 = {0,0}; *(b) = t0; } while (0)
#endif  /* __APPLE__ */

const char *default_payload="netmap pkt-gen DIRECT payload\n"
	"http://info.iet.unipi.it/~luigi/netmap/ ";

const char *indirect_payload="netmap pkt-gen indirect payload\n"
	"http://info.iet.unipi.it/~luigi/netmap/ ";

int verbose      = FALSE;
int full_verbose = FALSE;

#define VIRT_HDR_1	10	           /* length of a base vnet-hdr */
#define VIRT_HDR_2	12	     /* length of the extenede vnet-hdr */
#define VIRT_HDR_MAX	VIRT_HDR_2
struct virt_header {
	uint8_t fields[VIRT_HDR_MAX];
};

#define MAX_BODYSIZE 	16384

enum pkt_type { IP_PKT, ICMP_PKT, UDP_DGRAM, TCP_SEGM, OTHER };

struct pkt {
	struct  virt_header  vh;
	struct  ether_header eh;
	struct  ip ip;

	// Discriminate ICMP, UDP and TCP packets
	enum pkt_type type;

	// Beyond IP header, we support ICMP/UDP/TCP headers
	union {
		struct icmphdr icmp;
		struct udphdr  udp;
		struct tcphdr  tcp;
	} beyond_l3;

	// Packet payload
	uint8_t body[MAX_BODYSIZE];	                   /* hardwired */
} __attribute__((__packed__));

struct ip_range {
	char     *name;
	uint32_t start, end;                  /* same as struct in_addr */
	uint16_t port0, port1;
};

struct mac_range {
	char*  name;
	struct ether_addr start, end;
};

/* ifname can be netmap:foo-xxxx */
#define MAX_IFNAMELEN 64	               /* our buffer for ifname */
#define MAX_PKTSIZE	  MAX_BODYSIZE	          /* + IP_HDR + ETH_HDR */

/* Compact timestamp to fit into 60 byte packet. (enough to obtain RTT) */
struct tstamp {
	uint32_t sec;
	uint32_t nsec;
};

/* Counters to accumulate statistics */
struct my_ctrs {
	uint64_t pkts, bytes, events;
	struct timeval t;
};

/*
 * Global arguments for all threads
 */
struct glob_arg {
	struct ip_range  src_ip;
	struct ip_range  dst_ip;
	struct mac_range dst_mac;
	struct mac_range src_mac;
	int              pkt_size;
	int              burst;
	int              forever;
	int              npackets;              /* total packets to send or receive */
	int              frags;	                /* fragments per packet */
	int              nthreads;
	int              cpus;	                /* cpus used for running */
	int              system_cpus;           /* cpus on the system */

	int              options;               /* testing */
#define OPT_PREFETCH      1
#define OPT_ACCESS        2
#define OPT_COPY          4
#define OPT_MEMCPY        8
#define OPT_TS           16	                /* add a timestamp */
#define OPT_INDIRECT     32	                /* use indirect buffers, tx only */
#define OPT_DUMP         64	                /* dump rx/tx traffic */
#define OPT_RUBBISH     256	                /* send wathever the buffers contain */
#define OPT_RANDOM_SRC  512
#define OPT_RANDOM_DST 1024
	int              dev_type;
	pcap_t           *p;

	int              tx_rate;
	struct timespec  tx_period;

	int              affinity;
	int              main_fd;
	struct nm_desc   *nmd;
	int              report_interval;       /* milliseconds between prints */
	void             *(*td_body)(void *);
	void             *mmap_addr;
	char             ifname[MAX_IFNAMELEN];
	char             *nmr_config;
	int              dummy_send;
	int              virt_header;           /* send also the virt_header */
	int              extra_bufs;            /* goes in nr_arg3 */
	int              extra_pipes;           /* goes in nr_arg1 */
	char             *packet_file;          /* -P option */
};

enum dev_type { DEV_NONE, DEV_NETMAP, DEV_PCAP, DEV_TAP };

/*
 * Arguments for a new thread. The same structure is used by
 * the source and the sink
 */
struct targ {
	struct glob_arg  *g;
	int              used;
	int              completed;
	int              cancel;
	int              fd;
	struct nm_desc   *nmd;

	/*
	 * These ought to be volatile, but they are
	 * only sampled and errors should not accumulate
	 */
	struct my_ctrs   ctr;

	struct timespec  tic, toc;
	int              me;
	pthread_t        thread;
	int              affinity;

	struct           pkt pkt;
	void             *frame;
};

/*
 * In case we generate packets from pcap trace, this struct keeps a huge vector
 * with the loaded packets (and the number of loaded packets) to be emitted.
 * The vector is a custom implementation detailed in huge_vector.h and .c
 */
// If 1, generate traffic using a pcap trace
unsigned short          read_from_pcap;
// If 1, calculate latency by writing and reading timestamps to/from the packets' palyload.
unsigned short          latency_calc;
// In rx mode, if the user has specified the number of packets to be received (-n), then selecting (-t)
// will result in the receiver stoppong receiving packets before reaching the limit set by -n.
// This tolerance is a hardcoded percentage between 70-95%.
unsigned short          pkt_loss_tolerance;
float                   tolerance_amount;
// This variable denotes the minimum duration of the traffic.
// It can be calculated as pkts_to_send/pkt_rate if we know how the Tx program is set.
// After min_rx_duration has elapsed, we fire an alarm signal to stop the receiver.
float                   min_rx_duration;
volatile unsigned short stop_rx;
// If user kills the process this variable sets to 1 (TRUE)
volatile unsigned short is_killed;

// Data structure to host the packets
struct pcap_trace {
	huge_vector   loaded_pkts;
	vector_size_t loaded_pkts_no;
};

// The global instance to host the packets
static struct pcap_trace pt;
// Numner of packets to be loaded
//static vector_size_t  MAX_PACKETS_TO_READ = 10000000;
// Maximum size per packet
static unsigned short MAX_PKT_SIZE        = 1500;
// Minimum IP header size
static unsigned short MIN_IP_HEADER_SIZE  = 20;

/*
 * extract the extremes from a range of ipv4 addresses.
 * addr_lo[-addr_hi][:port_lo[-port_hi]]
 */
static void
extract_ip_range(struct ip_range *r) {
	char *ap, *pp;
	struct in_addr a;

	if ( verbose ) {
		D("Extract IP range from %s", r->name);
	}
	r->port0 = r->port1 = 0;
	r->start = r->end = 0;

	/* the first - splits start/end of range */
	ap = index(r->name, '-');	                /* do we have ports ? */
	if (ap) {
		*ap++ = '\0';
	}
	/* grab the initial values (mandatory) */
	pp = index(r->name, ':');
	if (pp) {
		*pp++ = '\0';
		r->port0 = r->port1 = strtol(pp, NULL, 0);
	};
	inet_aton(r->name, &a);
	r->start = r->end = ntohl(a.s_addr);
	if (ap) {
		pp = index(ap, ':');
		if (pp) {
			*pp++ = '\0';
			if (*pp) {
				r->port1 = strtol(pp, NULL, 0);
			}
		}
		if (*ap) {
			inet_aton(ap, &a);
			r->end = ntohl(a.s_addr);
		}
	}

	if (r->port0 > r->port1) {
		uint16_t tmp = r->port0;
		r->port0 = r->port1;
		r->port1 = tmp;
	}

	if (r->start > r->end) {
		uint32_t tmp = r->start;
		r->start = r->end;
		r->end = tmp;
	}

	{
		struct in_addr a;
		char buf1[16]; // one ip address

		a.s_addr = htonl(r->end);
		strncpy(buf1, inet_ntoa(a), sizeof(buf1));
		a.s_addr = htonl(r->start);
		if ( verbose ) {
			D("Range is %s:%d to %s:%d", inet_ntoa(a), r->port0, buf1, r->port1);
		}
	}
}

static void
extract_mac_range(struct mac_range* r) {
	if ( verbose ) {
		D("Extract MAC range from %s", r->name);
	}
	bcopy(ether_aton(r->name), &r->start, 6);
	bcopy(ether_aton(r->name), &r->end, 6);
#if 0
	bcopy(targ->src_mac, eh->ether_shost, 6);
	p = index(targ->g->src_mac, '-');
	if (p) {
		targ->src_mac_range = atoi(p+1);
	}

	bcopy(ether_aton(targ->g->dst_mac), targ->dst_mac, 6);
	bcopy(targ->dst_mac, eh->ether_dhost, 6);
	p = index(targ->g->dst_mac, '-');
	if (p) {
		targ->dst_mac_range = atoi(p+1);
	}
#endif
	if ( verbose ) {
		D("%s starts at %s", r->name, ether_ntoa(&r->start));
	}
}

static struct targ *targs;
static int global_nthreads;

/* control-C handler */
static void
sigint_h(int sig) {
	int i;

	(void)sig;	/* UNUSED */
	D("Received control-C on thread %p", (void *)pthread_self());
	for (i = 0; i < global_nthreads; i++) {
		targs[i].cancel = 1;
	}

	// Release memory before you leave
	if ( read_from_pcap && !is_killed ) {
		huge_vector_free(&pt.loaded_pkts);

		// Make sure you do not double release any buffer
		is_killed = TRUE;
	}

	signal(SIGINT, SIG_DFL);
}

/* sysctl wrapper to return the number of active CPUs */
static int
system_ncpus(void) {
	int ncpus;
#if defined (__FreeBSD__)
	int mib[2] = { CTL_HW, HW_NCPU };
	size_t len = sizeof(mib);
	sysctl(mib, 2, &ncpus, &len, NULL, 0);
#elif defined(linux)
	ncpus = sysconf(_SC_NPROCESSORS_ONLN);
#elif defined(_WIN32)
	{
		SYSTEM_INFO sysinfo;
		GetSystemInfo(&sysinfo);
		ncpus = sysinfo.dwNumberOfProcessors;
	}
#else /* others */
	ncpus = 1;
#endif /* others */
	return (ncpus);
}

#ifdef __linux__
#define sockaddr_dl    sockaddr_ll
#define sdl_family     sll_family
#define AF_LINK        AF_PACKET
#define LLADDR(s)      s->sll_addr;
#include <linux/if_tun.h>
#define TAP_CLONEDEV	"/dev/net/tun"
#endif /* __linux__ */

#ifdef __FreeBSD__
#include <net/if_tun.h>
#define TAP_CLONEDEV	"/dev/tap"
#endif /* __FreeBSD */

#ifdef __APPLE__
// #warning TAP not supported on apple ?
#include <net/if_utun.h>
#define TAP_CLONEDEV	"/dev/tap"
#endif /* __APPLE__ */

/*
 * parse the vale configuration in conf and put it in nmr.
 * Return the flag set if necessary.
 * The configuration may consist of 0 to 4 numbers separated
 * by commas: #tx-slots,#rx-slots,#tx-rings,#rx-rings.
 * Missing numbers or zeroes stand for default values.
 * As an additional convenience, if exactly one number
 * is specified, then this is assigned to both #tx-slots and #rx-slots.
 * If there is no 4th number, then the 3rd is assigned to both #tx-rings
 * and #rx-rings.
 */
int
parse_nmr_config(const char *conf, struct nmreq *nmr) {
	char *w, *tok;
	int i;

	nmr->nr_tx_rings = nmr->nr_rx_rings = 0;
	nmr->nr_tx_slots = nmr->nr_rx_slots = 0;
	if (conf == NULL || ! *conf) {
		return 0;
	}

	w = strdup(conf);
	for (i = 0, tok = strtok(w, ","); tok; i++, tok = strtok(NULL, ",")) {
		int v = atoi(tok);
		switch (i) {
			case 0:
				nmr->nr_tx_slots = nmr->nr_rx_slots = v;
				break;
			case 1:
				nmr->nr_rx_slots = v;
				break;
			case 2:
				nmr->nr_tx_rings = nmr->nr_rx_rings = v;
				break;
			case 3:
				nmr->nr_rx_rings = v;
				break;
			default:
				D("Ignored config: %s", tok);
				break;
		}
	}

	D("Txr %d Txd %d Rxr %d Rxd %d",
			nmr->nr_tx_rings, nmr->nr_tx_slots,
			nmr->nr_rx_rings, nmr->nr_rx_slots);
	free(w);
	return (nmr->nr_tx_rings || nmr->nr_tx_slots ||
			nmr->nr_rx_rings || nmr->nr_rx_slots) ?
			NM_OPEN_RING_CFG : 0;
}


/*
 * locate the src mac address for our interface, put it
 * into the user-supplied buffer. return 0 if ok, -1 on error.
 */
static int
source_hwaddr(const char* ifname, char* buf) {
	struct ifaddrs *ifaphead, *ifap;
	int l = sizeof(ifap->ifa_name);

	if (getifaddrs(&ifaphead) != 0) {
		D("Getifaddrs %s failed", ifname);
		return (-1);
	}

	for (ifap = ifaphead; ifap; ifap = ifap->ifa_next) {
		struct sockaddr_dl *sdl = (struct sockaddr_dl *)ifap->ifa_addr;
		uint8_t *mac;

		if (!sdl || sdl->sdl_family != AF_LINK) {
			continue;
		}

		if (strncmp(ifap->ifa_name, ifname, l) != 0) {
			continue;
		}

		mac = (uint8_t *)LLADDR(sdl);
		sprintf(buf, "%02x:%02x:%02x:%02x:%02x:%02x",
			mac[0], mac[1], mac[2],
			mac[3], mac[4], mac[5]);

		if ( verbose ) {
			D("Source hwaddr %s", buf);
		}

		break;
	}
	freeifaddrs(ifaphead);
	return ifap ? 0 : 1;
}


/* set the thread affinity. */
static int
setaffinity(pthread_t me, int i) {
	cpuset_t cpumask;

	if (i == -1) {
		return 0;
	}

	/* Set thread affinity affinity.*/
	CPU_ZERO(&cpumask);
	CPU_SET(i, &cpumask);

	if ( pthread_setaffinity_np(me, sizeof(cpuset_t), &cpumask) != 0 ) {
		D("Unable to set affinity: %s", strerror(errno));
		return 1;
	}

	return 0;
}

/* Compute the checksum of the given IP header. */
static uint16_t
checksum(const void *data, uint16_t len, uint32_t sum) {
	const uint8_t *addr = data;
	uint32_t i;

	/* Checksum all the pairs of bytes first... */
	for (i = 0; i < (len & ~1U); i += 2) {
		sum += (u_int16_t)ntohs(*((u_int16_t *)(addr + i)));

		if (sum > 0xFFFF) {
			sum -= 0xFFFF;
		}
	}
	/*
	 * If there's a single byte left over, checksum it, too.
	 * Network byte order is big-endian, so the remaining byte is
	 * the high byte.
	 */
	if (i < len) {
		sum += addr[i] << 8;
		if (sum > 0xFFFF)
			sum -= 0xFFFF;
	}
	return sum;
}

static u_int16_t
wrapsum(u_int32_t sum) {
	sum = ~sum & 0xFFFF;
	return (htons(sum));
}

/* Check the payload of the packet for errors (use it for debug).
 * Look for consecutive ascii representations of the size of the packet.
 */
static void
dump_payload(const char *_p, int len, struct netmap_ring *ring, int cur) {
	char buf[128];
	int i, j;
	const unsigned char *p = (const unsigned char *)_p;

	/* get the length in ASCII of the length of the packet. */

	printf("ring %p cur %5d [buf %6d flags 0x%04x len %5d]\n",
			ring, cur, ring->slot[cur].buf_idx,
			ring->slot[cur].flags, len);

	/* hexdump routine */
	for (i = 0; i < len; ) {
		memset(buf, sizeof(buf), (const char)' ');
		sprintf(buf, "%5d: ", i);

		int i0 = i;
		for (j=0; j < 16 && i < len; i++, j++)
			sprintf(buf+7+j*3, "%02x ", (uint8_t)(p[i]));

		i = i0;
		for (j=0; j < 16 && i < len; i++, j++)
			sprintf(buf+7+j + 48, "%c",	isprint(p[i]) ? p[i] : '.');

		printf("%s\n", buf);
	}
}

/*
 * Fill a packet with some payload.
 * We create a UDP packet so the payload starts at
 *	14+20+8 = 42 bytes.
 */
#ifdef __linux__
#define uh_sport source
#define uh_dport dest
#define uh_ulen len
#define uh_sum check
#endif /* linux */

/*
 * In verbose mode, print the packets to be sent out
 */
void
print_packet_info(void* frame, int size) {
	// Check what's going on
	if ( verbose || full_verbose ) {
		void* tmp = frame;
		tmp += sizeof(struct ether_header);
		struct ip* ip_hdr = (struct ip*) tmp;

		// See the packet's destination
		if ( verbose )
			D("IP Size: %4d - IP dst: %s", size, inet_ntoa(ip_hdr->ip_dst));

		// See the packet to be sent
		if ( full_verbose ) {
			if      ( ip_hdr->ip_p == IPPROTO_IP   )
				print_ip_header(frame);
			else if ( ip_hdr->ip_p == IPPROTO_ICMP )
				print_icmp_header(frame);
			else if ( ip_hdr->ip_p == IPPROTO_UDP  )
				print_udp_header(frame);
			else if ( ip_hdr->ip_p == IPPROTO_TCP  )
				print_tcp_header(frame);
		}
	}
}

/*
 * Calculate UDP checksum
 * @param frame The raw data frame.
 * @param udp_paylen The length of UDP header + payload.
 */
static void
calculate_udp_checksum(void *frame, uint16_t udp_paylen){
	struct pkt        *pkt = (struct pkt*)(frame);
	struct ip      *ip_hdr = (struct ip*) (frame + sizeof(struct ether_header));
	struct udphdr *udp_hdr = (struct udphdr*)(ip_hdr + sizeof(struct ip));
	//struct ip      *ip_hdr = &pkt->ip;
	//struct udphdr *udp_hdr = (struct udphdr*)(&pkt->beyond_l3);

	if ( ip_hdr->ip_p != IPPROTO_UDP ) {
		if ( verbose || full_verbose )
			D("UDP checksum function received a non-UDP packet");
		return;
	}

	// Magic: taken from sbin/dhclient/packet.c
	udp_hdr->uh_sum = wrapsum(
		checksum(
				udp_hdr,
				sizeof(*udp_hdr),
				checksum(
					pkt->body,
					udp_paylen - sizeof(*udp_hdr),
					checksum(
							&ip_hdr->ip_src,
							2 * sizeof(ip_hdr->ip_src),
							IPPROTO_UDP + (u_int32_t)ntohs(udp_hdr->uh_ulen)
						)
				)
		)
	);
}

/*
 * Calculate the TCP checksum.
 * @param frame The raw data frame.
 * @param len The size of the TCP packet.
 */
static void
calculate_tcp_checksum(void *frame, short len) {

	struct pkt        *pkt = (struct pkt*)(frame);
	struct ip      *ip_hdr = (struct ip*) (frame + sizeof(struct ether_header));
	struct tcphdr *tcp_hdr = (struct tcphdr*)(ip_hdr + sizeof(struct ip));

	//struct ip      *ip_hdr = &pkt->ip;
	//struct tcphdr *tcp_hdr = (struct tcphdr*)(&pkt->beyond_l3);

	if ( ip_hdr->ip_p != IPPROTO_TCP ) {
		if ( verbose || full_verbose )
			D("TCP checksum function received a non-TCP packet");
		return;
	}

	const uint16_t *buf = (const uint16_t*) pkt;
	uint16_t *ip_src = (void *)&ip_hdr->ip_src;
	uint16_t *ip_dst = (void *)&ip_hdr->ip_dst;
	uint32_t sum;
	size_t   length = ntohs(ip_hdr->ip_len);

	// Calculate the sum 
	sum = 0;
	while (len > 1)	{
		sum += *buf++;
		if (sum & 0x80000000)
		sum = (sum & 0xFFFF) + (sum >> 16);
		len -= 2;
	}

	// Add the padding if the packet lenght is odd
	if ( len & 1 )
		sum += *((uint8_t *)buf);

	// Add the pseudo-header
	sum += *(ip_src++);
	sum += *ip_src;
	sum += *(ip_dst++);
	sum += *ip_dst;
	sum += htons(IPPROTO_TCP);
	sum += htons(length);

	// Add the carries
	while (sum >> 16)
		sum = (sum & 0xFFFF) + (sum >> 16);

	// Checksum is the one's complement of sum.
	tcp_hdr->check = (uint16_t)(~sum);
}

/*
 * Calculate ICMP checksum. Not tested!
 * @param frame The raw data frame.
 * @param len The size of the TCP packet.
 */
void
calculate_icmp_checksum(void *frame, short len) {

	struct pkt          *pkt = (struct pkt*)(frame);
	struct ip        *ip_hdr = (struct ip*) (frame + sizeof(struct ether_header));
	struct icmphdr *icmp_hdr = (struct icmphdr*)(ip_hdr + sizeof(struct ip));

	if ( ip_hdr->ip_p != IPPROTO_ICMP ) {
		if ( verbose || full_verbose )
			D("ICMP checksum function received a non-ICMP packet");
		return;
	}

	uint16_t *buffer = (uint16_t*) pkt;
	size_t    length = len;

	unsigned long cksum=0;
	while(length >1) {
		cksum+=*buffer++;
		length -=sizeof(u_short);
	}

	if( length )
		cksum += *(u_char*)buffer;

	cksum  = (cksum >> 16) + (cksum & 0xffff);
	cksum += (cksum >>16);

	// Checksum is the one's complement of sum.
	icmp_hdr->checksum = (uint16_t)(~cksum);
}

/*
 * Calculate packet's checksum based on protocol type.
 */
static void
calculate_checksum(u_char proto, void *frame){

	//struct pkt   *pkt = (struct pkt*)(frame);
	struct ip *ip_hdr = (struct ip*) (frame + sizeof(struct ether_header));

	short ip_pkt_len = ntohs(ip_hdr->ip_len);
	unsigned int ip_hdr_len = (unsigned int) (ip_hdr->ip_hl * 4);

	if ( verbose || full_verbose ) {
		D("IP packet length: %u", ip_pkt_len);
		D("IP header length: %d", ip_hdr_len);
	}

	if      ( proto == IPPROTO_UDP ) {
		//print_udp_header( (const unsigned char*)frame );
		uint16_t udp_paylen = ip_pkt_len - sizeof(struct ip);
		calculate_udp_checksum (frame, udp_paylen);
	}
	else if ( proto == IPPROTO_TCP ) {
		//print_tcp_header( (const unsigned char*)frame );
		calculate_tcp_checksum (frame, ntohs(ip_hdr->ip_len));
	}
	else if ( proto == IPPROTO_ICMP ) {
		//print_icmp_header( (const unsigned char*)frame );
		calculate_icmp_checksum(frame, ntohs(ip_hdr->ip_len));
	}
	else
		return;

	if ( verbose || full_verbose )
		print_packet_info(frame, (int) ip_pkt_len);
}

/*
 * Increment the addressed in the packet,
 * starting from the least significant field.
 *	DST_IP DST_PORT SRC_IP SRC_PORT
 */
static void
update_addresses(struct pkt *pkt, struct glob_arg *g) {
	uint32_t a;
	uint16_t p;
	struct ip *ip = &pkt->ip;

	if ( pkt->type != UDP_DGRAM )
		return;
	struct udphdr* udp = (struct udphdr*)(&pkt->beyond_l3);

	do {
		/* XXX for now it doesn't handle non-random src, random dst */
		if (g->options & OPT_RANDOM_SRC) {
			udp->uh_sport = random();
			ip->ip_src.s_addr = random();
		}
		else {
			p = ntohs(udp->uh_sport);
			if (p < g->src_ip.port1) { /* just inc, no wrap */
				udp->uh_sport = htons(p + 1);
				break;
			}
			udp->uh_sport = htons(g->src_ip.port0);

			a = ntohl(ip->ip_src.s_addr);
			if (a < g->src_ip.end) { /* just inc, no wrap */
				ip->ip_src.s_addr = htonl(a + 1);
				break;
			}
			ip->ip_src.s_addr = htonl(g->src_ip.start);

			udp->uh_sport = htons(g->src_ip.port0);
		}

		if (g->options & OPT_RANDOM_DST) {
			udp->uh_dport = random();
			ip->ip_dst.s_addr = random();
		}
		else {
			p = ntohs(udp->uh_dport);
			if (p < g->dst_ip.port1) { /* just inc, no wrap */
				udp->uh_dport = htons(p + 1);
				break;
			}
			udp->uh_dport = htons(g->dst_ip.port0);

			a = ntohl(ip->ip_dst.s_addr);
			if (a < g->dst_ip.end) { /* just inc, no wrap */
				ip->ip_dst.s_addr = htonl(a + 1);
				break;
			}
		}

		ip->ip_dst.s_addr = htonl(g->dst_ip.start);

	} while (0);
	// update checksum
}

/*
 * Initialize one packet and prepare for the next one.
 */
static void
initialize_packet(struct targ* targ) {

	void      *frame  = NULL;
	struct ip *ip_hdr = NULL;
	struct pkt   *pkt = &(targ)->pkt;

	// In trace mode, initialize with the first packet of the trace ;)
	if ( read_from_pcap ) {
		frame = huge_vector_get(pt.loaded_pkts, 0);
		void* tmp  = frame;
		tmp += sizeof(struct ether_header);

		ip_hdr = (struct ip*) tmp;
		int size = ntohs(ip_hdr->ip_len) + sizeof(struct ether_header);
		memset(&targ->pkt, 0, sizeof(struct pkt));
		memcpy(&targ->pkt, frame, size);

		targ->frame = frame;

		if      ( ip_hdr->ip_p == IPPROTO_IP   )
			targ->pkt.type = IP_PKT;
		else if ( ip_hdr->ip_p == IPPROTO_ICMP )
			targ->pkt.type = ICMP_PKT;
		else if ( ip_hdr->ip_p == IPPROTO_UDP  )
			targ->pkt.type = UDP_DGRAM;
		else if ( ip_hdr->ip_p == IPPROTO_TCP  )
			targ->pkt.type = TCP_SEGM;

		return;
	}

	// Basic structures
	frame = &targ->pkt;
	frame += sizeof(pkt->vh) - targ->g->virt_header;
	//targ->frame = frame;

	struct ether_header *eh;
	struct udphdr  *udp_hdr;
	uint16_t paylen = targ->g->pkt_size - sizeof(*eh) - sizeof(struct ip);
	const char *payload = targ->g->options & OPT_INDIRECT ? indirect_payload : default_payload;
	int i, l0 = strlen(payload);

	// Normal pkt-gen mode, all packets are UDP
	pkt->type = UDP_DGRAM;

	/* create a nice NULL-terminated string */
	for (i = 0; i < paylen; i += l0) {
		if (l0 > paylen - i) {
			l0 = paylen - i; // last round
		}
		bcopy(payload, pkt->body + i, l0);
	}

	pkt->body[i-1] = '\0';
	ip_hdr = &pkt->ip;

	/* prepare the headers */
	ip_hdr->ip_v = IPVERSION;
	ip_hdr->ip_hl = 5;
	ip_hdr->ip_tos = IPTOS_LOWDELAY;
	ip_hdr->ip_len = ntohs(targ->g->pkt_size - sizeof(*eh));
	ip_hdr->ip_id = 0;
	ip_hdr->ip_off = htons(IP_DF); /* Don't fragment */
	ip_hdr->ip_ttl = IPDEFTTL;
	ip_hdr->ip_p = IPPROTO_UDP;
	ip_hdr->ip_dst.s_addr = htonl(targ->g->dst_ip.start);
	ip_hdr->ip_src.s_addr = htonl(targ->g->src_ip.start);
	ip_hdr->ip_sum = wrapsum(checksum(ip_hdr, sizeof(*ip_hdr), 0));

	udp_hdr = (struct udphdr*)(&pkt->beyond_l3);
	udp_hdr->uh_sport = htons(targ->g->src_ip.port0);
	udp_hdr->uh_dport = htons(targ->g->dst_ip.port0);
	udp_hdr->uh_ulen = htons(paylen);

	calculate_checksum(ip_hdr->ip_p, (void*) frame);

	eh = &pkt->eh;
	bcopy(&targ->g->src_mac.start, eh->ether_shost, 6);
	bcopy(&targ->g->dst_mac.start, eh->ether_dhost, 6);
	eh->ether_type = htons(ETHERTYPE_IP);

	bzero(&pkt->vh, sizeof(pkt->vh));
}

static void
set_vnet_hdr_len(struct targ *t) {
	int err, l = t->g->virt_header;
	struct nmreq req;

	if (l == 0) {
		return;
	}

	memset(&req, 0, sizeof(req));
	bcopy(t->nmd->req.nr_name, req.nr_name, sizeof(req.nr_name));
	req.nr_version = NETMAP_API;
	req.nr_cmd = NETMAP_BDG_VNET_HDR;
	req.nr_arg1 = l;
	err = ioctl(t->fd, NIOCREGIF, &req);
	if (err) {
		D("Unable to set vnet header length %d", l);
	}
}

/*
 * Create and enqueue a batch of packets on a ring.
 * On the last one set NS_REPORT to tell the driver to generate
 * an interrupt when done.
 */
static int
send_packets(struct netmap_ring *ring, struct pkt *pkt, void *frame,
		int size, struct glob_arg *g, u_int count, int options, u_int nfrags) {

	u_int n, sent, cur = ring->cur;
	u_int fcnt;

	n = nm_ring_space(ring);
	if (n < count) {
		count = n;
	}

	if (count < nfrags)
		D("Truncating packet, no room for frags %d %d", count, nfrags);

#if 0
	if (options & (OPT_COPY | OPT_PREFETCH) ) {
		for (sent = 0; sent < count; sent++) {
			struct netmap_slot *slot = &ring->slot[cur];
			char *p = NETMAP_BUF(ring, slot->buf_idx);

			__builtin_prefetch(p);
			cur = nm_ring_next(ring, cur);
		}
		cur = ring->cur;
	}
#endif
	for (fcnt = nfrags, sent = 0; sent < count; sent++) {
		struct netmap_slot *slot = &ring->slot[cur];
		char *p = NETMAP_BUF(ring, slot->buf_idx);
		int buf_changed = slot->flags & NS_BUF_CHANGED;

		// Check what's going on
		if ( verbose || full_verbose )
			print_packet_info(frame, size);

		slot->flags = 0;
		// Dangerous if you want to test real systems
		if      (options & OPT_RUBBISH) {
			// Do nothing
		}
		// Just re-send whatever is in the frame.
		// You write once and then keep sending the same content (dangerous)
		else if (options & OPT_INDIRECT) {
			slot->flags |= NS_INDIRECT;
			slot->ptr = (uint64_t)((uintptr_t)frame);
		}
		// Preferred option for trace mode. It is also leveraging on Netmap's benefits.
		else if ((options & OPT_COPY) || buf_changed) {
			nm_pkt_copy(frame, p, size);
			if ( (fcnt == nfrags) && !read_from_pcap )
				update_addresses(pkt, g);
		}
		// Typical memory copy
		else if (options & OPT_MEMCPY) {
			memcpy(p, frame, size);
			if ( (fcnt == nfrags) && !read_from_pcap )
				update_addresses(pkt, g);
		}
		else if (options & OPT_PREFETCH) {
			__builtin_prefetch(p);
		}

		if (options & OPT_DUMP) {
			dump_payload(p, size, ring, cur);
		}

		slot->len = size;
		if (--fcnt > 0) {
			slot->flags |= NS_MOREFRAG;
		}
		else {
			fcnt = nfrags;
		}

		if (sent == count - 1) {
			slot->flags &= ~NS_MOREFRAG;
			slot->flags |= NS_REPORT;
		}
		cur = nm_ring_next(ring, cur);
	}
	ring->head = ring->cur = cur;

	return (sent);
}

/*
 * Index of the highest bit set
 */
uint32_t
msb64(uint64_t x) {
	uint64_t m = 1ULL << 63;
	int i;

	for (i = 63; i >= 0; i--, m >>=1) {
		if (m & x) {
			return i;
		}
	}
	return 0;
}

/*
 * Send a packet, and wait for a response.
 * The payload (after UDP header, ofs 42) has a 4-byte sequence
 * followed by a struct timeval (or bintime?)
 */
#define	PAY_OFS	42	     /* where in the UDP datagram... */

static void *
pinger_body(void *data) {
	struct targ *targ = (struct targ *) data;
	struct pollfd pfd = { .fd = targ->fd, .events = POLLIN };
	struct netmap_if *nifp = targ->nmd->nifp;
	int i, rx = 0, n = targ->g->npackets;
	void *frame;
	int size;
	uint32_t sent = 0;
	struct timespec ts, now, last_print;
	uint64_t count = 0, t_cur, t_min = ~0, av = 0;
	uint64_t buckets[64];	/* bins for delays, ns */

	frame = &targ->pkt;
	frame += sizeof(targ->pkt.vh) - targ->g->virt_header;
	size = targ->g->pkt_size + targ->g->virt_header;

	if (targ->g->nthreads > 1) {
		D("Can only ping with 1 thread");
		return NULL;
	}

	bzero(&buckets, sizeof(buckets));
	clock_gettime(CLOCK_REALTIME_PRECISE, &last_print);
	now = last_print;

	while (!targ->cancel && (n == 0 || (int)sent < n)) {
		struct netmap_ring *ring = NETMAP_TXRING(nifp, 0);
		struct netmap_slot *slot;
		char *p;
		for (i = 0; i < 1; i++) { /* XXX why the loop for 1 pkt ? */
			slot = &ring->slot[ring->cur];
			slot->len = size;
			p = NETMAP_BUF(ring, slot->buf_idx);

			if (nm_ring_empty(ring)) {
				D("Ouch, cannot send");
			}
			else {
				struct tstamp *tp;
				nm_pkt_copy(frame, p, size);
				clock_gettime(CLOCK_REALTIME_PRECISE, &ts);
				bcopy(&sent, p+42, sizeof(sent));
				tp = (struct tstamp *)(p+46);
				tp->sec  = (uint32_t)ts.tv_sec;
				tp->nsec = (uint32_t)ts.tv_nsec;
				sent++;
				ring->head = ring->cur = nm_ring_next(ring, ring->cur);
			}
		}

		/* should use a parameter to decide how often to send */
		if (poll(&pfd, 1, 3000) <= 0) {
			D("Poll error/timeout on queue %d: %s", targ->me, strerror(errno));
			continue;
		}

		/* see what we got back */
		for (i = targ->nmd->first_tx_ring; i <= targ->nmd->last_tx_ring; i++) {
			ring = NETMAP_RXRING(nifp, i);

			while (!nm_ring_empty(ring)) {
				uint32_t seq;
				struct tstamp *tp;
				int pos;

				slot = &ring->slot[ring->cur];
				p = NETMAP_BUF(ring, slot->buf_idx);

				clock_gettime(CLOCK_REALTIME_PRECISE, &now);
				bcopy(p+42, &seq, sizeof(seq));
				tp = (struct tstamp *)(p+46);
				ts.tv_sec = (time_t)tp->sec;
				ts.tv_nsec = (long)tp->nsec;
				ts.tv_sec = now.tv_sec - ts.tv_sec;
				ts.tv_nsec = now.tv_nsec - ts.tv_nsec;
				if (ts.tv_nsec < 0) {
					ts.tv_nsec += 1000000000;
					ts.tv_sec--;
				}

				if (0) {
					D("Seq %d/%d delta %d.%09d", seq, sent, (int)ts.tv_sec, (int)ts.tv_nsec);
				}

				t_cur = ts.tv_sec * 1000000000UL + ts.tv_nsec;
				if (t_cur < t_min)
					t_min = t_cur;
				count ++;
				av += t_cur;
				pos = msb64(t_cur);
				buckets[pos]++;

				/* Now store it in a bucket */
				ring->head = ring->cur = nm_ring_next(ring, ring->cur);
				rx++;
			}
		}

		//D("Tx %d Rx %d", sent, rx);
		//usleep(100000);
		ts.tv_sec = now.tv_sec - last_print.tv_sec;
		ts.tv_nsec = now.tv_nsec - last_print.tv_nsec;
		if (ts.tv_nsec < 0) {
			ts.tv_nsec += 1000000000;
			ts.tv_sec--;
		}

		if (ts.tv_sec >= 1) {
			D("Count %d RTT: min %d av %d ns", (int)count, (int)t_min, (int)(av/count));

			int k, j, kmin;
			char buf[512];

			for (kmin = 0; kmin < 64; kmin ++) {
				if (buckets[kmin]) {
					break;
				}
			}

			for (k = 63; k >= kmin; k--) {
				if (buckets[k]) {
					break;
				}
			}

			buf[0] = '\0';
			for (j = kmin; j <= k; j++) {
				sprintf(buf, "%s %5d", buf, (int)buckets[j]);
			}

			D("K: %d .. %d\n\t%s", 1<<kmin, 1<<k, buf);
			bzero(&buckets, sizeof(buckets));
			count = 0;
			av = 0;
			t_min = ~0;
			last_print = now;
		}
	}

	/* reset the ``used`` flag. */
	targ->used = 0;

	return NULL;
}


/*
 * Reply to ping requests
 */
static void *
ponger_body(void *data) {
	struct targ *targ = (struct targ *) data;
	struct pollfd pfd = { .fd = targ->fd, .events = POLLIN };
	struct netmap_if *nifp = targ->nmd->nifp;
	struct netmap_ring *txring, *rxring;
	int i, rx = 0, sent = 0, n = targ->g->npackets;

	if (targ->g->nthreads > 1) {
		D("Can only reply ping with 1 thread");
		return NULL;
	}

	D("Understood ponger %d but don't know how to do it", n);
	while (!targ->cancel && (n == 0 || sent < n)) {
		uint32_t txcur, txavail;
#ifdef BUSYWAIT
		ioctl(pfd.fd, NIOCRXSYNC, NULL);
#else
		if (poll(&pfd, 1, 1000) <= 0) {
			D("Poll error/timeout on queue %d: %s", targ->me, strerror(errno));
			continue;
		}
#endif
		txring = NETMAP_TXRING(nifp, 0);
		txcur = txring->cur;
		txavail = nm_ring_space(txring);

		/* see what we got back */
		for (i = targ->nmd->first_rx_ring; i <= targ->nmd->last_rx_ring; i++) {
			rxring = NETMAP_RXRING(nifp, i);
			while (!nm_ring_empty(rxring)) {
				uint16_t *spkt, *dpkt;
				uint32_t cur = rxring->cur;
				struct netmap_slot *slot = &rxring->slot[cur];
				char *src, *dst;
				src = NETMAP_BUF(rxring, slot->buf_idx);
				//D("Got pkt %p of size %d", src, slot->len);
				rxring->head = rxring->cur = nm_ring_next(rxring, cur);
				rx++;
				if (txavail == 0)
					continue;

				dst = NETMAP_BUF(txring, txring->slot[txcur].buf_idx);

				/* copy... */
				dpkt = (uint16_t *)dst;
				spkt = (uint16_t *)src;
				nm_pkt_copy(src, dst, slot->len);
				dpkt[0] = spkt[3];
				dpkt[1] = spkt[4];
				dpkt[2] = spkt[5];
				dpkt[3] = spkt[0];
				dpkt[4] = spkt[1];
				dpkt[5] = spkt[2];
				txring->slot[txcur].len = slot->len;
				/* XXX swap src dst mac */
				txcur = nm_ring_next(txring, txcur);
				txavail--;
				sent++;
			}
		}
		txring->head = txring->cur = txcur;
		targ->ctr.pkts = sent;
#ifdef BUSYWAIT
		ioctl(pfd.fd, NIOCTXSYNC, NULL);
#endif
		//D("Tx %d Rx %d", sent, rx);
	}

	/* reset the ``used`` flag. */
	targ->used = 0;

	return NULL;
}

static __inline int
timespec_ge(const struct timespec *a, const struct timespec *b) {

	if (a->tv_sec > b->tv_sec)
		return (1);
	if (a->tv_sec < b->tv_sec)
		return (0);
	if (a->tv_nsec >= b->tv_nsec)
		return (1);
	return (0);
}

static __inline struct timespec
timeval2spec(const struct timeval *a) {
	struct timespec ts = {
		.tv_sec = a->tv_sec,
		.tv_nsec = a->tv_usec * 1000
	};
	return ts;
}

static __inline struct timeval
timespec2val(const struct timespec *a) {
	struct timeval tv = {
		.tv_sec = a->tv_sec,
		.tv_usec = a->tv_nsec / 1000
	};
	return tv;
}

static __inline struct timespec
timespec_add(struct timespec a, struct timespec b) {
	struct timespec ret = { a.tv_sec + b.tv_sec, a.tv_nsec + b.tv_nsec };
	if (ret.tv_nsec >= 1000000000) {
		ret.tv_sec++;
		ret.tv_nsec -= 1000000000;
	}
	return ret;
}

static __inline struct timespec
timespec_sub(struct timespec a, struct timespec b) {
	struct timespec ret = { a.tv_sec - b.tv_sec, a.tv_nsec - b.tv_nsec };
	if (ret.tv_nsec < 0) {
		ret.tv_sec--;
		ret.tv_nsec += 1000000000;
	}
	return ret;
}

void
on_alarm (int signal) {
	D("Alarm %d caught: Minimum duration of %f seconds has elapsed", signal, min_rx_duration);
	stop_rx = TRUE;
}

/*
 * wait until ts, either busy or sleeping if more than 1ms.
 * Return wakeup time.
 */
static struct timespec
wait_time(struct timespec ts) {
	for (;;) {
		struct timespec w, cur;
		clock_gettime(CLOCK_REALTIME_PRECISE, &cur);
		w = timespec_sub(ts, cur);
		if (w.tv_sec < 0)
			return cur;
		else if (w.tv_sec > 0 || w.tv_nsec > 1000000)
			poll(NULL, 0, 1);
	}
}

static void *
sender_body(void *data) {
	struct targ* targ = (struct targ*) data;
	struct pollfd pfd = { .fd = targ->fd, .events = POLLOUT };
	struct netmap_if *nifp;
	struct netmap_ring *txring = NULL;
	int i, n = targ->g->npackets / targ->g->nthreads;
	int64_t sent = 0;
	int64_t sent_index = 0;
	uint64_t event = 0;
	int options = targ->g->options | OPT_COPY;
	struct timespec nexttime = {0, 0};          // XXX silence compiler
	int rate_limit = targ->g->tx_rate;
	struct pkt* pkt = &targ->pkt;
	void* frame = NULL;
	void* tmp   = NULL;
	int size    = 0;
	struct timespec timestamp;

	// Compose a static frame only if the trace mode (-P trace_path) is not active
	if ( !read_from_pcap ) {
		if ( !targ->frame ) {
			frame  = pkt;
			frame += sizeof(pkt->vh) - targ->g->virt_header;
			size   = targ->g->pkt_size + targ->g->virt_header;
		}
		else {
			frame = targ->frame;
			size  = targ->g->pkt_size;
		}
	}

	D("Start, fd %d main_fd %d", targ->fd, targ->g->main_fd);
	if ( setaffinity(targ->thread, targ->affinity) )
		goto quit;

	/* main loop.*/
	clock_gettime(CLOCK_REALTIME_PRECISE, &targ->tic);
	if ( rate_limit ) {
		targ->tic = timespec_add(targ->tic, (struct timespec){2,0});
		targ->tic.tv_nsec = 0;
		wait_time(targ->tic);
		nexttime = targ->tic;
	}

	if (targ->g->dev_type == DEV_TAP) {
		D("Writing to file desc %d", targ->g->main_fd);

		for (i = 0; !targ->cancel && (n == 0 || sent < n); i++) {
			// If pcap trace option is given, frame variable gets a packet from the trace
			if ( read_from_pcap && ((vector_size_t) sent < pt.loaded_pkts_no) ) {
				frame = huge_vector_get(pt.loaded_pkts, (vector_size_t)sent);

				// Check what's going on
				if ( verbose || full_verbose )
					print_packet_info(frame, size);
			}

			// Typical syscall to write to the socket
			if (write(targ->g->main_fd, frame, size) != -1)
				sent++;

			// Only normal pkt-gen execution can incrementally update IPs and ports
			if ( !read_from_pcap )
				update_addresses(pkt, targ->g);

			if (i > 10000) {
				targ->ctr.pkts   = sent;
				targ->ctr.bytes  = sent*size;
				targ->ctr.events = sent;
				i = 0;
			}
		}
	}
	else if (targ->g->dev_type == DEV_PCAP) {
		pcap_t *p = targ->g->p;

		for (i = 0; !targ->cancel && (n == 0 || sent < n); i++) {
			// If pcap trace option is given, frame variable gets a packet from the trace
			if ( read_from_pcap && ((vector_size_t) sent < pt.loaded_pkts_no) ) {
				frame = huge_vector_get(pt.loaded_pkts, (vector_size_t)sent);

				// Check what's going on
				if ( verbose || full_verbose )
					print_packet_info(frame, size);
			}

			if (pcap_inject(p, frame, size) != -1)
				sent++;

			// Only normal pkt-gen execution can incrementally update IPs and ports
			if ( !read_from_pcap )
				update_addresses(pkt, targ->g);

			if (i > 10000) {
				targ->ctr.pkts   = sent;
				targ->ctr.bytes  = sent*size;
				targ->ctr.events = sent;
				i = 0;
			}
		}
	}
	else if (targ->g->dev_type == DEV_NETMAP) {
		int tosend = 0;
		int frags = targ->g->frags;

		nifp = targ->nmd->nifp;
		while (!targ->cancel && (n == 0 || sent < n)) {

			if (rate_limit && tosend <= 0) {
				tosend = targ->g->burst;
				nexttime = timespec_add(nexttime, targ->g->tx_period);
				wait_time(nexttime);
			}

			/*
			 * Wait for available room in the send queue(s)
			 */
		#ifdef BUSYWAIT
			if (ioctl(pfd.fd, NIOCTXSYNC, NULL) < 0) {
				D("IOCTL error on queue %d: %s", targ->me, strerror(errno));
				goto quit;
			}
		#else /* !BUSYWAIT */
			if (poll(&pfd, 1, 2000) <= 0) {
				if (targ->cancel)
					break;
				D("Poll error/timeout on queue %d: %s", targ->me, strerror(errno));
				// goto quit;
			}
			if (pfd.revents & POLLERR) {
				D("Poll error on %d ring %d-%d", pfd.fd, targ->nmd->first_tx_ring, targ->nmd->last_tx_ring);
				goto quit;
			}
		#endif /* !BUSYWAIT */

			/*
			 * Scan our queues and send on those with room
			 */
			if (options & OPT_COPY && sent > 100000 && !(targ->g->options & OPT_COPY) ) {
				D("Drop copy");
				options &= ~OPT_COPY;
			}

			for (i = targ->nmd->first_tx_ring; i <= targ->nmd->last_tx_ring; i++) {
				int m, limit = rate_limit ? tosend : targ->g->burst;

				if (n > 0 && n - sent < limit)
					limit = n - sent;

				// Reset the index of the pcap file in order to start transmitting all over again
				if ( read_from_pcap && ((vector_size_t)sent_index >= pt.loaded_pkts_no) ) {
					sent_index = 0;
					//D("Packet limit: %ld --> Huge vector exhausted, reseting...", sent);
				}

				struct ip* ip_hdr;

				// If pcap trace option is given, frame variable gets a packet from the trace.
				// All threads (if more than 1) pick the same packet in each round.
				if ( read_from_pcap ) {
					//D("Trace option");
					frame  = huge_vector_get(pt.loaded_pkts, (vector_size_t)sent_index);
					tmp    = frame;
					tmp   += sizeof(struct ether_header);
					ip_hdr = (struct ip*) (tmp);
					size   = ntohs(ip_hdr->ip_len) + sizeof(struct ether_header);
				}
				else {
					//D("Non trace option");
					tmp    = frame;
					tmp   += sizeof(struct ether_header);
					ip_hdr = (struct ip*) (tmp);
				}

				if ( latency_calc ) {
					// Obtain a timestamp and dump it to the payload
					struct tstamp *tp;
					clock_gettime(CLOCK_REALTIME_PRECISE, &timestamp);

					char *p = (char*)frame;
					unsigned int ip_hdr_len = (unsigned int) (ip_hdr->ip_hl * 4);
					unsigned int hdr_len    = sizeof(struct ether_header) + ip_hdr_len;
					//D("Hdr len: %d", hdr_len);

					// Adding a timestamp in the UDP payload
					if      ( ip_hdr->ip_p == IPPROTO_UDP )
						hdr_len += sizeof(struct udphdr);
					else if ( ip_hdr->ip_p == IPPROTO_ICMP )
						hdr_len += sizeof(struct icmphdr);
					else if ( ip_hdr->ip_p == IPPROTO_TCP )
						hdr_len += sizeof(struct tcphdr);
					else
						continue;

					bcopy(&sent, p+hdr_len, sizeof(sent));
					tp = (struct tstamp *)(p + hdr_len + sizeof(sent));
					tp->sec  = (uint32_t)timestamp.tv_sec;
					tp->nsec = (uint32_t)timestamp.tv_nsec;
					//D("Timestamp is written");

					calculate_checksum(ip_hdr->ip_p, frame);
					//D("Checksum is calculated");
				}

				// Get a place in the Tx ring
				txring = NETMAP_TXRING(nifp, i);
				if (nm_ring_empty(txring)) {
					continue;
				}

				if (frags > 1)
					limit = ((limit + frags - 1) / frags) * frags;

				// Send the packet
				m = send_packets(txring, pkt, frame, size, targ->g, limit, options, frags);

				ND("Limit %d tail %d frags %d m %d", limit, txring->tail, frags, m);
				sent += m;
				sent_index += m;
				if (m > 0)
					event++;

				targ->ctr.pkts   = sent;
				targ->ctr.bytes  = sent*size;
				targ->ctr.events = event;
				if (rate_limit) {
					tosend -= m;
					if (tosend <= 0)
						break;
				}
			}
		}

		/* flush any remaining packets */
		D("Flush tail %d head %d on thread %p", txring->tail, txring->head, (void *)pthread_self());
		ioctl(pfd.fd, NIOCTXSYNC, NULL);

		/* final part: wait all the TX queues to be empty. */
		/*for (i = targ->nmd->first_tx_ring; i <= targ->nmd->last_tx_ring; i++) {
			txring = NETMAP_TXRING(nifp, i);
			while (nm_tx_pending(txring)) {
				RD(5, "pending tx tail %d head %d on ring %d", txring->tail, txring->head, i);
				ioctl(pfd.fd, NIOCTXSYNC, NULL);
				usleep(1); // wait 1 tick
			}
		}*/
	} /* end DEV_NETMAP */
	else {
		D("Unsupported device type %d", targ->g->dev_type);
		goto quit;
	}

	clock_gettime(CLOCK_REALTIME_PRECISE, &targ->toc);
	targ->completed  = 1;
	targ->ctr.pkts   = sent;
	targ->ctr.bytes  = sent*size;
	targ->ctr.events = event;

	quit:
		/* Reset the 'used' flag. */
		targ->used = 0;

	return (NULL);
}


//#ifndef NO_PCAP
static void
receive_pcap(u_char *user, const struct pcap_pkthdr * h, const u_char * bytes) {
	int *count = (int *)user;
	(void)h;	    /* UNUSED */
	(void)bytes;	/* UNUSED */
	(*count)++;
}
//#endif /* !NO_PCAP */

static int
receive_packets(struct netmap_ring *ring, u_int limit, int dump, uint64_t *bytes) {
//receive_packets(struct netmap_ring *ring, u_int limit, int dump, uint64_t *bytes,
//				uint64_t *buckets, struct timespec *now, uint64_t *count, uint64_t *t_min, uint64_t *av) {
	u_int cur, rx, n;
	uint64_t b = 0;

	///////////////////////////////////////////////////////////////////
	// Timestamping
	///////////////////////////////////////////////////////////////////
	if ( latency_calc ) {
		//struct timespec ts;
		//uint64_t t_cur = 0;
		//D("Entered");
	}
	///////////////////////////////////////////////////////////////////

	if ( !bytes )
		bytes = &b;

	cur = ring->cur;
	n = nm_ring_space(ring);
	if ( n < limit )
		limit = n;

	for (rx = 0; rx < limit; rx++) {
		struct netmap_slot *slot = &ring->slot[cur];
		char *p = NETMAP_BUF(ring, slot->buf_idx);

		*bytes += slot->len;
		if (dump)
			dump_payload(p, slot->len, ring, cur);

		cur = nm_ring_next(ring, cur);

		///////////////////////////////// Calculate latency /////////////////////////////////
		if ( latency_calc ) {
			/*
			uint32_t seq;
			struct tstamp *tp;
			int pos;

			clock_gettime(CLOCK_REALTIME_PRECISE, now);
			D("Timer");
			bcopy(p+42, &seq, sizeof(seq));
			tp = (struct tstamp *)(p+46);
			ts.tv_sec = (time_t)tp->sec;
			ts.tv_nsec = (long)tp->nsec;
			ts.tv_sec = now->tv_sec - ts.tv_sec;
			ts.tv_nsec = now->tv_nsec - ts.tv_nsec;
			if (ts.tv_nsec < 0) {
				ts.tv_nsec += 1000000000;
				ts.tv_sec--;
			}
			D("Middle");

			t_cur = ts.tv_sec * 1000000000UL + ts.tv_nsec;
			if ( t_cur < *t_min )
				t_min = &t_cur;
			(*count)++;
			D("0");
			(*av) += t_cur;
			D("1");
			pos = msb64(t_cur);
			D("2");
			//ptr = *buckets;
			buckets[pos]++;
			D("End");
			*/
		}
		/////////////////////////////////
	}

	ring->head = ring->cur = cur;

	return (rx);
}

static void *
receiver_body(void *data) {
	struct targ *targ = (struct targ *) data;
	struct pollfd pfd = { .fd = targ->fd, .events = POLLIN };
	struct netmap_if *nifp;
	struct netmap_ring *rxring;
	int i;
	uint64_t n = (targ->g->npackets);
	uint64_t limit = n;
	struct my_ctrs cur;

	// Tolerate some loss in the receiver
	if ( pkt_loss_tolerance )
		limit = ceil(n * tolerance_amount);
	D("Pkt-gen will stop after receiving %ld packets", limit);

	///////////////////////////////////////////////////////////////////
	// Timestamping
	///////////////////////////////////////////////////////////////////
	if ( latency_calc ) {
		/*
		struct timespec ts, now, last_print;

		uint64_t count = 0, t_min = ~0, av = 0;
		uint64_t buckets[64];	// bins for delays, ns
		bzero(&buckets, sizeof(buckets));
		clock_gettime(CLOCK_REALTIME_PRECISE, &last_print);
		now = last_print;
		*/
	}
	///////////////////////////////////////////////////////////////////

	cur.pkts = cur.bytes = cur.events = 0;

	if (setaffinity(targ->thread, targ->affinity)) {
		goto quit;
	}

	D("Reading from %s fd %d main_fd %d", targ->g->ifname, targ->fd, targ->g->main_fd);

	/* unbounded wait for the first packet. */
	for ( ; !targ->cancel ; ) {
		i = poll(&pfd, 1, 1000);
		if (i > 0 && !(pfd.revents & POLLERR))
			break;
		RD(1, "waiting for initial packets, poll returns %d %d", i, pfd.revents);
	}

	// After receiving the first bytes, set an alarm to stop the receiver after
	// a minimum duration has elapsed (-m argument)
	if ( min_rx_duration ) {
		D("Setting alarm of %f seconds", min_rx_duration);
		alarm(min_rx_duration);
	}

	/* main loop, exit after 1s silence */
	clock_gettime(CLOCK_REALTIME_PRECISE, &targ->tic);
	if (targ->g->dev_type == DEV_TAP) {
		while ( !targ->cancel && (limit == 0 || cur.pkts < limit) && !stop_rx ) {
			char buf[MAX_BODYSIZE];

			/* XXX should we poll ? */
			i = read(targ->g->main_fd, buf, sizeof(buf));
			if (i > 0) {
				targ->ctr.pkts++;
				targ->ctr.bytes += i;
				targ->ctr.events++;
			}
		}
	}
	else if (targ->g->dev_type == DEV_PCAP) {
		while ( !targ->cancel && (limit == 0 || cur.pkts < limit) && !stop_rx ) {
			/* XXX should we poll ? */
			//pcap_dispatch(targ->g->p, targ->g->burst, receive_pcap, (u_char *)&targ->count);
			//// POSSIBLE BUG! The above calls is Netmap's contribution but doesn't compile.
			//// I modified this call as below, but haven't tested
			pcap_dispatch(targ->g->p, targ->g->burst, receive_pcap, (u_char *)&targ->ctr.bytes);
			//XXX-ste: targ->count_event++ for pcap
		}
	}
	else {
		int dump = targ->g->options & OPT_DUMP;

		nifp = targ->nmd->nifp;
		while ( !targ->cancel && (limit == 0 || cur.pkts < limit) && !stop_rx ) {
			/* Once we started to receive packets, wait at most 1 seconds
			   before quitting. */

		#ifdef BUSYWAIT
			if (ioctl(pfd.fd, NIOCRXSYNC, NULL) < 0) {
				D("IOCTL error on queue %d: %s", targ->me, strerror(errno));
				goto quit;
			}

		#else /* !BUSYWAIT */
			if (poll(&pfd, 1, 1 * 1000) <= 0 && !targ->g->forever) {
				clock_gettime(CLOCK_REALTIME_PRECISE, &targ->toc);
				targ->toc.tv_sec -= 1; /* Subtract timeout time. */
				goto out;
			}

			if (pfd.revents & POLLERR) {
				D("Poll error");
				goto quit;
			}
		#endif /* !BUSYWAIT */

			for (i = targ->nmd->first_rx_ring; i <= targ->nmd->last_rx_ring; i++) {
				int m;

				rxring = NETMAP_RXRING(nifp, i);
				if (nm_ring_empty(rxring))
					continue;

				m = receive_packets(rxring, targ->g->burst, dump, &cur.bytes);
				//m = receive_packets(rxring, targ->g->burst, dump, &cur.bytes, (uint64_t *)buckets, &now, &count, &t_min, &av);
				cur.pkts += m;
				if (m > 0)
					cur.events++;

				// Check if the limit is reached
				if ( (cur.pkts > limit) && (limit > 0) ) {
					D("Packet limit (parameter -n %ld) is reached", limit);
					break;
				}
			}
			targ->ctr = cur;

			///////////////////////////////// Calculate latency /////////////////////////////////
			if ( latency_calc ) {
				/*
				ts.tv_sec  = now.tv_sec  - last_print.tv_sec;
				ts.tv_nsec = now.tv_nsec - last_print.tv_nsec;
				if (ts.tv_nsec < 0) {
					ts.tv_nsec += 1000000000;
					ts.tv_sec--;
				}

				if (ts.tv_sec >= 1) {
					D("Count %d RTT: min %d av %d ns", (int)count, (int)t_min, (int)(av/count));

					int k, j, kmin;
					char buf[512];

					for (kmin = 0; kmin < 64; kmin ++) {
						if (buckets[kmin]) {
							break;
						}
					}

					for (k = 63; k >= kmin; k--) {
						if (buckets[k]) {
							break;
						}
					}

					buf[0] = '\0';
					for (j = kmin; j <= k; j++) {
						sprintf(buf, "%s %5d", buf, (int)buckets[j]);
					}

					D("K: %d .. %d\n\t%s", 1<<kmin, 1<<k, buf);
					bzero(&buckets, sizeof(buckets));
					count = 0;
					av = 0;
					t_min = ~0;
					last_print = now;
				}
				*/
			}
			/////////////////////////////////////////////////////////////////////////////////////
		}
	}

	clock_gettime(CLOCK_REALTIME_PRECISE, &targ->toc);

#if !defined(BUSYWAIT)
	out:
#endif
		targ->completed = 1;
		targ->ctr = cur;

	quit:
		/* reset the ``used`` flag. */
		targ->used = 0;

	return (NULL);
}

/*
`* Very crude code to print a number in normalized form.
 * Caller has to make sure that the buffer is large enough.
 */
static const char *
norm2(char *buf, double val, char *fmt) {
	char *units[] = { "", "K", "M", "G", "T" };
	u_int i;

	for (i = 0; val >=1000 && i < sizeof(units)/sizeof(char *) - 1; i++)
		val /= 1000;
	sprintf(buf, fmt, val, units[i]);
	return buf;
}

static const char *
norm(char *buf, double val) {
	return norm2(buf, val, "%.3f %s");
}

static void
tx_output(struct my_ctrs *cur, double delta, const char *msg) {
	double bw, raw_bw, pps, abs;
	char b1[40], b2[80], b3[80];
	int size;

	if (cur->pkts == 0) {
		printf("%s nothing.\n", msg);
		return;
	}

	size = (int)(cur->bytes / cur->pkts);

	printf("%s %llu packets %llu bytes %llu events %d bytes each in %.2f seconds.\n",
		msg,
		(unsigned long long)cur->pkts,
		(unsigned long long)cur->bytes,
		(unsigned long long)cur->events, size, delta);

	if (delta == 0)
		delta = 1e-6;

	pps = cur->pkts / delta;
	bw = (8.0 * cur->bytes) / delta;
	/* raw packets have4 bytes crc + 20 bytes framing */
	raw_bw = (8.0 * (cur->pkts * 24 + cur->bytes)) / delta;
	abs = cur->pkts / (double)(cur->events);

	printf("Speed: %spps Bandwidth: %sbps (raw %sbps). Average batch: %.2f pkts\n",
		norm(b1, pps), norm(b2, bw), norm(b3, raw_bw), abs);
}

static void
usage(void) {
	const char *cmd = "pkt-gen";
	fprintf(
		stderr,
		"Usage:\n"
		"%s arguments\n"
		"\t-i interface				Interface name\n"
		"\t-f function				Modes: tx rx ping pong\n"
		"\t-n count				Limits the number of packets to send/receive (Useful in both tx/rx mode. If 0 runs forever)\n"
		"\t-l pkt_size				In bytes excluding CRC\n"
		"\t-s src_ip[:port[-src_ip:port]]		The source IP address (single or range) of the generated packets\n"
		"\t-d dst_ip[:port[-dst_ip:port]]		The destination IP address (single or range) of the generated packets\n"
		"\t-S src-mac				The source Ethernet address of the generated packets\n"
		"\t-D dst-mac				The destination Ethernet address of the generated packets\n"
		"\t-a cpu_id				Use setaffinity to pin this process to a (set of) core(s)\n"
		"\t-b burst size				Testing, mostly\n"
		"\t-c cores				CPU cores to use\n"
		"\t-p threads				Number of processes/threads to use\n"
		"\t-T report_ms				Milliseconds between reports\n"
		"\t-w wait_for_link_time			In seconds\n"
		"\t-R rate					In packets per second\n"
		"\t-H len					Add empty virtio-net-header with size 'len'\n"
		"\t-E pipes				Allocate extra space for a number of pipes\n"
		"\t-P file					Replay packets from a pcap file\n"
		"\t-F frags				Number of fragments in [1,63] \n"
		"\t-m minimum Rx duration			After this time has elapsed, Rx is stopped. Set as pkts_sent/pkt_rate.\n"
		"\t-t pkt loss tolerance in (0,1)		Tolerate packet loss in the receiver (Stop it earlier). Combine with -n.\n"
		"\t-L					Calculate latency (Not ready yet..)\n"
		"\t-W					Do not exit Rx even with no traffic\n"
		"\t-o					Options [-I, -r, -X, -z, -Z, ...]\n"
		"\t-I					Indirect buffer option \n"
		"\t-r					Do not touch the buffers (send rubbish)\n"
		"\t-X					Dump payload\n"
		"\t-z					Use random IPv4 src address/port\n"
		"\t-Z					Use random IPv4 dst address/port\n"
		"\t-v					Verbose (Do not set if you want high performance)\n"
		"\t-V					More verbose (Do not set if you want high performance)\n"
		"\t-h					Help\n"
		"",
		cmd
	);

	exit(0);
}

static void
start_threads(struct glob_arg *g) {
	int i;

	targs = calloc(g->nthreads, sizeof(*targs));

	/*
	 * Now create the desired number of threads, each one
	 * using a single descriptor.
 	 */
	for (i = 0; i < g->nthreads; i++) {
		struct targ *t = &targs[i];

		bzero(t, sizeof(*t));
		t->fd = -1; /* default, with pcap */
		t->g = g;

		if (g->dev_type == DEV_NETMAP) {
			struct nm_desc nmd = *g->nmd; /* copy, we overwrite ringid */
			uint64_t nmd_flags = 0;
			nmd.self = &nmd;

			if (i > 0) {
				/* the first thread uses the fd opened by the main
				 * thread, the other threads re-open /dev/netmap
				 */
				if (g->nthreads > 1) {
					nmd.req.nr_flags = g->nmd->req.nr_flags & ~NR_REG_MASK;
					nmd.req.nr_flags |= NR_REG_ONE_NIC;
					nmd.req.nr_ringid = i;
				}

				/* Only touch one of the rings (rx is already ok) */
				if (g->td_body == receiver_body)
					nmd_flags |= NETMAP_NO_TX_POLL;

				/* register interface. Override ifname and ringid etc. */
				t->nmd = nm_open(t->g->ifname, NULL, nmd_flags | NM_OPEN_IFNAME | NM_OPEN_NO_MMAP, &nmd);

				if (t->nmd == NULL) {
					D("Unable to open %s: %s", t->g->ifname, strerror(errno));
					continue;
				}
			}
			else {
				t->nmd = g->nmd;
			}
			t->fd = t->nmd->fd;
			set_vnet_hdr_len(t);
		}
		else {
			targs[i].fd = g->main_fd;
		}

		t->used = 1;
		t->me = i;
		if (g->affinity >= 0) {
			t->affinity = (g->affinity + i) % g->system_cpus;
		}
		else {
			t->affinity = -1;
		}

		/* default, init packets */
		initialize_packet(t);

		if (pthread_create(&t->thread, NULL, g->td_body, t) == -1) {
			D("Unable to create thread %d: %s", i, strerror(errno));
			t->used = 0;
		}
	}
}

static void
main_thread(struct glob_arg* g) {
	int i;

	struct my_ctrs prev, cur;
	double delta_t;
	struct timeval tic, toc;

	prev.pkts = prev.bytes = prev.events = 0;
	gettimeofday(&prev.t, NULL);

	for (;;) {
		char b1[40], b2[40], b3[40];
		struct timeval delta;
		uint64_t pps, usec;
		struct my_ctrs x;
		double abs;
		int done = 0;

		delta.tv_sec = g->report_interval/1000;
		delta.tv_usec = (g->report_interval%1000)*1000;
		select(0, NULL, NULL, NULL, &delta);
		cur.pkts = cur.bytes = cur.events = 0;
		gettimeofday(&cur.t, NULL);
		timersub(&cur.t, &prev.t, &delta);
		usec = delta.tv_sec* 1000000 + delta.tv_usec;
		if (usec < 10000) /* too short to be meaningful */
			continue;

		/* accumulate counts for all threads */
		for (i = 0; i < g->nthreads; i++) {
			cur.pkts   += targs[i].ctr.pkts;
			cur.bytes  += targs[i].ctr.bytes;
			cur.events += targs[i].ctr.events;
			if (targs[i].used == 0)
				done++;
		}

		x.pkts   = cur.pkts   - prev.pkts;
		x.bytes  = cur.bytes  - prev.bytes;
		x.events = cur.events - prev.events;
		pps = (x.pkts*1000000 + usec/2) / usec;
		abs = (x.events > 0) ? (x.pkts / (double) x.events) : 0;

		D("%spps (%spkts %sbps in %llu usec) %.2f avg_batch",
			norm(b1, pps),
			norm(b2, (double)x.pkts),
			norm(b3, (double)x.bytes*8),
			(unsigned long long)usec,
			abs);

		prev = cur;
		if (done == g->nthreads)
			break;
	}

	timerclear(&tic);
	timerclear(&toc);
	cur.pkts = cur.bytes = cur.events = 0;

	/* final round */
	for (i = 0; i < g->nthreads; i++) {
		struct timespec t_tic, t_toc;
		/*
		 * Join active threads, unregister interfaces and close
		 * file descriptors.
		 */
		if (targs[i].used)
			pthread_join(targs[i].thread, NULL); /* blocking */

		close(targs[i].fd);

		if (targs[i].completed == 0)
			D("Ouch, thread %d exited with error", i);

		/*
		 * Collect threads output and extract information about
		 * how long it took to send all the packets.
		 */
		cur.pkts   += targs[i].ctr.pkts;
		cur.bytes  += targs[i].ctr.bytes;
		cur.events += targs[i].ctr.events;
		/*
		 * Collect the largest start (tic) and end (toc) times,
		 * XXX maybe we should do the earliest tic, or do a weighted
		 * average ?
		 */
		t_tic = timeval2spec(&tic);
		t_toc = timeval2spec(&toc);
		if (!timerisset(&tic) || timespec_ge(&targs[i].tic, &t_tic))
			tic = timespec2val(&targs[i].tic);
		if (!timerisset(&toc) || timespec_ge(&targs[i].toc, &t_toc))
			toc = timespec2val(&targs[i].toc);
	}

	/* Print output. */
	timersub(&toc, &tic, &toc);
	delta_t = toc.tv_sec + 1e-6* toc.tv_usec;
	if (g->td_body == sender_body)
		tx_output(&cur, delta_t, "Sent");
	else
		tx_output(&cur, delta_t, "Received");

	if (g->dev_type == DEV_NETMAP) {
		munmap(g->nmd->mem, g->nmd->req.nr_memsize);
		close(g->main_fd);
	}
}


struct sf {
	char *key;
	void *f;
};

static struct sf func[] = {
	{ "tx",	sender_body },
	{ "rx",	receiver_body },
	{ "ping",	pinger_body },
	{ "pong",	ponger_body },
	{ NULL, NULL }
};

static int
tap_alloc(char *dev) {
	struct ifreq ifr;
	int fd, err = 0;
	char *clonedev = TAP_CLONEDEV;

	(void)err;
	(void)dev;
	/* Arguments taken by the function:
	 *
	 * char *dev: the name of an interface (or '\0'). MUST have enough
	 *   space to hold the interface name if '\0' is passed
	 * int flags: interface flags (eg, IFF_TUN etc.)
	 */

#ifdef __FreeBSD__
	if (dev[3]) { /* tapSomething */
		static char buf[128];
		snprintf(buf, sizeof(buf), "/dev/%s", dev);
		clonedev = buf;
	}
#endif

	/* open the device */
	if( (fd = open(clonedev, O_RDWR)) < 0 ) {
		return fd;
	}
	D("%s open successful", clonedev);

	/* preparation of the struct ifr, of type "struct ifreq" */
	memset(&ifr, 0, sizeof(ifr));

#ifdef linux
	ifr.ifr_flags = IFF_TAP | IFF_NO_PI;

	if (*dev) {
		/* if a device name was specified, put it in the structure; otherwise,
		* the kernel will try to allocate the "next" device of the
		* specified type */
		strncpy(ifr.ifr_name, dev, IFNAMSIZ);
	}

	/* try to create the device */
	if( (err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0 ) {
		D("Failed to to a TUNSETIFF: %s", strerror(errno));
		close(fd);
		return err;
	}

	/* if the operation was successful, write back the name of the
	* interface to the variable "dev", so the caller can know
	* it. Note that the caller MUST reserve space in *dev (see calling
	* code below) */
	strcpy(dev, ifr.ifr_name);
	D("New name is %s", dev);
#endif /* linux */

	/* this is the special file descriptor that the caller will use to talk
	 * with the virtual interface */
	return fd;
}

/*
 * Print error message in case of incomplete parsing of a packet
 */
static void
incomplete_packet(const char* truncated_hdr) {
	D("Packet is truncated and lacks a full %s", truncated_hdr);
}

/*
 * Check whether the loaded packet is a valid (for us) packet.
 * Valid packets are IP, ICMP, UDP, TCP packets.
 */
int
parse_packet(u_char **packet, const char *src_mac, const char *dst_mac, unsigned int capture_len) {
	struct ip    *ip_hdr    = NULL;
	unsigned int ip_hdr_len = 0;

	// We didn't even capture a full Ethernet header, so we
	// can't analyze this any further.
	if ( capture_len < sizeof(struct ether_header) ) {
		if ( verbose ) {
			incomplete_packet("Ethernet header");
		}
		return FAILURE;
	}

	// Skip over the Ethernet header.
	*packet     += sizeof(struct ether_header);
	capture_len -= sizeof(struct ether_header);

	// Didn't capture a full IP header
	if ( capture_len < sizeof(struct ip) ) {
		if ( verbose )
			incomplete_packet("IP header");
		return FAILURE;
	}

	ip_hdr = (struct ip*)(*packet);
	ip_hdr_len = ip_hdr->ip_hl * 4;

	// Didn't capture the full IP header including options
	if ( capture_len < ip_hdr_len ) {
		if ( verbose )
			incomplete_packet("IP header with options");
		return FAILURE;
	}

	if ( ip_hdr_len < MIN_IP_HEADER_SIZE ) {
		if ( verbose )
			incomplete_packet("IP header");
		return FAILURE;
	}

	// FIXME: TCP Packets cause problems in stateful NFs
	if ( ip_hdr->ip_p == IPPROTO_TCP ) {
		return FAILURE;
	}

	// We keep only IP packets that may contain ICMP/UDP/TCP headers.
	if ( 	(ip_hdr->ip_p != IPPROTO_IP)  && (ip_hdr->ip_p != IPPROTO_UDP) &&
		(ip_hdr->ip_p != IPPROTO_TCP) && (ip_hdr->ip_p != IPPROTO_ICMP) ) {
		//D("Non-IP/ICMP/UDP/TCP packet");
		return FAILURE;
	}

	// Bring the pointer back, otherwise your alignment is destroyed
	*packet -= sizeof(struct ether_header);

	// Fit the MAC addresses to our network settings
	struct ether_header* eth_hdr;
	eth_hdr = (struct ether_header*) (*packet);
	bcopy(ether_aton(src_mac), &eth_hdr->ether_shost, 6);
	bcopy(ether_aton(dst_mac), &eth_hdr->ether_dhost, 6);
	// Alternatives for MAC assignment
	//memset(eth_hdr->ether_shost, 0x00, sizeof(eth_hdr->ether_shost));
	//memset(eth_hdr->ether_dhost, 0xff, sizeof(eth_hdr->ether_dhost));
	eth_hdr->ether_type = htons(ETHERTYPE_IP);

	// Debug: Print packets
	/*
	if      ( ip_hdr->ip_p == IPPROTO_IP   )
		print_ip_header(*packet);
	else if ( ip_hdr->ip_p == IPPROTO_ICMP )
		print_icmp_header(*packet);
	else if ( ip_hdr->ip_p == IPPROTO_UDP  )
		print_udp_header(*packet);
	else if ( ip_hdr->ip_p == IPPROTO_TCP  )
		print_tcp_header(*packet);
	*/

	return SUCCESS;
}

static int
load_pcap_to_memory(const char *input_trace, const char *src_mac, const char *dst_mac,
					vector_size_t max_packets_to_allocate, int pkt_size, 
					huge_vector *pkt_container, vector_size_t *loaded_pkts_no
					) {

	// Create an array to hold pcap errors
	char errbuff[PCAP_ERRBUF_SIZE];
	memset(errbuff, 0, sizeof(errbuff));

	// Open the file and store result in pointer to pcap_t
	pcap_t *pcap = pcap_open_offline(input_trace, errbuff);
	if ( pcap == NULL ) {
		D("Error while opening trace %s: %s \n", input_trace, errbuff);
		return FAILURE;
	}

	// Create a header and a packet object
	struct pcap_pkthdr  *header;
	u_char*             packet;

	// Loop through packets and print them to screen
	vector_size_t packet_count = 0;
	while ( pcap_next_ex(pcap, &header, (const u_char**)&packet) >= 0 )
	{
		//D("Packet #%lu", packet_count);
		//D("Packet size: %d bytes\n", header->len);

		// Show a warning if the length captured is different
		if (header->len > header->caplen) {
			//D("Packet header %d bytes exceeds capture length: %d bytes\n", header->len, header->caplen);
		}

		// We do a simple parsing to keep only relevant packets (IP)
		if ( parse_packet(&packet, src_mac, dst_mac, header->caplen) != SUCCESS )
			continue;

		// Check if we still have buffers to host this new packet
		if ( packet_count < max_packets_to_allocate ) {
			// And if its header does not exceed the maximum packet size
			if ( header->len > MAX_PKT_SIZE ) {
				D("Packet header %d bytes exceeds maximum: %d bytes\n", header->len, MAX_PKT_SIZE);
				return FAILURE;
			}

			// 3rd argument can also be header->len if you want variable packet sizes
			if ( huge_vector_add(pkt_container, (void*)packet, pkt_size) != SUCCESS )
				return FAILURE;
		}
		else
			break;

		++packet_count;
	}

	// Close the pcap file
	pcap_close(pcap);

	// Keep the packet counter as well
	if ( packet_count <= 0 )
		return FAILURE;

	*loaded_pkts_no = packet_count;

	return SUCCESS;
}

size_t
get_total_system_memory()
{
    long pages     = sysconf(_SC_PHYS_PAGES);
    long page_size = sysconf(_SC_PAGE_SIZE);
    return pages * page_size;
}

int
start_trace_mode(struct glob_arg *g) {

	int pkt_size = g->pkt_size;
	vector_size_t pkts_to_allocate = 0;

	// File exists
	if( access( g->packet_file, F_OK ) != -1 ) {
		// Trick to avoid wasteful pre-allocation:
		// |-> If user specifies -n <number of pkts>, we allocate
		// |-> exactly that space. Otherwise, MAX_PACKETS_TO_READ is
		// |-> defined above.

		size_t  system_memory   = get_total_system_memory();
		int32_t packet_capacity = system_memory / pkt_size;
		float memory_share_for_pktgen = 0.6;
		int32_t avail_packet_capacity = packet_capacity * memory_share_for_pktgen;
		D("Total system memory: %ldGB", system_memory / GB);
		D("In memory packet (MTU %d) capacity: %d packets", pkt_size, packet_capacity);
		D("Available packet (MTU %d) capacity: %d packets (%.2f%%)",
			pkt_size, avail_packet_capacity, memory_share_for_pktgen*100);

		// We can afford the memory asked by the user
		if ( (g->npackets > 0) && (g->npackets <= avail_packet_capacity) )
			pkts_to_allocate = g->npackets;
		// We should limit user's requirements to the available memory of the system
		else if (g->npackets > avail_packet_capacity)
			pkts_to_allocate = g->npackets = avail_packet_capacity;
		// Allocate the available memory and work infinitely
		else
			pkts_to_allocate = avail_packet_capacity;

		D("To allocate: %ld packets (%.2fGB)", pkts_to_allocate, (system_memory / GB)*memory_share_for_pktgen);

		// In this mode we use this option
		g->options |= OPT_COPY;
		//g->options |= OPT_MEMCPY;

		// Allocate the vector to host the packets
		if ( huge_vector_init(&pt.loaded_pkts, pkts_to_allocate, pkt_size) != SUCCESS )
			return FAILURE;
		D("Allocated space for %lu packets of size %d bytes each",
			(unsigned long)pkts_to_allocate, pkt_size);
		pt.loaded_pkts_no = 0;

		// Load packets here because it takes time if the trace is big!!!
		if ( load_pcap_to_memory(g->packet_file, g->src_mac.name, g->dst_mac.name,
								pkts_to_allocate, pkt_size, &pt.loaded_pkts,
								&pt.loaded_pkts_no) != SUCCESS ) {
			huge_vector_free(&pt.loaded_pkts);
			return FAILURE;
		}
		D("Number of packets read from trace: %lu\n", (unsigned long)pt.loaded_pkts_no);
	}
	// File doesn't exist
	else {
		D("Option -P: PCAP trace %s does not exist\n", g->packet_file);
		return FAILURE;
	}

	return SUCCESS;
}

int
stop_trace_mode(void) {
	int32_t released_gb = (
		(unsigned long) huge_vector_entries_no(pt.loaded_pkts) * huge_vector_entry_size(pt.loaded_pkts) * sizeof(u_char) )
		/ GB;

	huge_vector_free(&pt.loaded_pkts);
	D("Successfully released %dGB of memory", released_gb);

	return FAILURE;
}

int
main(int arc, char **argv) {

	struct glob_arg g;

	int i, ch;
	int devqueues = 1;                             /* how many device queues */
	int wait_link = 2;

	bzero(&g, sizeof(g));

	g.main_fd          = -1;
	g.td_body          = receiver_body;
	g.report_interval  = 1000;	                          /* report interval */
	g.affinity         = -1;
	g.src_ip.name      = "10.0.0.1";
	g.dst_ip.name      = "10.1.0.1";     /* IP addresses can also be a range */
	g.dst_mac.name     = "ff:ff:ff:ff:ff:ff";
	g.src_mac.name     = NULL;
	g.pkt_size         = 60;
	g.burst            = 512;	                                  /* default */
	g.nthreads         = 1;
	g.cpus             = 1;                                       /* default */
	g.forever          = 1;
	g.tx_rate          = 0;
	g.frags            = 1;
	g.nmr_config       = "";
	g.virt_header      = 0;
	g.npackets         = 0;
	read_from_pcap     = FALSE;
	latency_calc       = FALSE;
	pkt_loss_tolerance = FALSE;
	tolerance_amount   = 0.0;
	min_rx_duration    = 0.0;
	stop_rx            = FALSE;
	is_killed          = FALSE;

	while ( (ch = getopt(arc, argv,
		"a:f:F:n:i:R:l:d:s:D:S:b:c:o:p:T:w:H:e:E:P:t:m:LIXWVvhzZr")) != -1) {

		struct sf *fn;

		switch(ch) {
			default:
				D("Bad option %c %s", ch, optarg);
				usage();
				break;

			case 'n':
				g.npackets = atoi(optarg);
				break;

			case 'F':
				i = atoi(optarg);
				if (i < 1 || i > 63) {
					D("Invalid frags %d [1..63], ignore", i);
					break;
				}
				g.frags = i;
				break;

			case 'f':
				for (fn = func; fn->key; fn++) {
					if (!strcmp(fn->key, optarg)) {
						break;
					}
				}

				if (fn->key)
					g.td_body = fn->f;
				else
					D("Unrecognised function %s", optarg);
				break;

			case 'o':	                   /* data generation options */
				g.options = atoi(optarg);
				break;

			case 'a':                                   /* force affinity */
				g.affinity = atoi(optarg);
				break;

			case 'i':	                                 /* interface */
				/*
				 * A prefix of tap: netmap: or pcap: forces the mode.
				 * otherwise we guess
				 */

				D("Interface is %s", optarg);
				if (strlen(optarg) > MAX_IFNAMELEN - 8) {
					D("Ifname too long %s", optarg);
					break;
				}

				strcpy(g.ifname, optarg);
				if (!strcmp(optarg, "null")) {
					g.dev_type = DEV_NETMAP;
					g.dummy_send = 1;
				}
				else if (!strncmp(optarg, "tap:", 4)) {
					g.dev_type = DEV_TAP;
					strcpy(g.ifname, optarg + 4);
				}
				else if (!strncmp(optarg, "pcap:", 5)) {
					g.dev_type = DEV_PCAP;
					strcpy(g.ifname, optarg + 5);
				}
				else if (!strncmp(optarg, "netmap:", 7) ||
					   !strncmp(optarg, "vale", 4)) {
					g.dev_type = DEV_NETMAP;
				}
				else if (!strncmp(optarg, "tap", 3)) {
					g.dev_type = DEV_TAP;
				}
				else {                             /* prepend netmap: */
					g.dev_type = DEV_NETMAP;
					sprintf(g.ifname, "netmap:%s", optarg);
				}
				break;

			case 'I':
				g.options |= OPT_INDIRECT; /* XXX use indirect buffer */
				break;

			case 'l':	                                  /* pkt_size */
				g.pkt_size = atoi(optarg);
				break;

			case 'L':	                         /* calculate latency */
				latency_calc = TRUE;
				break;

			case 't':	             /* tolerate loss in the receiver */
				tolerance_amount = atof(optarg);
				if ( (tolerance_amount > 0) && (tolerance_amount < 1) ) {
					pkt_loss_tolerance = TRUE;
					D("Pkt loss tolerance: %f ", tolerance_amount);
				}
				else {
					D("Packet loss tolerance must be in (0,1)");
					usage();
				}
				break;

			case 'm':
				min_rx_duration = atof(optarg);
				if ( min_rx_duration <= 0 ) {
					D("Minimum Rx duration must be positive (pkts_sent/pkt_rate)");
					usage();
				}
				// Catch a SIGALRM on_alarm function
				signal(SIGALRM, on_alarm);

				break;

			case 'd':
				g.dst_ip.name = optarg;
				break;

			case 's':
				g.src_ip.name = optarg;
				break;

			case 'T':	                           /* report interval */
				g.report_interval = atoi(optarg);
				break;

			case 'w':
				wait_link = atoi(optarg);
				break;

			case 'W':                          /* XXX changed default */
				g.forever = FALSE;       /* Stay even with no traffic */
				break;

			case 'b':	                                     /* burst */
				g.burst = atoi(optarg);
				break;

			case 'c':
				g.cpus = atoi(optarg);
				break;

			case 'p':
				g.nthreads = atoi(optarg);
				break;

			case 'D':                                  /* destination mac */
				g.dst_mac.name = optarg;
				break;

			case 'S':                                       /* source mac */
				g.src_mac.name = optarg;
				break;

			case 'v':
				verbose++;
				break;

			case 'V':
				full_verbose++;
				break;

			case 'R':
				g.tx_rate = atoi(optarg);
				break;

			case 'X':
				g.options |= OPT_DUMP;
				break;

			case 'C':
				g.nmr_config = strdup(optarg);
				break;

			case 'H':
				g.virt_header = atoi(optarg);
				break;

			case 'e':                                   /* extra bufs */
				g.extra_bufs = atoi(optarg);
				break;

			case 'E':
				g.extra_pipes = atoi(optarg);
				break;

			case 'P':
				g.packet_file = strdup(optarg);

				// Flag to enter in 'trace generation' mode
				read_from_pcap = TRUE;

				break;

			//case 'm':                                      /* ignored */
			//	break;
			case 'r':
				g.options |= OPT_RUBBISH;
				break;

			case 'z':
				g.options |= OPT_RANDOM_SRC;
				break;

			case 'Z':
				g.options |= OPT_RANDOM_DST;
				break;

			case 'h':
				usage();
				break;
		}
	}

	if (strlen(g.ifname) <=0 ) {
		D("Missing ifname");
		usage();
	}

	g.system_cpus = i = system_ncpus();
	if (g.cpus < 0 || g.cpus > i) {
		D("%d cpus is too high, have only %d cpus", g.cpus, i);
		usage();
	}

	D("Running on %d cpus (have %d)", g.cpus, i);
	if (g.cpus == 0)
		g.cpus = i;

	if (g.pkt_size < 16 || g.pkt_size > MAX_PKTSIZE) {
		D("Bad pktsize %d [16..%d]\n", g.pkt_size, MAX_PKTSIZE);
		usage();
	}

	if (g.src_mac.name == NULL) {
		static char mybuf[20] = "00:00:00:00:00:00";
		/* retrieve source mac address. */
		if (source_hwaddr(g.ifname, mybuf) == -1) {
			D("Unable to retrieve source mac");
			// continue, fail later
		}
		g.src_mac.name = mybuf;
	}

	/* extract address ranges */
	extract_ip_range(&g.src_ip);
	extract_ip_range(&g.dst_ip);
	extract_mac_range(&g.src_mac);
	extract_mac_range(&g.dst_mac);

	if ( (g.src_ip.start != g.src_ip.end ||
	g.src_ip.port0 != g.src_ip.port1 ||
	g.dst_ip.start != g.dst_ip.end ||
	g.dst_ip.port0 != g.dst_ip.port1) &&
	!read_from_pcap )
		g.options |= OPT_COPY;

	/*
	 * Trace mode on: -P argument is given
	 */
	if ( read_from_pcap && (g.packet_file != NULL) ) {
		if ( start_trace_mode(&g) != SUCCESS ) {
			usage();
		}
	}

	if (g.virt_header != 0 && g.virt_header != VIRT_HDR_1
		&& g.virt_header != VIRT_HDR_2) {
		D("Bad virtio-net-header length");
		usage();
	}

	if (g.dev_type == DEV_TAP) {
		D("Want to use tap %s", g.ifname);
		g.main_fd = tap_alloc(g.ifname);
		if (g.main_fd < 0) {
			D("Cannot open tap %s", g.ifname);
			usage();
		}
	}
	else if (g.dev_type == DEV_PCAP) {
		char pcap_errbuf[PCAP_ERRBUF_SIZE];

		pcap_errbuf[0] = '\0'; // init the buffer
		g.p = pcap_open_live(g.ifname, 256 /* XXX */, 1, 100, pcap_errbuf);
		if (g.p == NULL) {
			D("Cannot open pcap on %s", g.ifname);
			usage();
		}
		g.main_fd = pcap_fileno(g.p);
		D("Using pcap on %s fileno %d", g.ifname, g.main_fd);
	}
	else if (g.dummy_send) { /* but DEV_NETMAP */
		D("Using a dummy send routine");
	}
	else {
		struct nmreq base_nmd;

		bzero(&base_nmd, sizeof(base_nmd));

		parse_nmr_config(g.nmr_config, &base_nmd);
		if (g.extra_bufs) {
			base_nmd.nr_arg3 = g.extra_bufs;
		}

		if (g.extra_pipes) {
			base_nmd.nr_arg1 = g.extra_pipes;
		}

		/*
		 * Open the netmap device using nm_open().
		 *
		 * protocol stack and may cause a reset of the card,
		 * which in turn may take some time for the PHY to
		 * reconfigure. We do the open here to have time to reset.
		 */
		g.nmd = nm_open(g.ifname, &base_nmd, 0, NULL);
		if (g.nmd == NULL) {
			D("Unable to open %s: %s", g.ifname, strerror(errno));
			goto out;
		}

		if (g.nthreads > 1) {
			struct nm_desc saved_desc = *g.nmd;
			saved_desc.self = &saved_desc;
			saved_desc.mem = NULL;
			nm_close(g.nmd);
			saved_desc.req.nr_flags &= ~NR_REG_MASK;
			saved_desc.req.nr_flags |= NR_REG_ONE_NIC;
			saved_desc.req.nr_ringid = 0;
			g.nmd = nm_open(g.ifname, &base_nmd, NM_OPEN_IFNAME, &saved_desc);
			if (g.nmd == NULL) {
				D("Unable to open %s: %s", g.ifname, strerror(errno));
				goto out;
			}
		}

		g.main_fd = g.nmd->fd;
		D("Mapped %dKB at %p", g.nmd->req.nr_memsize>>10, g.nmd->mem);

		/* get num of queues in tx or rx */
		if (g.td_body == sender_body)
			devqueues = g.nmd->req.nr_tx_rings;
		else
			devqueues = g.nmd->req.nr_rx_rings;

		/* validate provided nthreads. */
		if (g.nthreads < 1 || g.nthreads > devqueues) {
			D("Bad nthreads %d, have %d queues", g.nthreads, devqueues);
			// continue, fail later
		}

		if ( verbose ) {
			struct netmap_if *nifp = g.nmd->nifp;
			struct nmreq *req = &g.nmd->req;

			D("Nifp at offset %d, %d tx %d rx region %d",
				req->nr_offset, req->nr_tx_rings, req->nr_rx_rings, req->nr_arg2);

			// Tx Rings
			for (i = 0; i <= req->nr_tx_rings; i++) {
				struct netmap_ring *ring = NETMAP_TXRING(nifp, i);
				D("   TX%d at 0x%lx slots %d", i, (char *)ring - (char *)nifp, ring->num_slots);
			}

			// Rx Rings
			for (i = 0; i <= req->nr_rx_rings; i++) {
				struct netmap_ring *ring = NETMAP_RXRING(nifp, i);
				D("   RX%d at 0x%p slots %d", i, (void *)((char *)ring - (char *)nifp), ring->num_slots);
			}
		}

		/* Print some debug information. */
		fprintf(
			stdout,
			"%s %s: %d queues, %d threads and %d cpus.\n",
			(g.td_body == sender_body) ? "Sending on" : "Receiving from",
			g.ifname,
			devqueues,
			g.nthreads,
			g.cpus
		);

		if (g.td_body == sender_body) {
			fprintf(stdout, "%s -> %s (%s -> %s)\n",
					g.src_ip.name, g.dst_ip.name,
					g.src_mac.name, g.dst_mac.name);
		}

		out:
			/* Exit if something went wrong. */
			if (g.main_fd < 0) {
				D("aborting");
				usage();
			}
	}

	if (g.options) {
		D("--- SPECIAL OPTIONS:%s%s%s%s%s%s",
			g.options & OPT_PREFETCH ? " prefetch" : "",
			g.options & OPT_ACCESS ? " access" : "",
			g.options & OPT_MEMCPY ? " memcpy" : "",
			g.options & OPT_INDIRECT ? " indirect" : "",
			g.options & OPT_COPY ? " copy" : "",
			g.options & OPT_RUBBISH ? " rubbish " : ""
		);
	}

	g.tx_period.tv_sec = g.tx_period.tv_nsec = 0;
	if (g.tx_rate > 0) {
		/* try to have at least something every second,
		 * reducing the burst size to some 0.01s worth of data
		 * (but no less than one full set of fragments)
	 	 */
		uint64_t x;
		int lim = (g.tx_rate)/300;
		if (g.burst > lim)
			g.burst = lim;

		if (g.burst < g.frags)
			g.burst = g.frags;

		x = ((uint64_t)1000000000 * (uint64_t)g.burst) / (uint64_t) g.tx_rate;
		g.tx_period.tv_nsec = x;
		g.tx_period.tv_sec = g.tx_period.tv_nsec / 1000000000;
		g.tx_period.tv_nsec = g.tx_period.tv_nsec % 1000000000;
	}

	if (g.td_body == sender_body)
	    D("Sending %d packets every  %ld.%09ld s", g.burst, g.tx_period.tv_sec, g.tx_period.tv_nsec);

	/* Wait for PHY reset. */
	D("Wait %d secs for phy reset", wait_link);
	sleep(wait_link);
	D("Ready...");

	/* Install ^C handler. */
	global_nthreads = g.nthreads;
	signal(SIGINT, sigint_h);

	start_threads(&g);
	main_thread(&g);

	// Release memory if not killed
	if ( read_from_pcap && !is_killed ) {
		stop_trace_mode();
	}

	return SUCCESS;
}

/* end of file */
