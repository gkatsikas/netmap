/*
 * Copyright (C) 2015 Georgios Katsikas - KTH Royal Institute of Technology. All rights reserved.
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
 * $Id: packet.c
 *
 * An implementation of pretty IP/ICMP/UDP/TCP header printouts.
 * Used by pkt-gen for debugging purposes.
 *
 */

#include <stdio.h>

#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <net/ethernet.h>
#include <netinet/ip_icmp.h>

#include "packet.h"

/*
 * Print L2 frame header
 */
void print_ethernet_header(const unsigned char* frame)
{
	if ( frame == NULL ) {
		fprintf(stderr, "No frame to be printed\n");
		return;
	}

	struct ether_header* eth_hdr = (struct ether_header*) frame;

	fprintf(stdout, "\n");
	fprintf(stdout, "Ethernet Header \n");
	fprintf(stdout, "   |-       Source Address: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n",
				eth_hdr->ether_shost[0], eth_hdr->ether_shost[1], eth_hdr->ether_shost[2],
				eth_hdr->ether_shost[3], eth_hdr->ether_shost[4], eth_hdr->ether_shost[5]);
	fprintf(stdout, "   |-  Destination Address: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n",
				eth_hdr->ether_dhost[0], eth_hdr->ether_dhost[1], eth_hdr->ether_dhost[2],
				eth_hdr->ether_dhost[3], eth_hdr->ether_dhost[4], eth_hdr->ether_dhost[5]);
	if ( ntohs(eth_hdr->ether_type) == ETHERTYPE_IP )
		fprintf(stdout, "   |-        Ethernet Type: IP \n");
	else if ( ntohs(eth_hdr->ether_type) == ETHERTYPE_ARP )
		fprintf(stdout, "   |-        Ethernet Type: ARP \n");
	else
		fprintf(stdout, "   |-        Ethernet Type: %x \n", ntohs(eth_hdr->ether_type));
}

/*
 * Print L3 packet header
 */
void print_ip_header(const unsigned char* frame)
{
	if ( frame == NULL ) {
		fprintf(stderr, "No frame to be printed\n");
		return;
	}

	print_ethernet_header(frame);

	struct ip* ip_hdr = (struct ip*) (frame + sizeof(struct ether_header));

	fprintf(stdout, "IP Header\n");
	fprintf(stdout, "   |-           IP Version: %d       \n",	(unsigned int) ip_hdr->ip_v);
	fprintf(stdout, "   |-     IP Header Length: %d bytes \n",	(unsigned int)ip_hdr->ip_hl*4);
	fprintf(stdout, "   |-      Type Of Service: %d       \n",	(unsigned int)ip_hdr->ip_tos);
	fprintf(stdout, "   |-      IP Total Length: %u bytes \n",	ntohs(ip_hdr->ip_len));
	fprintf(stdout, "   |-       Identification: %u       \n",	ntohs(ip_hdr->ip_id));
	fprintf(stdout, "   |-  Reserved ZERO Field: %d       \n",	(unsigned int)ip_hdr->ip_off);
	fprintf(stdout, "   |-  Dont Fragment Field: %d       \n",	(unsigned int)ip_hdr->ip_off | IP_DF);
	fprintf(stdout, "   |-  More Fragment Field: %d       \n",	(unsigned int)ip_hdr->ip_off | IP_MF);
	fprintf(stdout, "   |-                  TTL: %d       \n",	(unsigned int)ip_hdr->ip_ttl);
	fprintf(stdout, "   |-             Protocol: %d       \n",	ip_hdr->ip_p);
	fprintf(stdout, "   |-             Checksum: %d       \n",	ntohs(ip_hdr->ip_sum));
	fprintf(stdout, "   |-            Source IP: %s       \n",	inet_ntoa(ip_hdr->ip_src));
	fprintf(stdout, "   |-       Destination IP: %s       \n",	inet_ntoa(ip_hdr->ip_dst));
}

/*
 * Print TCP/IP/Eth header
 */
void print_tcp_header(const unsigned char* frame)
{
	if ( frame == NULL ) {
		fprintf(stderr, "No frame to be printed\n");
		return;
	}

	unsigned short ip_hdr_len;

	struct ip *ip_hdr = (struct ip*) (frame + sizeof(struct ether_header));
	ip_hdr_len = ip_hdr->ip_hl * 4;

	struct tcphdr* tcp_hdr = (struct tcphdr*) (frame + sizeof(struct ether_header) + ip_hdr_len);

	print_ip_header(frame);

	fprintf(stdout, "TCP Header \n");
	fprintf(stdout, "   |-          Source Port: %u\n",        ntohs(tcp_hdr->source));
	fprintf(stdout, "   |-     Destination Port: %u\n",        ntohs(tcp_hdr->dest));
	fprintf(stdout, "   |-      Sequence Number: %u\n",        ntohl(tcp_hdr->seq));
	fprintf(stdout, "   |-   Acknowledge Number: %u\n",        ntohl(tcp_hdr->ack_seq));
	fprintf(stdout, "   |-        Header Length: %d bytes \n", (unsigned int)tcp_hdr->doff*4);
	fprintf(stdout, "   |-          Urgent Flag: %d\n",        (unsigned int)tcp_hdr->urg);
	fprintf(stdout, "   |- Acknowledgement Flag: %d\n",        (unsigned int)tcp_hdr->ack);
	fprintf(stdout, "   |-            Push Flag: %d\n",        (unsigned int)tcp_hdr->psh);
	fprintf(stdout, "   |-           Reset Flag: %d\n",        (unsigned int)tcp_hdr->rst);
	fprintf(stdout, "   |-     Synchronize Flag: %d\n",        (unsigned int)tcp_hdr->syn);
	fprintf(stdout, "   |-          Finish Flag: %d\n",        (unsigned int)tcp_hdr->fin);
	fprintf(stdout, "   |-               Window: %d\n",        ntohs(tcp_hdr->window));
	fprintf(stdout, "   |-             Checksum: %d\n",        ntohs(tcp_hdr->check));
	fprintf(stdout, "   |-       Urgent Pointer: %d\n",        tcp_hdr->urg_ptr);
	fprintf(stdout, "Payload \n");
	fprintf(stdout, "   |-         Payload size: %ld\n",       ntohs(ip_hdr->ip_len) - ip_hdr_len - sizeof(struct tcphdr));
}

/*
 * Print UDP header
 */
void print_udp_header(const unsigned char* frame)
{
	if ( frame == NULL ) {
		fprintf(stderr, "No frame to be printed\n");
		return;
	}

	unsigned short ip_hdr_len;

	struct ip* ip_hdr = (struct ip*) (frame + sizeof(struct ether_header));
	ip_hdr_len = ip_hdr->ip_hl * 4;

	struct udphdr* udp_hdr = (struct udphdr*) (frame + sizeof(struct ether_header) + ip_hdr_len);

	print_ip_header(frame);

	fprintf(stdout, "UDP Header\n");
	fprintf(stdout, "   |-          Source Port: %d \n", ntohs(udp_hdr->source));
	fprintf(stdout, "   |-     Destination Port: %d \n", ntohs(udp_hdr->dest));
	fprintf(stdout, "   |-           UDP Length: %d \n", ntohs(udp_hdr->len));
	fprintf(stdout, "   |-         UDP Checksum: %d \n", ntohs(udp_hdr->check));
	fprintf(stdout, "Payload \n");
	fprintf(stdout, "   |-         Payload size: %ld\n", ntohs(ip_hdr->ip_len) - (unsigned short)ip_hdr_len - sizeof(struct udphdr));
}

/*
 * Print ICMP header
 */
void print_icmp_header(const unsigned char* frame)
{
	if ( frame == NULL ) {
		fprintf(stderr, "No frame to be printed\n");
		return;
	}

	unsigned short ip_hdr_len;

	struct ip* ip_hdr = (struct ip*) (frame + sizeof(struct ether_header));
	ip_hdr_len = ip_hdr->ip_hl * 4;

	struct icmphdr* icmp_hdr = (struct icmphdr*) (frame + sizeof(struct ether_header) + ip_hdr_len);

	print_ip_header(frame);

	fprintf(stdout, "\n");
	fprintf(stdout, "ICMP Header             \n");
	fprintf(stdout, "   |-                 Type: %d", (unsigned int)(icmp_hdr->type));

	if ( (unsigned int)(icmp_hdr->type) == EXPIRED_TTL )
		fprintf(stdout, "  (TTL Expired)     \n");
	else if ( (unsigned int)(icmp_hdr->type) == ICMP_ECHOREPLY)
		fprintf(stdout, "  (ICMP Echo Reply) \n");
	else
		fprintf(stdout, "\n");

	fprintf(stdout, "   |-                 Code: %d  \n", (unsigned int)(icmp_hdr->code));
	fprintf(stdout, "   |-             Checksum: %d  \n", ntohs(icmp_hdr->checksum));
	fprintf(stdout, "Payload \n");
	fprintf(stdout, "   |-         Payload size: %ld \n", ntohs(ip_hdr->ip_len) - (unsigned short)ip_hdr_len - sizeof(struct icmphdr));
}
