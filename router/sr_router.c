/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

#define OP_ARP_REQUEST 1
#define OP_ARP_REPLY 2

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
	/* REQUIRES */
	assert(sr);
	assert(packet);
	assert(interface);
	struct sr_if* out_iface = 0;

	struct sr_arpreq *req;
	struct sr_arpcache *cache = &(sr->cache);

	uint16_t ethtype = ethertype(packet);

	printf("*** -> Received packet of length %d \n",len);
	/*printf("%u \n", packet);*/
	
	/*printf("%s\n", sr.user);*/
	
	if (ethtype == ethertype_arp) {

		uint8_t* arp_data = packet +  sizeof(sr_ethernet_hdr_t);
		sr_arp_hdr_t* arp_hdr = (sr_arp_hdr_t *) arp_data;
		if (arp_hdr->ar_op == htons(arp_op_request)){
			send_arpreply(sr, packet, len, interface);
			/*sr_print_routing_table(sr);*/
		}

		else if(arp_hdr->ar_op == htons(arp_op_reply)){
			req = sr_arpcache_insert(cache, arp_hdr->ar_sha, arp_hdr->ar_sip);
			struct sr_packet *pkt, *nxt;
        
        	for (pkt = req->packets; pkt; pkt = nxt) {
        		/*handle_ip(sr, pkt->buf, pkt->len, pkt->iface);*/
        		out_iface = sr_get_interface(sr, pkt->iface);
		      	assert(out_iface);
		      /* update ethernet header */
		      	sr_ethernet_hdr_t* ethernet_hdr = (sr_ethernet_hdr_t *)(pkt->buf);
		      	memcpy(ethernet_hdr->ether_dhost, arp_hdr->ar_sha, sizeof(uint8_t)*ETHER_ADDR_LEN);
		      	memcpy(ethernet_hdr->ether_shost, out_iface->addr, sizeof(uint8_t)*ETHER_ADDR_LEN);
		        
		      /* update ip header */

		      	sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t *)(pkt->buf + sizeof(struct sr_ethernet_hdr));

		      	ip_hdr->ip_ttl--;
		      	bzero(&(ip_hdr->ip_sum), 2);
		      	uint16_t ip_cksum = cksum(ip_hdr, sizeof(struct sr_ip_hdr));
		      	ip_hdr->ip_sum = ip_cksum;

		      	printf("Send packet:\n");
		      	/*print_hdrs(pkt->buf, pkt->len);*/
		      	sr_send_packet(sr, pkt->buf, pkt->len, pkt->iface);
            	nxt = pkt->next;
            }
            sr_arpreq_destroy(cache, req);
		}
		
	}
	
	else if (ethtype == ethertype_ip) {

		handle_ip(sr, packet, len, interface);
		
		/*send_arprequest(sr, htonl(3232236033));*/
		
		
	}
	
	else{
		sr_arpcache_dump(&(sr->cache));
	}
	
  

  /* fill in code here */

}/* end sr_ForwardPacket */

void handle_ip(struct sr_instance* sr, 
		uint8_t * packet/* lent */,
        unsigned int len,
        char* name/* sent from*/)

{
	struct sr_if* iface = 0;
	char outgoing_iface[sr_IFACE_NAMELEN];
	bzero(outgoing_iface, sr_IFACE_NAMELEN);
	struct sr_arpcache *cache = &(sr->cache);
	uint8_t* ip_data = packet +  sizeof(sr_ethernet_hdr_t);
	sr_ip_hdr_t *iphdr = (sr_ip_hdr_t *)(ip_data);
	uint8_t* icmp_data = packet +  sizeof(sr_ethernet_hdr_t)+  sizeof(sr_ip_hdr_t);
	sr_icmp_hdr_t* icmp_hdr = (sr_icmp_hdr_t *)icmp_data;

	sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t*) packet;

	

	if((iphdr->ip_p == ip_protocol_icmp) && (icmp_hdr->icmp_type == 3) && (icmp_hdr->icmp_code == 1)){
		printf("IM HERE with %s\n", name);
			iface = sr_get_interface(sr, name);
			print_addr_ip_int(ntohl(iface->ip));
			handle_icmp(sr, packet, len, iface, 3, 1);
			return;
		}

	/* check if this packet is for one of the router's interfaces*/
	iface = sr_get_interface_byip(sr, iphdr->ip_dst);
	if(iface){
		printf("%d\n", ntohl(iphdr->ip_src));
		if(iphdr->ip_p == ip_protocol_icmp){
			
			handle_icmp(sr, packet, len, iface, 0, 0);
			
		}
		else{
			handle_icmp(sr, packet,len, iface, 3, 3);
		}
		return;
	}

	/*print_hdr_ip(ip_data);*/

	printf("%d\n", ntohl(iphdr->ip_dst));
	struct sr_arpentry* entry = sr_arpcache_lookup(cache, iphdr->ip_dst);

	sr_longest_prefix_iface(sr, iphdr->ip_dst, outgoing_iface);
	printf("OUT ON: %s\n", outgoing_iface);

	
	if(iphdr->ip_ttl <=1){
		printf("Sending TYPE 11 ICMP\n" );
		iface = sr_get_interface(sr, name);
		handle_icmp(sr, packet, len,iface, 11, 0);
		return;
	}


	if(entry && entry->valid == 1){/*cache hit*/
		
		iface = sr_get_interface(sr, outgoing_iface);
		memcpy(eth_hdr->ether_dhost, entry->mac, sizeof(uint8_t)*ETHER_ADDR_LEN);
		memcpy(eth_hdr->ether_shost, iface->addr, sizeof(uint8_t)*ETHER_ADDR_LEN);

		iphdr->ip_sum = 0;
		iphdr->ip_ttl--;
		iphdr->ip_sum = cksum(iphdr, sizeof(sr_ip_hdr_t));

		if (sr_send_packet(sr, packet, len, iface->name) == -1 ) {
			fprintf(stderr, "CANNOT FORWARD IP PACKET \n");
		}
		
	}
	else if(outgoing_iface[0]!=0){ 
		
		sr_arpcache_queuereq(cache, iphdr->ip_dst, packet, len, outgoing_iface);
	}
	else{
		iface = sr_get_interface(sr, name);
		handle_icmp(sr, packet, len,iface, 3, 0);
	}
}

void handle_icmp(struct sr_instance* sr, 
				uint8_t * packet, int len,
				struct sr_if* iface, 
				int type, int code)
{
	char outgoing_iface[sr_IFACE_NAMELEN];

	struct sr_arpcache *cache = &(sr->cache);

	sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t*) packet;

	uint8_t* ip_data = packet +  sizeof(sr_ethernet_hdr_t);
	sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t *)(ip_data);

	uint8_t* icmp_payload = (uint8_t*) malloc((sizeof(sr_ip_hdr_t) +8));
	memcpy(icmp_payload, ip_data, (sizeof(sr_ip_hdr_t) +8));

	struct sr_arpentry* entry = sr_arpcache_lookup(cache, ip_hdr->ip_src);
	sr_longest_prefix_iface(sr, ip_hdr->ip_src, outgoing_iface);

	uint8_t* icmp_data = packet +  sizeof(sr_ethernet_hdr_t)+  sizeof(sr_ip_hdr_t);

	uint32_t ip_src = ip_hdr->ip_src;
	
	struct sr_if* out_iface = 0;

	ip_hdr->ip_p = ip_protocol_icmp;

	if(type == 0){
		sr_icmp_hdr_t* icmp_hdr = (sr_icmp_hdr_t *)icmp_data;


		icmp_hdr->icmp_type = (uint8_t)type;
		icmp_hdr->icmp_code = (uint8_t)code;
		bzero(&(icmp_hdr->icmp_sum), 2);
	
		icmp_hdr->icmp_sum = cksum(icmp_hdr, (len-(sizeof(sr_ethernet_hdr_t)+ sizeof(sr_ip_hdr_t))));
	}
	else if(type == 3 || type == 11){
		len = 70;
		sr_icmp_t3_hdr_t* icmp_hdr = (sr_icmp_t3_hdr_t *)icmp_data;
		printf("i should not be here\n");
		
		

		/*if(icmp_hdr->icmp_type != (uint8_t)type){*/
			ip_hdr->ip_len = htons(56);
			/*ip_hdr->ip_dst = iface->ip;*/
			icmp_hdr->icmp_type = (uint8_t)type;
			icmp_hdr->icmp_code = (uint8_t)code;
			bzero(&(icmp_hdr->icmp_sum), 2);
			
			memcpy(icmp_hdr->data, icmp_payload, (sizeof(sr_ip_hdr_t) +8));
			icmp_hdr->icmp_sum = cksum(icmp_hdr, (len-(sizeof(sr_ethernet_hdr_t)+ sizeof(sr_ip_hdr_t))));
		/*}*/
		/*else{
			printf("SENDING 11 TO IF: %s\n", iface->name);
			ip_hdr->ip_dst = iface->ip;
		}*/
		
	}
	sr_longest_prefix_iface(sr, ip_hdr->ip_src, outgoing_iface);
	out_iface = sr_get_interface(sr, outgoing_iface);
	ip_hdr->ip_ttl = 100;
	ip_hdr->ip_dst = ip_src;	
	ip_hdr->ip_src = iface->ip;
	
	if(entry && entry->valid == 1){
		
		/*bzero(eth_hdr->ether_dhost, 6);*/
		
		memcpy(eth_hdr->ether_dhost, entry->mac, sizeof(uint8_t)*ETHER_ADDR_LEN);
		memcpy(eth_hdr->ether_shost, out_iface->addr, sizeof(uint8_t)*ETHER_ADDR_LEN);
		/*eth_hdr->ether_type = htons(ethertype_ip);*/

		
		/*print_addr_ip_int(ntohl(iface->ip));
		
		
	
		/*print_addr_ip_int(ntohl(entry->ip));

		/* Create IP packet */
		
		bzero(&(ip_hdr->ip_sum), 2);
		ip_hdr->ip_sum = cksum(ip_hdr, 4*(ip_hdr->ip_hl));
		/*cksum(ip_data, sizeof(sr_ip_hdr_t));*/
		printf("hit %s\n", outgoing_iface);
		if (sr_send_packet(sr, packet, len, outgoing_iface) == -1 ) {
					fprintf(stderr, "CANNOT SEND ICMP PACKET \n");
				}
	}
	else{
		
		printf("cache miss %s\n", outgoing_iface);
		sr_arpcache_queuereq(cache, ip_hdr->ip_dst, packet, len, outgoing_iface);
	}

}



void send_arprequest(struct sr_instance* sr, uint32_t ip, char* name)
{
	unsigned int len=42;
	/* Assume MAC address is not found in ARP cache. We are using the next IP hop*/
	struct sr_if* iface = 0;


	iface = sr_get_interface(sr, name);
	uint8_t broadcast_addr[ETHER_ADDR_LEN]  = {255, 255, 255, 255, 255, 255};
	
	uint8_t* arp_packet = (uint8_t*) malloc(len);
	/*memcpy(arp_packet, packet, len);*/
	
	sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t*) arp_packet;
	/*bzero(eth_hdr->ether_dhost, 6);*/
	memcpy(eth_hdr->ether_dhost, broadcast_addr, sizeof(uint8_t)*ETHER_ADDR_LEN);
	memcpy(eth_hdr->ether_shost, iface->addr, sizeof(uint8_t)*ETHER_ADDR_LEN);
	eth_hdr->ether_type = htons(ethertype_arp);
	
	/* Create ARP packet */
	uint8_t* arp_data = arp_packet +  sizeof(sr_ethernet_hdr_t);
	sr_arp_hdr_t* arp_hdr = (sr_arp_hdr_t *) arp_data;
	
	arp_hdr->ar_hrd = htons(arp_hrd_ethernet);
	arp_hdr->ar_pro = htons(ethertype_ip);
	arp_hdr->ar_hln = (unsigned char) 6;
	arp_hdr->ar_pln = (unsigned char) 4;
	arp_hdr->ar_op = htons(arp_op_request);
	memcpy(arp_hdr->ar_sha, iface->addr, sizeof(uint8_t)*ETHER_ADDR_LEN);
	arp_hdr->ar_sip = iface->ip;
	bzero(arp_hdr->ar_tha, sizeof(uint8_t)*ETHER_ADDR_LEN);
	arp_hdr->ar_tip = ip;
	
	if (sr_send_packet(sr, arp_packet, len, iface->name) == -1 ) {
		fprintf(stderr, "CANNOT SEND ARP REQUEST \n");
	}
	
}

void send_arpreply(struct sr_instance* sr,
				uint8_t* packet,
				unsigned int len,
				const char* name) {

	/*sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(packet);*/
					
	struct sr_if* iface = 0;
	
	/* Create Ethernet header */
	uint8_t* arp_packet = (uint8_t *)malloc(len);
	memcpy(arp_packet, packet, len);
					
	sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)arp_packet;
	memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost,6);
	iface = sr_get_interface(sr, name);
	memcpy(eth_hdr->ether_shost,iface->addr,6);
	
	/* Create ARP packet */
	uint8_t* arp_data = arp_packet + sizeof(sr_ethernet_hdr_t);					
	sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(arp_data);
	
	/*if (arp_hdr->ar_op == htons(OP_ARP_REQUEST)){*/
		arp_hdr->ar_op = htons(OP_ARP_REPLY);
		memcpy(arp_hdr->ar_tha, arp_hdr->ar_sha, arp_hdr->ar_hln);
		arp_hdr->ar_tip = arp_hdr->ar_sip;
		memcpy(arp_hdr->ar_sha, iface->addr, arp_hdr->ar_hln);
		arp_hdr->ar_sip = iface->ip;	
	/*}*/
	/*printf("IP ADDRESS: %lu \n", ntohl(arp_hdr->ar_tip));*/
	/*TODO:
		We want to be able to send out an ARP Requset. An ARP Request must be sent out if:
			1. An ARP Request is recevied and the request is looking for an IP address that is not ourself; OR
			2. An IP packet is received and we don't know the next-hop MAC address for that IP packet
	
	*/
					
	/*
	int sr_send_packet(struct sr_instance* sr  borrowed ,
                         uint8_t* buf  borrowed  ,
                         unsigned int len,
                         const char* iface  borrowed )
	*/
	
	if (sr_send_packet(sr, arp_packet, len, name) == -1 ) {
		fprintf(stderr, "CANNOT SEND ARP REPLY \n");
	}
	
	
}

