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
#include "sr_nat.h"

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
 * by sr_vns_comm.c that means d NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance *sr,
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
	if(sr->nat && iphdr->ip_dst==sr->nat->ip_ext){
		handle_nat(sr, packet, len, name, FORWARD);
		printf("it hath returned\n");
		return;
	}
	else if(iface){
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

		if(sr->nat && sr->nat->ip_ext != iphdr->ip_src){
			handle_nat(sr, packet, len, name, FORWARD);
		}
		else{
			if (sr_send_packet(sr, packet, len, iface->name) == -1 ) {
				fprintf(stderr, "CANNOT FORWARD IP PACKET \n");
			}
		}
		
		
	}
	else if(outgoing_iface[0]!=0){ 
		if(sr->nat){
			handle_nat(sr, packet, len, name, QUEUE);
		}else{
			sr_arpcache_queuereq(cache, iphdr->ip_dst, packet, len, outgoing_iface);
		}
		
		
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
	if(type == 3 || type == 11){
		int new_len = sizeof(sr_ethernet_hdr_t)+ sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t) + sizeof(uint8_t)*ICMP_DATA_SIZE;
		if (new_len>len){
			uint8_t* new_packet = (uint8_t*) malloc(new_len);
			printf("lenghts %d, %d\n", len, new_len);
			memcpy(new_packet, packet, len);
			len = new_len;
			packet = new_packet;
		}
	}
	sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t*) packet;

	uint8_t* ip_data = packet +  sizeof(sr_ethernet_hdr_t);
	sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t *)(ip_data);
	printf("maklox\n");
	uint8_t* icmp_payload = (uint8_t*) malloc(sizeof(uint8_t)*ICMP_DATA_SIZE);
	printf("%d\n", sizeof(sr_ip_hdr_t) +8);
	memcpy(icmp_payload, ip_data, sizeof(uint8_t)*ICMP_DATA_SIZE);

	struct sr_arpentry* entry = sr_arpcache_lookup(cache, ip_hdr->ip_src);
	

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
		
		sr_icmp_t3_hdr_t* icmp_hdr = (sr_icmp_t3_hdr_t *)icmp_data;
		printf("i should not be here\n");
		
	
		/*if(icmp_hdr->icmp_type != (uint8_t)type){*/
			ip_hdr->ip_len = htons(len);
			/*ip_hdr->ip_dst = iface->ip;*/
			icmp_hdr->icmp_type = (uint8_t)type;
			icmp_hdr->icmp_code = (uint8_t)code;
			icmp_hdr->icmp_sum = 0;
			
			
			memcpy(icmp_hdr->data, icmp_payload, sizeof(uint8_t)*ICMP_DATA_SIZE);
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
				const char* name)
{

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

void handle_nat(struct sr_instance* sr,
				uint8_t* packet,
				int len,
				const char* name,
				int action)
{
	struct sr_if* iface=0;
	char outgoing_iface[sr_IFACE_NAMELEN];
	bzero(outgoing_iface, sr_IFACE_NAMELEN);
	int aux_int;
	struct sr_nat_mapping *copy;
	uint8_t* ip_data = packet +  sizeof(sr_ethernet_hdr_t);
	sr_ip_hdr_t *iphdr = (sr_ip_hdr_t *)(ip_data);
	struct sr_arpcache *cache = &(sr->cache);
	sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t*) packet;

	uint8_t* icmp_data = packet +  sizeof(sr_ethernet_hdr_t)+  sizeof(sr_ip_hdr_t);
	sr_icmp_hdr_t* icmp_hdr = (sr_icmp_hdr_t *)icmp_data;

	if(iphdr->ip_p == ip_protocol_icmp){
		aux_int = ntohs(icmp_hdr->icmp_id);
		if(iphdr->ip_dst==sr->nat->ip_ext){

			
			printf("%lu\n", aux_int);
			copy = sr_nat_lookup_external(sr->nat, aux_int, nat_mapping_icmp);
			
			if(copy){
				iphdr->ip_dst = copy->ip_int;
				struct sr_arpentry* entry = sr_arpcache_lookup(cache, iphdr->ip_dst);
				sr_longest_prefix_iface(sr, iphdr->ip_dst, outgoing_iface);
				iface = sr_get_interface(sr, outgoing_iface);
				if(entry && entry->valid == 1){/*cache hit*/
					
					
					memcpy(eth_hdr->ether_dhost, entry->mac, sizeof(uint8_t)*ETHER_ADDR_LEN);
					memcpy(eth_hdr->ether_shost, iface->addr, sizeof(uint8_t)*ETHER_ADDR_LEN);

					iphdr->ip_sum = 0;
					iphdr->ip_ttl--;
					iphdr->ip_sum = cksum(iphdr, sizeof(sr_ip_hdr_t));
					if (sr_send_packet(sr, packet, len, iface->name) == -1 ) {
						fprintf(stderr, "CANNOT FORWARD IP PACKET \n");
					}
				}
				else{
					sr_arpcache_queuereq(cache, iphdr->ip_dst, packet, len, outgoing_iface);
				}
				free(copy);
			}
			else{
				iface = sr_get_interface_byip(sr, iphdr->ip_dst);
				handle_icmp(sr, packet, len, iface, 0, 0);
			}
			
			return;
		}



		if(action == QUEUE){
			
			copy = sr_nat_lookup_internal(sr->nat, iphdr->ip_src, aux_int, nat_mapping_icmp);
			if(copy==NULL){
				copy = sr_nat_insert_mapping(sr->nat, iphdr->ip_src,  aux_int,  nat_mapping_icmp);
			}
			iphdr->ip_src = copy->ip_ext;
			sr_longest_prefix_iface(sr, iphdr->ip_dst, outgoing_iface);
			sr_arpcache_queuereq(cache, iphdr->ip_dst, packet, len, outgoing_iface);
			
		}
		else if(action == FORWARD){
			
			copy = sr_nat_lookup_internal(sr->nat, iphdr->ip_src, aux_int, nat_mapping_icmp);
			if(copy==NULL){
				copy = sr_nat_insert_mapping(sr->nat, iphdr->ip_src,  aux_int,  nat_mapping_icmp);
			}
			iphdr->ip_src = copy->ip_ext;
			iphdr->ip_sum = 0;
			iphdr->ip_sum = cksum(iphdr, sizeof(sr_ip_hdr_t));
			sr_longest_prefix_iface(sr, iphdr->ip_dst, outgoing_iface);
			if (sr_send_packet(sr, packet, len, outgoing_iface) == -1 ) {
				fprintf(stderr, "CANNOT FORWARD IP PACKET \n");
			}
		}
		free(copy);
	}
	else if(iphdr->ip_p == ip_protocol_tcp){
		sr_tcp_hdr_t *tcp_header = (sr_tcp_hdr_t *)(packet+sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t));
		

		if(iphdr->ip_dst==sr->nat->ip_ext){
			aux_int = ntohs(tcp_header->aux_dst);
			printf("synack? %lu\n",aux_int);
			copy = sr_nat_lookup_external(sr->nat, aux_int, nat_mapping_tcp);
			
			if(copy){
				iphdr->ip_dst = copy->ip_int;
				tcp_header->aux_dst= htons(copy->aux_int);
				struct sr_arpentry* entry = sr_arpcache_lookup(cache, iphdr->ip_dst);
				sr_longest_prefix_iface(sr, iphdr->ip_dst, outgoing_iface);
				iface = sr_get_interface(sr, outgoing_iface);
				sr_tcp_conn_handle(sr, copy, packet, len, INCOMING);
				if(entry && entry->valid == 1){/*cache hit*/
					
					
					memcpy(eth_hdr->ether_dhost, entry->mac, sizeof(uint8_t)*ETHER_ADDR_LEN);
					memcpy(eth_hdr->ether_shost, iface->addr, sizeof(uint8_t)*ETHER_ADDR_LEN);

					iphdr->ip_sum = 0;
					iphdr->ip_ttl--;
					iphdr->ip_sum = cksum(iphdr, sizeof(sr_ip_hdr_t));
					tcp_header->checksum= tcp_cksum(packet,len);
					if (sr_send_packet(sr, packet, len, iface->name) == -1 ) {
						fprintf(stderr, "CANNOT FORWARD IP PACKET \n");
					}
				}
				else{
					tcp_header->checksum= tcp_cksum(packet,len);
					sr_arpcache_queuereq(cache, iphdr->ip_dst, packet, len, outgoing_iface);
				}
				free(copy);
			}
			else if(aux_int <= 1023){
				printf("bumboclod\n");
				iface = sr_get_interface(sr, name);
				handle_icmp(sr, packet, len,iface, 3, 3);
			}
			else{/* this is when we keep an uncolicited syn*/
				uint8_t* new_packet = (uint8_t*) malloc(len);
				memcpy(new_packet, packet, len);
				copy = sr_nat_insert_unsol_mapping(sr->nat, packet, len);

			}
			return;
		}

		aux_int = ntohs(tcp_header->aux_src);
		printf("auaxind %lu\n", aux_int);

		if(action == QUEUE){
			copy = sr_nat_lookup_internal(sr->nat, iphdr->ip_src, aux_int, nat_mapping_tcp);
			if(copy==NULL){
				copy = sr_nat_lookup_waiting_syn(sr->nat, iphdr->ip_dst, tcp_header->aux_dst);
				sr_nat_delete_mapping(sr->nat, copy);
				copy = sr_nat_insert_mapping(sr->nat, iphdr->ip_src,  aux_int,  nat_mapping_tcp);
			}
			iphdr->ip_src = copy->ip_ext;
			printf("auz ext %lu\n", copy->aux_ext);
        	tcp_header->aux_src= htons(copy->aux_ext);
        	tcp_header->checksum= tcp_cksum(packet,len);
        	sr_longest_prefix_iface(sr, iphdr->ip_dst, outgoing_iface);
			sr_tcp_conn_handle(sr, copy, packet, len, OUTGOING);
			sr_arpcache_queuereq(cache, iphdr->ip_dst, packet, len, outgoing_iface);
		}
		else if(action == FORWARD){
			copy = sr_nat_lookup_internal(sr->nat, iphdr->ip_src, aux_int, nat_mapping_tcp);
			if(copy==NULL){
				copy = sr_nat_insert_mapping(sr->nat, iphdr->ip_src,  aux_int,  nat_mapping_tcp);
			}
			iphdr->ip_src = copy->ip_ext;
			iphdr->ip_sum = 0;
			iphdr->ip_sum = cksum(iphdr, sizeof(sr_ip_hdr_t));
			tcp_header->aux_src= htons(copy->aux_ext);
        	tcp_header->checksum= tcp_cksum(packet,len);
			sr_longest_prefix_iface(sr, iphdr->ip_dst, outgoing_iface);
			sr_tcp_conn_handle(sr, copy, packet, len, OUTGOING);
			if (sr_send_packet(sr, packet, len, outgoing_iface) == -1 ) {
				fprintf(stderr, "CANNOT FORWARD IP PACKET \n");
			}
		}
		free(copy);

	}
}
uint16_t tcp_cksum(uint8_t* packet, int len){

  sr_ip_hdr_t *iphdr = (sr_ip_hdr_t *)(packet + sizeof(struct sr_ethernet_hdr));
  sr_tcp_hdr_t *tcp_header = (sr_tcp_hdr_t *)(packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr));

  sr_tcp_pshdr_t *tcp_pshdr = calloc(1,sizeof(struct sr_tcp_pshdr));
  tcp_pshdr->ip_src = iphdr->ip_src;
  tcp_pshdr->ip_dst = iphdr->ip_dst;
  tcp_pshdr->ip_p = iphdr->ip_p;
  uint16_t tcp_length = len-sizeof(struct sr_ethernet_hdr)-sizeof(struct sr_ip_hdr);
  tcp_pshdr->len = htons(tcp_length);

  tcp_header->checksum = 0; 

  uint8_t *total_tcp = calloc(1, sizeof(struct sr_tcp_pshdr)+tcp_length);
  memcpy(total_tcp,tcp_pshdr, sizeof(struct sr_tcp_pshdr));
  memcpy((total_tcp+sizeof(struct sr_tcp_pshdr)), tcp_header, tcp_length);

  uint16_t checksum = cksum(total_tcp, sizeof(struct sr_tcp_pshdr)+tcp_length);
  
  free(tcp_pshdr);
  free(total_tcp);

  return checksum;
}