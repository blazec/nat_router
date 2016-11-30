
#ifndef SR_NAT_TABLE_H
#define SR_NAT_TABLE_H

#include <inttypes.h>
#include <time.h>
#include <pthread.h>
#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

#define MAX_HOSTS 256 
#define MIN_PORT 1024
#define MAX_PORT 65535
#define FIN 1
#define SYN 2
#define RST 4
#define PSH 8
#define ACK 16
#define URG 32
#define ECE 64
#define CWR 128
#define NS 256
#define MAX_PACKET_VOL 1024
#define INCOMING 2
#define OUTGOING 1

typedef enum {
  nat_mapping_icmp,
  nat_mapping_tcp
  /* nat_mapping_udp, */
} sr_nat_mapping_type;

typedef enum {
  nat_conn_unest,
  nat_conn_syn,
  nat_conn_synack,
  nat_conn_est,
  nat_conn_fin1,
  nat_conn_fin1ack,
  nat_conn_fin2
  /* nat_mapping_udp, */
} sr_nat_conn_states;

struct sr_nat_connection {
  /* add TCP connection state data members here */
  uint32_t ip_dst;
  uint16_t aux_dst;

  sr_nat_conn_states state;
  int len;
  uint8_t* packet;
  time_t last_updated;
  struct sr_nat_connection *next;
};

struct sr_nat_mapping {
  sr_nat_mapping_type type;
  uint32_t ip_int; /* internal ip addr */
  uint32_t ip_ext; /* external ip addr */
  uint16_t aux_int; /* internal port or icmp id */
  uint16_t aux_ext; /* external port or icmp id */
  time_t last_updated; /* use to timeout mappings */
  struct sr_nat_connection *conns; /* list of connections. null for ICMP */
  struct sr_nat_mapping *next;
};

struct sr_nat {
  /* add any fields here */
  struct sr_nat_mapping *mappings;
  uint32_t ip_ext;
  uint16_t next_port;

  /* timeout values */
  uint16_t icmp_to;
  uint16_t tcp_est_to;
  uint16_t tcp_trans_to;
  /* threading */
  pthread_mutex_t lock;
  pthread_mutexattr_t attr;
  pthread_attr_t thread_attr;
  pthread_t thread;
};


int sr_nat_init(struct sr_instance *sr, int tcmp_to, int tcp_est_to, int tcp_trans_to);     /* Initializes the nat */
int   sr_nat_destroy(struct sr_nat *nat);  /* Destroys the nat (free memory) */
void *sr_nat_timeout(void *nat_ptr);  /* Periodic Timout */
void sr_nat_delete_mapping(struct sr_nat *nat, struct sr_nat_mapping *map);
void sr_nat_delete_conn(struct sr_nat_mapping *mapping, struct sr_nat_connection *prev, 
  struct sr_nat_connection *conn);

void sr_tcp_conn_handle(struct sr_instance *sr, struct sr_nat_mapping *map, 
  uint8_t * packet, int len, int direction);

/* Get the mapping associated with given external port.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat,
    uint16_t aux_ext, sr_nat_mapping_type type );

/* Get the mapping associated with given internal (ip, port) pair.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_internal(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type );

/* Insert a new mapping into the nat's mapping table.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_nat *nat,
  uint32_t ip_int,  uint16_t aux_int,  
  sr_nat_mapping_type type );

struct sr_nat_mapping *sr_nat_insert_unsol_mapping(struct sr_nat *nat, uint8_t *packet, int len);
struct sr_nat_mapping *sr_nat_lookup_waiting_syn(struct sr_nat *nat, uint32_t ip_dst, uint16_t aux_dst);

#endif