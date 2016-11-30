
#include <signal.h>
#include <assert.h>
#include "sr_nat.h"
#include <unistd.h>
#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

#include <stdio.h>
#include <assert.h>
#include <string.h>


int sr_nat_init(struct sr_instance *sr, int icmp_to, int tcp_est_to, int tcp_trans_to) { /* Initializes the nat */
  assert(sr);
  struct sr_nat *nat = sr->nat;
  assert(nat);

  /* Acquire mutex lock */
  pthread_mutexattr_init(&(nat->attr));
  pthread_mutexattr_settype(&(nat->attr), PTHREAD_MUTEX_RECURSIVE);
  int success = pthread_mutex_init(&(nat->lock), &(nat->attr));

  /* Initialize timeout thread */

  pthread_attr_init(&(nat->thread_attr));
  pthread_attr_setdetachstate(&(nat->thread_attr), PTHREAD_CREATE_JOINABLE);
  pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
  pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
  pthread_create(&(nat->thread), &(nat->thread_attr), sr_nat_timeout, sr);
  
  /* CAREFUL MODIFYING CODE ABOVE THIS LINE! */

  nat->mappings = NULL;
  nat->next_port = MIN_PORT;

  nat->icmp_to=icmp_to;
  nat->tcp_est_to=tcp_est_to;
  nat->tcp_trans_to=tcp_trans_to;

  printf("ICMP TIMEOUT: %d\n", icmp_to);
  printf("TCP EST TIMEOUT: %d\n", tcp_est_to);
  printf("ICMP TIMEOUT: %d\n", tcp_trans_to);

  /* Initialize any variables here */

  return success;
}


int sr_nat_destroy(struct sr_nat *nat) {  /* Destroys the nat (free memory) */

  pthread_mutex_lock(&(nat->lock));


  /* free nat memory here */
  if(nat->mappings){
    struct sr_nat_mapping *cur = NULL, *next = NULL;
    cur = nat->mappings;
    while(cur->next){
      next = cur->next;
      free(cur);
      cur = next;
    }
    free(cur);
  }

  pthread_kill(nat->thread, SIGKILL);
  return pthread_mutex_destroy(&(nat->lock)) &&
    pthread_mutexattr_destroy(&(nat->attr));

}

void *sr_nat_timeout(void *sr_ptr) {  /* Periodic Timout handling */
  struct sr_instance *sr = sr_ptr;
  struct sr_nat *nat = sr->nat;
  char outgoing_iface[sr_IFACE_NAMELEN];
  while (1) {
    sleep(1.0);
    pthread_mutex_lock(&(nat->lock));
    
    int mapping_time=0, conn_time =0;
    time_t curtime = time(NULL);

    
    struct sr_nat_mapping *mapping = nat->mappings;
    while(mapping){
      mapping_time = difftime(curtime,mapping->last_updated);
      if (mapping->type == nat_mapping_icmp && mapping_time>=nat->icmp_to){
        sr_nat_delete_mapping(nat,mapping);
      }
      else if(mapping->type==nat_mapping_tcp)
      {
        if (mapping->conns == NULL){
          sr_nat_delete_mapping(nat,mapping);
        }
        else{
          struct sr_nat_connection *prev=NULL, *conn = mapping->conns;
          while(conn){
            conn_time = difftime(curtime, conn->last_updated);
            if(conn_time>=nat->tcp_est_to && conn->state == nat_conn_est)
            {
              sr_nat_delete_conn(mapping, prev, conn);
            }
            else if(conn_time>=nat->tcp_trans_to && conn->state != nat_conn_est)
            {
              sr_nat_delete_conn(mapping, prev, conn);
            }
            else if(conn_time>=6 && conn->packet != NULL){
                uint8_t* ip_data = conn->packet +  sizeof(sr_ethernet_hdr_t);
                sr_ip_hdr_t *iphdr = (sr_ip_hdr_t *)(ip_data);

                sr_longest_prefix_iface(sr, iphdr->ip_src, outgoing_iface);
                struct sr_if* iface = sr_get_interface(sr, outgoing_iface);

                handle_icmp(sr, conn->packet, conn->len, iface, 3, 3);
              
                sr_nat_delete_conn(mapping, prev, conn);

              }
              prev=conn;
              conn=conn->next;
          }
        }
      }
      mapping = mapping->next;
      

    }

    pthread_mutex_unlock(&(nat->lock));
  }
  return NULL;
}
void sr_nat_delete_conn(struct sr_nat_mapping *mapping, struct sr_nat_connection *prev, 
  struct sr_nat_connection *conn){
  if (prev){
    prev->next = conn->next;
  }
  else{
    mapping->conns = conn->next;
  }
}

/* Get the mapping associated with given external port.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat,
    uint16_t aux_ext, sr_nat_mapping_type type ) 
{

  pthread_mutex_lock(&(nat->lock));

  /* handle lookup here, malloc and assign to copy */
  struct sr_nat_mapping *copy = NULL, *mapping = NULL;
  mapping = nat->mappings;
  while(mapping){
    if(mapping->aux_ext == aux_ext && mapping->type == type){
      mapping->last_updated = time(NULL);
      copy = (struct sr_nat_mapping *) malloc(sizeof(struct sr_nat_mapping));
      memcpy(copy, mapping, sizeof(struct sr_nat_mapping));
    }
    mapping = mapping->next;
  }

  pthread_mutex_unlock(&(nat->lock));
  return copy;
}

/* Get the mapping associated with given internal (ip, port) pair.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_internal(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  /* handle lookup here, malloc and assign to copy. */
  struct sr_nat_mapping *copy = NULL, *mapping = NULL;
  mapping = nat->mappings;
  while(mapping){
    if(mapping->aux_int == aux_int && mapping->ip_int == ip_int && mapping->type == type){
      mapping->last_updated = time(NULL);
      copy = (struct sr_nat_mapping *) malloc(sizeof(struct sr_nat_mapping));
      memcpy(copy, mapping, sizeof(struct sr_nat_mapping));
    }
    mapping = mapping->next;
  }

  pthread_mutex_unlock(&(nat->lock));
  return copy;
}

/* Insert a new mapping into the nat's mapping table.
   Actually returns a copy to the new mapping, for thread safety.
 */
struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  /* handle insert here, create a mapping, and then return a copy of it */
  struct sr_nat_mapping *mapping = NULL, *runner=NULL, *copy=NULL;

  mapping = (struct sr_nat_mapping *) malloc(sizeof(struct sr_nat_mapping));
  time_t curtime = time(NULL);
  mapping->ip_int = ip_int;
  mapping->aux_int = aux_int;
  mapping->type = type;
  mapping->ip_ext = nat->ip_ext;
  if (type == nat_mapping_icmp){
    mapping->aux_ext = aux_int;
  }
  else{
    mapping->aux_ext = nat->next_port;
  }
  
  mapping->last_updated = curtime;
  mapping->next = NULL;
  mapping->conns = NULL;

  if(nat->next_port>MAX_PORT){
    nat->next_port=MIN_PORT;
  }
  else{
    nat->next_port++;
  }
  
  if(nat->mappings){
    runner = nat->mappings;
    while(runner->next){
      runner = runner->next;
    }
    runner->next = mapping;
  }
  else{
    nat->mappings = mapping;
  }

  copy = (struct sr_nat_mapping *) malloc(sizeof(struct sr_nat_mapping));
  memcpy(copy, mapping, sizeof(struct sr_nat_mapping));

  pthread_mutex_unlock(&(nat->lock));
  return copy;
}

void sr_tcp_conn_handle(struct sr_instance *sr, struct sr_nat_mapping *copy, uint8_t * packet, int len, int direction){
  struct sr_nat *nat = sr->nat;

  sr_ip_hdr_t *iphdr = (sr_ip_hdr_t *)(packet + sizeof(struct sr_ethernet_hdr));
  assert(iphdr->ip_p == ip_protocol_tcp);
  sr_tcp_hdr_t *tcp_header = (sr_tcp_hdr_t *)(packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr));

  pthread_mutex_lock(&(nat->lock));

  struct sr_nat_mapping *mapping = nat->mappings;
  while(mapping){
    if (mapping->aux_ext == copy->aux_ext)
      break;
    mapping = mapping->next;
  }
  printf("check1\n");
  uint32_t ip_dst;
  uint16_t aux_dst;
  if(direction == INCOMING){
    ip_dst = ntohs(iphdr->ip_src);
    aux_dst = ntohs(tcp_header->aux_src);
  }
  else{
    ip_dst = ntohs(iphdr->ip_dst);
    aux_dst = ntohs(tcp_header->aux_dst);
  }
  

  struct sr_nat_connection *conn = mapping->conns;

  while(conn){
    if(conn->ip_dst == ip_dst && conn->aux_dst == aux_dst)
      break;
    conn=conn->next;
  }
  printf("check2\n");
  if (conn==NULL){/*connection don't exist mon*/
    if(tcp_header->flags != tcp_flag_syn){
      pthread_mutex_unlock(&(nat->lock));
      return;
    }
    conn = malloc(sizeof(struct sr_nat_connection));
    conn->ip_dst=ip_dst;
    conn->aux_dst=aux_dst;
    conn->state=nat_conn_syn;
    conn->packet = NULL;
    conn->next = NULL;

    struct sr_nat_connection *runner = mapping->conns;
    if(runner){
      while(runner->next){
        runner=runner->next;
      }
      runner->next = conn;
    }
    else{
      mapping->conns = conn;
    }
  }

  if(conn->state == nat_conn_syn){
    /*Look for syn+ack*/  
    if (tcp_header->flags == tcp_flag_syn+tcp_flag_ack){
      conn->state=nat_conn_synack;
    }
  }
  else if(conn->state == nat_conn_synack){
    if (tcp_header->flags == tcp_flag_ack){
        conn->state=nat_conn_est;
      }
  }

  conn->last_updated = time(NULL);


  pthread_mutex_unlock(&(nat->lock));
}

struct sr_nat_mapping *sr_nat_insert_unsol_mapping(struct sr_nat *nat, uint8_t *packet, int len){
  sr_ip_hdr_t *iphdr = (sr_ip_hdr_t *)(packet + sizeof(struct sr_ethernet_hdr));
  assert(iphdr->ip_p == ip_protocol_tcp);
  sr_tcp_hdr_t *tcp_header = (sr_tcp_hdr_t *)(packet+sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t));
  pthread_mutex_lock(&(nat->lock));

  /* handle insert here, create a mapping, and then return a copy of it */
  struct sr_nat_mapping *mapping = NULL, *runner=NULL, *copy=NULL;

  mapping = (struct sr_nat_mapping *) malloc(sizeof(struct sr_nat_mapping));
  time_t curtime = time(NULL);
  mapping->ip_int = htonl(0);
  mapping->aux_int = htonl(0);
  mapping->type = nat_mapping_tcp;
  mapping->ip_ext = nat->ip_ext;
  mapping->aux_ext = nat->next_port;

  mapping->last_updated = curtime;
  mapping->next = NULL;

  struct sr_nat_connection *conn = malloc(sizeof(struct sr_nat_connection));
  conn->ip_dst=ntohs(iphdr->ip_src);
  conn->aux_dst=ntohs(tcp_header->aux_src);
  conn->state=nat_conn_unest;
  conn->packet = packet;
  conn->len=len;
  conn->next = NULL;
  conn->last_updated = curtime;
  mapping->conns = conn;

  if(nat->next_port>MAX_PORT){
    nat->next_port=MIN_PORT;
  }
  else{
    nat->next_port++;
  }
  
  if(nat->mappings){
    runner = nat->mappings;
    while(runner->next){
      runner = runner->next;
    }
    runner->next = mapping;
  }
  else{
    nat->mappings = mapping;
  }

  copy = (struct sr_nat_mapping *) malloc(sizeof(struct sr_nat_mapping));
  memcpy(copy, mapping, sizeof(struct sr_nat_mapping));

  pthread_mutex_unlock(&(nat->lock));
  return copy;
}

void sr_nat_delete_mapping(struct sr_nat *nat, struct sr_nat_mapping *copy)
{
  pthread_mutex_lock(&(nat->lock));
  if(copy==NULL)
    return;
  struct sr_nat_mapping *mapping = nat->mappings, *prev=NULL;
  while(mapping){
    if (mapping->aux_ext == copy->aux_ext)
      break;
    prev = mapping;
    mapping = mapping->next;
  }
  if(prev == NULL){
    nat->mappings = copy->next;
  }
  else{
    prev->next = copy->next;
  }
  free(copy);
  pthread_mutex_unlock(&(nat->lock));
}

struct sr_nat_mapping *sr_nat_lookup_waiting_syn(struct sr_nat *nat, uint32_t ip_dst, uint16_t aux_dst)
{
  pthread_mutex_lock(&(nat->lock));

  /* handle lookup here, malloc and assign to copy. */
  struct sr_nat_mapping *copy = NULL, *mapping = NULL;
  mapping = nat->mappings;
  while(mapping){
    if(mapping->aux_int == htonl(0) && mapping->ip_int == htonl(0)){
        struct sr_nat_connection *conn = mapping->conns;
        while(conn){
          if(conn->ip_dst == ip_dst && conn->aux_dst == aux_dst)
          {
            copy = (struct sr_nat_mapping *) malloc(sizeof(struct sr_nat_mapping));
            memcpy(copy, mapping, sizeof(struct sr_nat_mapping));
            break;
          }
          conn=conn->next;
        }
    }
    mapping = mapping->next;
  }

  pthread_mutex_unlock(&(nat->lock));
  return copy;
}
