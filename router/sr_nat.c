
#include <signal.h>
#include <assert.h>
#include "sr_nat.h"
#include <unistd.h>
#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

int sr_nat_init(struct sr_nat *nat) { /* Initializes the nat */

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
  pthread_create(&(nat->thread), &(nat->thread_attr), sr_nat_timeout, nat);

  /* CAREFUL MODIFYING CODE ABOVE THIS LINE! */

  nat->mappings = NULL;
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

void *sr_nat_timeout(void *nat_ptr) {  /* Periodic Timout handling */
  struct sr_nat *nat = (struct sr_nat *)nat_ptr;
  while (1) {
    sleep(1.0);
    pthread_mutex_lock(&(nat->lock));

    time_t curtime = time(NULL);

    /* handle periodic tasks here */
    

    pthread_mutex_unlock(&(nat->lock));
  }
  return NULL;
}

/* Get the mapping associated with given external port.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat,
    uint16_t aux_ext, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  /* handle lookup here, malloc and assign to copy */
  struct sr_nat_mapping *copy = NULL, *mapping = NULL;
  mapping = nat->mappings;
  while(mapping){
    if(mapping->aux_ext == aux_ext){
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
    if(mapping->aux_int == aux_int && mapping->ip_int == ip_int){
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
  uint32_t ip_int, uint32_t ip_ext, uint16_t aux_int, uint16_t aux_ext, 
  sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  /* handle insert here, create a mapping, and then return a copy of it */
  struct sr_nat_mapping *mapping = NULL, *runner=NULL, *copy=NULL;

  mapping = (struct sr_nat_mapping *) malloc(sizeof(struct sr_nat_mapping));
  time_t curtime = time(NULL);
  mapping->ip_int = ip_int;
  mapping->aux_int = aux_int;
  mapping->type = type;
  mapping->ip_ext = ip_ext;
  mapping->aux_ext = aux_ext;
  mapping->last_updated = curtime;
  mapping->next = NULL;

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
