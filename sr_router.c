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
#include <stdlib.h>
#include <string.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

#define ICMP_REQUEST 8
#define ICMP_REPLY 0

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

int ip_sanity_check(uint8_t* packet, unsigned int length) {
    unsigned int target_length = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t);
    if(length < target_length) {
        return 1;
    }

    //check checksum
    sr_ip_hdr_t* ip_header = (sr_ip_hdr_t*)(&(packet[sizeof(sr_ethernet_hdr_t)]));
    uint16_t curr_cksum = ip_header->ip_sum;
    ip_header->ip_sum = 0;
    uint16_t target_cksum = cksum(ip_header, sizeof(sr_ip_hdr_t));

    if(target_cksum != curr_cksum) {
        // polluted
        ip_header->ip_sum = curr_cksum; 
        return 1;
    } else {
        ip_header->ip_sum = curr_cksum;
        return 0;
    }
}

struct sr_if* get_rt_entry(struct sr_instance* sr, uint32_t target_ip) {
    // get interface
    struct sr_rt* table_entry = sr->routing_table;
    struct sr_if* target_if = NULL;
    while(table_entry != NULL) {
        if(table_entry->dest.s_addr == target_ip) {
            target_if = sr_get_interface(sr, table_entry->interface);
        }
        table_entry = table_entry->next;
    }

    return target_if;
}

struct sr_if* get_rt_entry_prefix(struct sr_instance* sr, uint32_t target_ip) {
    struct sr_rt* table_entry = sr->routing_table;
    struct sr_if* target_if = NULL;
    int longest_match = 0;
    
    while(table_entry != NULL) {
        uint32_t table_prefix = (uint32_t)ntohl(table_entry->dest.s_addr) & 
                                (uint32_t)ntohl(table_entry->mask.s_addr);
        uint32_t target_ip_prefix = target_ip & (uint32_t)ntohl(table_entry->mask.s_addr);
        uint32_t res = target_ip_prefix ^ table_prefix;
        uint32_t temp = (uint32_t)ntohl(table_entry->mask.s_addr);
        int cnt = 0;
        
        // find length of prefix
        for(int i = 0; i < 32; i ++) {
            if(temp != 0) {
                temp <<= 1;
                cnt ++;
            } else {
                break;
            }
        }

        // compare longest match
        if(res == 0 && cnt > longest_match) {
            longest_match = cnt;
            target_if = sr_get_interface(sr, table_entry->interface);
        }
        table_entry = table_entry->next;
    }
    printf("eth: %s\n", target_if->name);
    return target_if;
}

void set_arp_field(sr_arp_hdr_t* arp_header, unsigned short ar_hrd,
                   unsigned short ar_pro, unsigned char ar_hln,
                   unsigned char ar_pln, unsigned short ar_op,
                   unsigned char* ar_sha, uint32_t ar_sip,
                   unsigned char* ar_tha, uint32_t ar_tip) {
    arp_header->ar_hrd = ar_hrd;
    arp_header->ar_pro = ar_pro;
    arp_header->ar_hln = ar_hln;
    arp_header->ar_pln = ar_pln;
    arp_header->ar_op = ar_op;
    memcpy(arp_header->ar_sha, ar_sha, ETHER_ADDR_LEN);
    arp_header->ar_sip = ar_sip;
    memcpy(arp_header->ar_tha, ar_tha, ETHER_ADDR_LEN);
    arp_header->ar_tip = ar_tip;
}

void set_ether_field(sr_ethernet_hdr_t* ether_header, uint16_t ether_type, 
                     uint8_t* ether_dhost, uint8_t* ether_shost) {
    ether_header->ether_type = ether_type; 
    memcpy(ether_header->ether_shost, ether_shost, ETHER_ADDR_LEN);
    memcpy(ether_header->ether_dhost, ether_dhost, ETHER_ADDR_LEN);
}

void set_ip_field(sr_ip_hdr_t* ip_header, unsigned int ip_hl, unsigned int ip_v,
                  uint8_t ip_tos, uint16_t ip_len, uint16_t ip_id, uint16_t ip_off,
                  uint8_t ip_ttl, uint8_t ip_p, uint16_t ip_sum, 
                  uint32_t ip_src, uint32_t ip_dst) {
    // set ip header
    ip_header->ip_hl = ip_hl;
    ip_header->ip_v = ip_v;
    ip_header->ip_tos = ip_tos;
    ip_header->ip_len = ip_len;
    ip_header->ip_id = ip_id;
    ip_header->ip_off = ip_off;
    ip_header->ip_ttl = ip_ttl;
    ip_header->ip_p = ip_p;           
    ip_header->ip_sum = ip_sum;
    ip_header->ip_src = ip_src;
    ip_header->ip_dst = ip_dst;
    ip_header->ip_sum = cksum(ip_header, sizeof(sr_ip_hdr_t));
}

void send_unreachable_icmp(struct sr_instance* sr, uint8_t* prev_packet, uint8_t code, char* if_name) {
    uint8_t* packet = calloc(sizeof(sr_ethernet_hdr_t) + 
                             sizeof(sr_ip_hdr_t) + 
                             sizeof(sr_icmp_t3_hdr_t), sizeof(uint8_t));
    
    // extract new header
    sr_ethernet_hdr_t* ether_header = (sr_ethernet_hdr_t*)packet;
    sr_ip_hdr_t* ip_header = (sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
    sr_icmp_t3_hdr_t* icmp_header = (sr_icmp_t3_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t) + 
                                                                 sizeof(sr_ip_hdr_t));

    // extract prev header
    sr_ethernet_hdr_t* p_ether_header = (sr_ethernet_hdr_t*)prev_packet;
    sr_ip_hdr_t* p_ip_header = (sr_ip_hdr_t*)(prev_packet + sizeof(sr_ethernet_hdr_t));

    // find interface
    struct sr_if* target_if = get_rt_entry_prefix(sr, ntohl(p_ip_header->ip_src)); // sr->routing_table;
    if(target_if == NULL) return;

    // set icmp header
    icmp_header->icmp_type = 3;
    icmp_header->icmp_code = code;
    icmp_header->icmp_sum = 0;
    memcpy(icmp_header->data, p_ip_header, 28);
    icmp_header->icmp_sum = cksum(icmp_header, sizeof(sr_icmp_t3_hdr_t));

    // set ip header
    set_ip_field(ip_header, p_ip_header->ip_hl, p_ip_header->ip_v, p_ip_header->ip_tos,
                 htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t)), p_ip_header->ip_id,
                 p_ip_header->ip_off, INIT_TTL, 1, 0, sr_get_interface(sr, if_name)->ip, p_ip_header->ip_src);

    // set eth header
    set_ether_field(ether_header, p_ether_header->ether_type, 
                    p_ether_header->ether_shost, target_if->addr);

    sr_send_packet(sr, packet, 74, target_if->name);
}

void send_timeexceed_icmp(struct sr_instance* sr, uint8_t* prev_packet, uint8_t code, char* if_name) {
    uint8_t* packet = calloc(sizeof(sr_ethernet_hdr_t) + 
                             sizeof(sr_ip_hdr_t) + 
                             sizeof(sr_icmp_t11_hdr_t), sizeof(uint8_t));
    
    // extract new header
    sr_ethernet_hdr_t* ether_header = (sr_ethernet_hdr_t*)packet;
    sr_ip_hdr_t* ip_header = (sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
    sr_icmp_t11_hdr_t* icmp_header = (sr_icmp_t11_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t) + 
                                                                   sizeof(sr_ip_hdr_t));

    // extract prev header
    sr_ethernet_hdr_t* p_ether_header = (sr_ethernet_hdr_t*)prev_packet;
    sr_ip_hdr_t* p_ip_header = (sr_ip_hdr_t*)(prev_packet + sizeof(sr_ethernet_hdr_t));

    // find interface
    struct sr_if* target_if = get_rt_entry_prefix(sr, ntohl(p_ip_header->ip_src));
    if(target_if == NULL) return;

    // set icmp header
    icmp_header->icmp_type = 11;
    icmp_header->icmp_code = code;
    icmp_header->icmp_sum = 0;
    memcpy(icmp_header->data, p_ip_header, 28);
    icmp_header->icmp_sum = cksum(icmp_header, sizeof(sr_icmp_t11_hdr_t));

     // set ip header
    set_ip_field(ip_header, p_ip_header->ip_hl, p_ip_header->ip_v, p_ip_header->ip_tos,
                 htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t11_hdr_t)), p_ip_header->ip_id,
                 p_ip_header->ip_off, INIT_TTL, 1, 0, sr_get_interface(sr, if_name)->ip, p_ip_header->ip_src);

    // set eth header
    set_ether_field(ether_header, p_ether_header->ether_type, 
                    p_ether_header->ether_shost, target_if->addr);

    sr_send_packet(sr, packet, 74, target_if->name);
}


void router_handle_my_ip_packet(struct sr_instance* sr, uint8_t* packet, 
                             sr_ethernet_hdr_t* p_ether_header, sr_ip_hdr_t* p_ip_header, 
                             unsigned int len, char* interface) {
    // if packet is ICMP echo request and cksum valid, send ICMP echo to host
    if(p_ip_header->ip_p == ip_protocol_icmp) {
        sr_icmp_t8_hdr_t* p_icmp_header = (sr_icmp_t8_hdr_t*)(packet + 
                                            sizeof(sr_ethernet_hdr_t) + 
                                            sizeof(sr_ip_hdr_t));
        
        // check if it is reqeust
        if(p_icmp_header->icmp_type == ICMP_REQUEST) {
            struct sr_rt* curr_rt_entry = sr->routing_table;
            
            // find which entry to reply
            while(curr_rt_entry != NULL) {
                if(curr_rt_entry->dest.s_addr == p_ip_header->ip_src) {
                    // check if icmp checksum is valid
                    uint16_t icmp_cksum = p_icmp_header->icmp_sum;
                    p_icmp_header->icmp_sum = 0;
                    uint16_t target_cksum = cksum(p_icmp_header, len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));
                    p_icmp_header->icmp_sum = icmp_cksum;
                    if(icmp_cksum != target_cksum) {
                        return;
                    }
                    
                    // alloc new packet
                    struct sr_if* target_if = sr_get_interface(sr, curr_rt_entry->interface);
                    uint8_t* new_packet = calloc(len, sizeof(uint8_t));
                    memcpy(new_packet, packet, len);
                    sr_ethernet_hdr_t* ether_header = (sr_ethernet_hdr_t*)new_packet;
                    sr_ip_hdr_t* ip_header = (sr_ip_hdr_t*)(new_packet + sizeof(sr_ethernet_hdr_t));
                    sr_icmp_t8_hdr_t* icmp_header = (sr_icmp_t8_hdr_t*)(new_packet + sizeof(sr_ethernet_hdr_t) + 
                                                                                     sizeof(sr_ip_hdr_t));
               
                    // reset ip addr
                    uint32_t temp = p_ip_header->ip_src;
                    ip_header->ip_src = p_ip_header->ip_dst;
                    ip_header->ip_dst = temp;

                    // reset icmp 
                    icmp_header->icmp_code = 0;
                    icmp_header->icmp_type = ICMP_REPLY;
                    icmp_header->icmp_sum= 0;
                    icmp_header->icmp_sum = cksum(icmp_header, len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));

                    // reset ethernet
                    set_ether_field(ether_header, ether_header->ether_type, 
                                    p_ether_header->ether_shost, target_if->addr);

                    // reply
                    sr_send_packet(sr, new_packet, len, target_if->name);
                    //break;
                }
                curr_rt_entry = curr_rt_entry->next;
            }
        }
    } else if (p_ip_header->ip_p == ip_protocol_tcp ||
               p_ip_header->ip_p == ip_protocol_udp) {
        // udp/tcp, send unreacahble icmp
        send_unreachable_icmp(sr, packet, 3, interface);                
    }
}

void check_outstanding_reqeust(struct sr_instance* sr, struct sr_arpreq* arp_req) {
    struct sr_packet* curr_packet = arp_req->packets;

    while(curr_packet != NULL) {
        send_unreachable_icmp(sr, curr_packet->buf, 1, curr_packet->iface);
        curr_packet = curr_packet->next;
    }

    sr_arpreq_destroy(&sr->cache, arp_req);
}

void send_arp_request(struct sr_instance* sr, struct sr_arpreq* arp_req) {
    uint8_t* arp_packet = calloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t), sizeof(uint8_t));

    // if outstanding
    if(difftime(time(NULL), arp_req->sent) > 1.0) {
       if(arp_req->times_sent >= 5) {
           check_outstanding_reqeust(sr, arp_req);
       } else {
        // get interface
        struct sr_if* target_if = get_rt_entry_prefix(sr, ntohl(arp_req->ip));
        if(target_if == NULL) return;

        // process ethernet header
        uint8_t tha[ETHER_ADDR_LEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff}; 
        sr_ethernet_hdr_t* ether_header = (sr_ethernet_hdr_t*)arp_packet;
        set_ether_field(ether_header, htons(ethertype_arp), 
                        tha, target_if->addr);

        // process arp header
        sr_arp_hdr_t* arp_header = (sr_arp_hdr_t*)(arp_packet+ sizeof(sr_ethernet_hdr_t));
        set_arp_field(arp_header, htons(arp_hrd_ethernet), htons(ethertype_ip),
                      ETHER_ADDR_LEN, 4, htons(arp_op_request), target_if->addr,
                      target_if->ip, tha, arp_req->ip);

        // update times
        arp_req->times_sent ++;
        arp_req->sent = time(NULL);

        sr_send_packet(sr, arp_packet, 
                       sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t), target_if->name);
       }
    }
}

void router_handle_others_ip_packet(struct sr_instance* sr, uint8_t* packet, 
                                 sr_ethernet_hdr_t* ether_header, sr_ip_hdr_t* ip_header, 
                                 unsigned int len, char* interface) {
    // check TTL
    if(ip_header->ip_ttl == 0) {
        return;
    }
   
    // decrease TTL and recompute cksum
    ip_header->ip_ttl --;
    ip_header->ip_sum= 0;
    ip_header->ip_sum = cksum(ip_header, sizeof(sr_ip_hdr_t)); 

    if(ip_header->ip_ttl == 0) {
        send_timeexceed_icmp(sr, packet, 0, interface);
        return;
    }

    // find place in routing table
    struct sr_if* target_if = get_rt_entry_prefix(sr, ntohl(ip_header->ip_dst));
    if(target_if == NULL) {
        send_unreachable_icmp(sr, packet, 0, interface);
        return;
    }

    // check cache
    struct sr_arpentry* cache = sr_arpcache_lookup(&sr->cache, ip_header->ip_dst);
    if(cache != NULL) {
        ip_header->ip_sum = 0;
        ip_header->ip_sum = cksum(ip_header, sizeof(sr_ip_hdr_t));
        set_ether_field(ether_header, ether_header->ether_type, cache->mac, target_if->addr);
        sr_send_packet(sr, packet, len, target_if->name);
    } else {
        // send arp request for next hop ip 
        struct sr_arpreq* arp_req = sr_arpcache_queuereq(&sr->cache, ip_header->ip_dst, packet, 
                                                         len, target_if->name);
        // set default value and send the request
        arp_req->sent = 0;
        arp_req->times_sent = 0;                     
        send_arp_request(sr, arp_req);
    }
}

void router_handle_arp_req(struct sr_instance* sr, sr_arp_hdr_t* arp_header, 
                           sr_ethernet_hdr_t* ether_header, char* receive_if, int len) {
    uint8_t* rply_arp_packet = calloc(sizeof(sr_ethernet_hdr_t) 
                                 + sizeof(sr_arp_hdr_t), sizeof(uint8_t));

    // get reply pckt header
    sr_arp_hdr_t* rply_arp_header = (sr_arp_hdr_t*)(rply_arp_packet + sizeof(sr_ethernet_hdr_t));
    sr_ethernet_hdr_t* rply_ether_header = (sr_ethernet_hdr_t*)rply_arp_packet;
    struct sr_if* target_if = sr_get_interface(sr, receive_if);

    // insert to arp cache
    sr_arpcache_insert(&sr->cache, arp_header->ar_sha, 
                        arp_header->ar_sip);

    /* set arp field */  
    set_arp_field(rply_arp_header, arp_header->ar_hrd, arp_header->ar_pro,
                      ETHER_ADDR_LEN, 4, htons(2), target_if->addr,
                      target_if->ip, arp_header->ar_sha, arp_header->ar_sip);

    /* set ether field */
    set_ether_field(rply_ether_header, ether_header->ether_type, 
                    ether_header->ether_shost, target_if->addr);

    sr_send_packet(sr, rply_arp_packet, len, target_if->name);
}

void router_handle_arp_rply(struct sr_instance* sr, sr_arp_hdr_t* arp_header, 
                           sr_ethernet_hdr_t* ether_header, char* receive_if, int len) {
    struct sr_if* target_if = sr_get_interface(sr, receive_if);
    
    // check if ip equals
    if(arp_header->ar_tip == target_if->ip) {
        // find queued packets
        struct sr_arpreq* saved_req = sr_arpcache_insert(&sr->cache, arp_header->ar_sha, 
                                                  arp_header->ar_sip);
        
        if(saved_req == NULL) return;

        // send out the packets
        struct sr_packet* curr_packet = saved_req->packets;
        while(curr_packet != NULL) {
            uint8_t* packet = curr_packet->buf;
            unsigned int packet_len = curr_packet->len;

            sr_ethernet_hdr_t* cur_ether_header = (sr_ethernet_hdr_t*)packet;
            sr_ip_hdr_t* cur_ip_header = (sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));

            // initialize cksum
            cur_ip_header->ip_sum = 0;
            cur_ip_header->ip_sum = cksum(cur_ip_header, sizeof(sr_ip_hdr_t));

            // initialize mac addr
            set_ether_field(cur_ether_header, cur_ether_header->ether_type, 
                            arp_header->ar_sha, target_if->addr);

            // send packet
            sr_send_packet(sr, packet, packet_len, target_if->name);
            curr_packet = curr_packet->next;
            //break;
        }
        sr_arpreq_destroy(&sr->cache, saved_req);
    }
}


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

    printf("*** -> Received packet of length %d \n",len);

    /* fill in code here */

    // check the type of packet
    if(ethertype(packet) == ethertype_ip) {
        // perform sanity check
        int corrupted = ip_sanity_check(packet, len);
        
        if(!corrupted) {
            //check whether this packet for me
            struct sr_if* curr_if = sr->if_list;
            sr_ip_hdr_t* ip_header = (sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
            sr_ethernet_hdr_t* ether_header = (sr_ethernet_hdr_t*)(packet);
         
            while(curr_if != NULL) {
                // ip for me
                if(curr_if->ip == ip_header->ip_dst) {
                    router_handle_my_ip_packet(sr, packet, ether_header, 
                                               ip_header, len, interface);
                    return;
                }
                curr_if = curr_if->next;
            }
          
            router_handle_others_ip_packet(sr, packet, ether_header, 
                                           ip_header, len, interface);
        }
    } else if(ethertype(packet) == ethertype_arp) {
        sr_arp_hdr_t* arp_header = (sr_arp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
        sr_ethernet_hdr_t* ether_header = (sr_ethernet_hdr_t*) (packet);
        
        // check opcode
        if(ntohs(arp_header->ar_op) == arp_op_request) {
            router_handle_arp_req(sr, arp_header, ether_header, interface, len);
        } else if(ntohs(arp_header->ar_op) == arp_op_reply) {
            // handle arp reply
            router_handle_arp_rply(sr, arp_header, ether_header, interface, len);
        }
    }

}/* end sr_ForwardPacket */

