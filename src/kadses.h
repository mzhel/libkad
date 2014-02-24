#ifndef _KAD_SES_H_
#define _KAD_SES_H_

#define KADEMLIA_VERSION 0x08

#define CONTROL_PACKET_QUEUE_LENGTH 64

#define DATA_PACKET_QUEUE_LENGTH 64

typedef struct _mule_session MULE_SESSION;

typedef bool (*MULE_ADD_SOURCE_FOR_UDP_FW_CHECK)(MULE_SESSION* ms, UINT128* id, uint32_t ip4_no, uint16_t tcp_port_no,  uint16_t udp_port_no);

typedef bool (*MULE_ADD_SOURCE_FOR_TCP_FW_CHECK)(void* ms, void* id, uint32_t ip4_no, uint16_t tcp_port_no,  uint16_t udp_port_no);

typedef struct _mule_callbacks {
  MULE_ADD_SOURCE_FOR_UDP_FW_CHECK add_source_for_udp_fw_check;
  MULE_ADD_SOURCE_FOR_UDP_FW_CHECK add_source_for_tcp_fw_check;
} MULE_CALLBACKS;

typedef int (*ZLIB_UNCOMPRESS)(unsigned char FAR* dest, unsigned long FAR* dest_len_ptr, const unsigned char FAR * src, unsigned long src_len);

typedef struct _zlib_callbacks {
  ZLIB_UNCOMPRESS uncompress;
} ZLIB_CALLBACKS;

typedef struct _kad_opts {
  bool use_extrn_udp_port;
} KAD_OPTS;

typedef struct _kad_session_timers {
  uint32_t udp_port_lookup;
  uint32_t self_lookup;
  uint32_t state_update;
  uint32_t nodes_count_check;
  uint32_t zone_safe;
  uint32_t done_sources_check;
  uint32_t inacvtive_sources_check;
  uint32_t search_jumpstart;
} KAD_SESSION_TIMERS;

typedef struct _kad_session {
  uint32_t version;
  UINT128 kad_id;
  uint8_t user_hash[16];
  uint32_t udp_key;
  ROUTING_ZONE* root_zone;
  LIST* active_zones;
  LIST* searches;
  QUEUE* queue_in_udp;
  QUEUE* queue_out_udp;
  uint32_t pub_ip4_no;
  uint32_t loc_ip4_no;
  uint16_t tcp_port;
  uint16_t udp_port;
  KAD_FW fw;
  KAD_SESSION_TIMERS timers;
  KAD_OPTS opts;
  MULE_SESSION* mule_session;
  MULE_CALLBACKS mcbs;
  ZLIB_CALLBACKS zcbs;
} KAD_SESSION;

typedef struct _kad_session_status {
  uint8_t version;
  uint16_t udp_port;
  uint16_t ext_udp_port;
  bool fw;
  bool fw_udp;
  uint32_t pub_ip4_no;
} KAD_SESSION_STATUS;

uint32_t
kadses_get_pub_ip(
                  KAD_SESSION* ks
                 );

uint16_t
kadses_get_udp_port(
                    KAD_SESSION* ks
                   );

bool
kadses_create_queue_udp_pkt(
                            KAD_SESSION* ks,
                            uint32_t ip4_no,
                            uint16_t port_no,
                            UINT128* target_id,
                            uint32_t verify_key,
                            void* pkt,
                            uint32_t pkt_len
                           );

bool
kadses_set_pub_ip(
                  KAD_SESSION* ks,
                  uint32_t ip4_no
                  );

bool
kadses_get_status(
                  void* ks,
                  KAD_SESSION_STATUS* kss
                 );

bool
kadses_calc_verify_key(
                       void* ks,
                       uint32_t ip4_no,
                       uint32_t* key_out
                      );

bool
kadses_bootstrap_from_node(
                           void* ks,
                           uint32_t ip4_no,
                           uint16_t port_no
                           );

bool
kadses_send_fw_check_udp(
                         void* ks,
                         uint16_t check_port,
                         uint32_t key,
                         uint32_t ip4_no
                        );


#define QUEUE_IN_UDP(ks, p) queue_enq(ks->queue_in_udp, p)

#define DEQ_IN_UDP(ks, pp) queue_deq(ks->queue_in_udp, pp)

#define QUEUE_OUT_UDP(ks, p) queue_enq(ks->queue_out_udp, p)

#define DEQ_OUT_UDP(ks, pp) queue_deq(ks->queue_out_udp, pp)

#define ONGOING_SEARCHES_LOCK(ks)

#define ONGOING_SEARCHES_UNLOCK(ks)

#define ACTIVE_ZONES_LOCK(ks)

#define ACTIVE_ZONES_UNLOCK(ks)

#endif //_KAD_SES_H_
