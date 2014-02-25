#ifndef _LIBKAD_H_
#define _LIBKAD_H_

#ifndef KAD_SESSION_STATUS_DEFINED
#define KAD_SESSION_STATUS_DEFINED

typedef struct _kad_session_status {
  uint8_t version;
  uint16_t udp_port;
  uint16_t ext_udp_port;
  bool fw;
  bool fw_udp;
} KAD_SESSION_STATUS;

#endif

#ifndef MULE_SESSION_DEFINED
#define MULE_SESSION_DEFINED

typedef struct _mule_session MULE_SESSION;

#endif 

typedef struct _kad_session KAD_SESSION;

typedef bool (*MULE_ADD_SOURCE_FOR_UDP_FW_CHECK)(MULE_SESSION* ms, void* id, uint32_t ip4_no, uint16_t tcp_port_no, uint16_t udp_port_no);

typedef bool (*MULE_ADD_SOURCE_FOR_TCP_FW_CHECK)(MULE_SESSION* ms, void* id, uint32_t ip4_no, uint16_t tcp_port_no, uint16_t udp_port_no);

typedef struct _mule_callbacks {
  MULE_ADD_SOURCE_FOR_UDP_FW_CHECK add_source_for_udp_fw_check;
  MULE_ADD_SOURCE_FOR_UDP_FW_CHECK add_source_for_tcp_fw_check;
} MULE_CALLBACKS;

typedef int (*ZLIB_UNCOMPRESS)(unsigned char * dest, unsigned long * dest_len_ptr, const unsigned char * src, unsigned long src_len);

typedef struct _zlib_callbacks {
  ZLIB_UNCOMPRESS uncompress;
} ZLIB_CALLBACKS;

#ifndef CIPHER_CALLBACKS_DEFINED
#define CIPHER_CALLBACKS_DEFINED

// arc4_context is commented out here
// because when this header is included in application
// using this library polarssl headers
// should be included before this header.
// Measure is temporary, need to figure out something better.

/*
typedef struct {
  uint8_t data[512];
} arc4_context;
*/

typedef void (*MD4)(const unsigned char *input, size_t ilen, unsigned char output[16]);
typedef void (*MD5)(const unsigned char *input, size_t ilen, unsigned char output[16]);
typedef void (*ARC4_SETUP)(arc4_context *ctx, const unsigned char *key, unsigned int keylen);
typedef int (*ARC4_CRYPT)(arc4_context *ctx, size_t length, const unsigned char *input, unsigned char *output);

typedef struct _cipher_callbacks {
  MD4 md4;
  MD5 md5;
  ARC4_SETUP arc4_setup;
  ARC4_CRYPT arc4_crypt;
} CIPHER_CALLBACKS;

#endif

bool
kad_session_init(
                 uint16_t tcp_port,
                 uint16_t udp_port,
                 char* nodes_file_path,
                 KAD_SESSION** ks_out
                 );

bool
kad_session_uninit(
                   KAD_SESSION* ks
                   );

bool
kad_session_update(
                   KAD_SESSION* ks,
                   uint32_t now
                   );

bool
kadses_set_mule_callbacks(
                          KAD_SESSION* ks,
                          void* ms,
                          MULE_CALLBACKS* mcbs
                         );

bool
kadses_set_zlib_callbacks(
                          KAD_SESSION* ks,
                          ZLIB_CALLBACKS* zcbs
                         );

bool
kadses_set_cipher_callbacks(
                            KAD_SESSION* ks,
                            CIPHER_CALLBACKS* ccbs
                           );

bool
kad_timer(KAD_SESSION* ks);

bool
kad_get_control_packet_to_send(
                               KAD_SESSION* ks,
                               uint32_t* ip4_no_out,
                               uint16_t* port_no_out,
                               void** pkt_out,
                               uint32_t* pkt_len_out
                               );

bool
kad_control_packet_received(
                            KAD_SESSION* ks,
                            uint32_t ip4_no,
                            uint16_t port_no,
                            void* ctrl_pkt,
                            uint32_t ctrl_pkt_len
                            );

bool
kad_deq_and_handle_control_packet(
                                  KAD_SESSION* ks
                                  );

bool
kad_bootstrap_from_node(
                        KAD_SESSION* ks,
                        char* node_addr,
                        uint16_t node_port
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

bool
kadses_fw_check_response(
                         void* ks
                        );

bool
kadses_fw_dec_checks_running(
                             void* ks
                             );

bool
kadses_fw_dec_checks_running_udp(
                                 void* ks
                                );

#endif //_LIBKAD_H_
