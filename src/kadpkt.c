#include <stdint.h>
#include <stdbool.h>
#include <memory.h>
#include <arpa/inet.h>
#include <uint128.h>
#include <list.h>
#include <queue.h>
#include <node.h>
#include <nodelist.h>
#include <tag.h>
#include <protocols.h>
#include <packet.h>
#include <str.h>
#include <mem.h>
#include <log.h>

bool
kadpkt_create_bootstrap(
                        void** raw_pkt_out,
                        uint32_t* raw_pkt_len_out
                        )
{
  bool result = false;
  void* raw_pkt = NULL;
  uint32_t raw_pkt_len = 0;
  KAD_PACKET* kp = NULL;
  uint32_t bytes_emited = 0;

  do {

    if (!raw_pkt_out || !raw_pkt_len_out) break;
    
    if (!pkt_create(NULL, 0, OP_KADEMLIAHEADER, KADEMLIA2_BOOTSTRAP_REQ, &kp)){

      LOG_ERROR("Failed to create bootstrap packet.");

      break;

    }

    raw_pkt_len = pkt_length_with_header(kp);

    raw_pkt = mem_alloc(raw_pkt_len);

    if (!raw_pkt){

      LOG_ERROR("Failed to allocate memeory for raw packet.");

      break;

    }

    if (!pkt_emit(kp, (uint8_t*)raw_pkt, raw_pkt_len, &bytes_emited)){

      LOG_ERROR("Failed to emit packet to buffer.");

      break;

    }

    *raw_pkt_out = raw_pkt;

    *raw_pkt_len_out = bytes_emited;

    result = true;

  } while (false);

  if (kp) pkt_destroy(kp);

  if (!result && raw_pkt) mem_free(raw_pkt);

  return result;
}

bool
kadpkt_create_search(
                     uint8_t cont_cnt,
                     UINT128* search_id,
                     UINT128* node_id,
                     void** raw_pkt_out,
                     uint32_t* raw_pkt_len_out
                     )
{
  bool result = false;
  void* raw_pkt = NULL;
  uint32_t raw_pkt_len = 0;
  KAD_PACKET* kp = NULL;
  uint32_t bytes_emited = 0;
  uint8_t* pkt_data = NULL;
  uint32_t pkt_data_len = 0;

  do {

    if (!search_id || !node_id || !raw_pkt_out || !raw_pkt_len_out) break;

    pkt_data_len = sizeof(UINT128) * 2 + sizeof(uint8_t);

    pkt_data = (uint8_t*)mem_alloc(pkt_data_len);

    if (!pkt_data){

      LOG_ERROR("Failed to allocate memory for packet data.");

      break;

    }

    *pkt_data = cont_cnt;

    memcpy(pkt_data + 1, search_id, sizeof(UINT128));

    memcpy(pkt_data + 1 + sizeof(UINT128), node_id, sizeof(UINT128));

    if (!pkt_create(pkt_data, pkt_data_len, OP_KADEMLIAHEADER, KADEMLIA2_REQ, &kp)){

      LOG_ERROR("Failed to create packet.");

      break;

    }

    raw_pkt_len = pkt_length_with_header(kp);

    raw_pkt = mem_alloc(raw_pkt_len);

    if (!raw_pkt){

      LOG_ERROR("Failed to allocate memory for raw packet.");

      break;

    }

    if (!pkt_emit(kp, (uint8_t*)raw_pkt, raw_pkt_len, &bytes_emited)){

      LOG_ERROR("Failed to emit packet to buffer.");

      break;

    }

    *raw_pkt_out = raw_pkt;

    *raw_pkt_len_out = bytes_emited;

    result = true;

  } while (false);

  if (pkt_data) mem_free(pkt_data);

  if (kp) pkt_destroy(kp);

  if (!result && raw_pkt) mem_free(raw_pkt);

  return result;
}

bool
kadpkt_create_ping(
                   void** raw_pkt_out,
                   uint32_t* raw_pkt_len_out
                   )
{
  bool result = false;
  KAD_PACKET* kp = NULL;
  void* raw_pkt = NULL;
  uint32_t raw_pkt_len = 0;
  uint32_t bytes_emited = 0;

  do {

    if (!raw_pkt_out || !raw_pkt_len_out) break;

    if (!pkt_create(NULL, 0, OP_KADEMLIAHEADER, KADEMLIA2_PING, &kp)){

      LOG_ERROR("pkt_create failed.");

      break;

    }

    raw_pkt_len = pkt_length_with_header(kp);

    LOG_DEBUG("raw_pkt_len: %.8x", raw_pkt_len);

    raw_pkt = mem_alloc(raw_pkt_len);

    if (!raw_pkt){

      LOG_ERROR("Failed to allocate memory for raw packet.");

      break;

    }

    if (!pkt_emit(kp, (uint8_t*)raw_pkt, raw_pkt_len, &bytes_emited)){

      LOG_ERROR("Failed to emit packet to buffer.");

      break;

    }

    LOG_DEBUG("bytes_emited: %.8x", bytes_emited);

    *raw_pkt_out = raw_pkt;

    *raw_pkt_len_out = bytes_emited;

    result = true;

  } while (false);

  if (kp) pkt_destroy(kp);

  if (!result && raw_pkt) mem_free(raw_pkt);

  return result;
}

bool
kadpkt_create_pong(
                   uint16_t port_from_no,
                   void** raw_pkt_out,
                   uint32_t* raw_pkt_len_out
                  )
{
  bool result = false;
  void* raw_pkt = NULL;
  uint32_t raw_pkt_len = 0;
  void* pkt_data = NULL;
  uint32_t pkt_data_len = 0;
  uint32_t bytes_emited = 0;
  KAD_PACKET* kp = NULL;

  do {

    if (!raw_pkt_out || !raw_pkt_len_out) break;

    pkt_data_len = 2;  // Udp port from.    

    pkt_data = (uint8_t*)mem_alloc(pkt_data_len);

    if (!pkt_data){

      LOG_ERROR("Failed to allocate memory for packet data.");

      break;

    }

    *(uint16_t*)pkt_data = port_from_no;

    if (!pkt_create(pkt_data, pkt_data_len, OP_KADEMLIAHEADER, KADEMLIA2_PONG, &kp)){

      LOG_ERROR("Failed to create kad packet.");

      break;

    }

    raw_pkt_len = pkt_length_with_header(kp);

    raw_pkt = mem_alloc(raw_pkt_len);

    if (!raw_pkt){

      LOG_ERROR("Failed to allocate memory for raw packet.");

      break;

    }

    if (!pkt_emit(kp, (uint8_t*)raw_pkt, raw_pkt_len, &bytes_emited)){

      LOG_ERROR("Failed to emit packet to buffer.");

      break;

    }

    *raw_pkt_out = raw_pkt;

    *raw_pkt_len_out = raw_pkt_len;

    result = true;

  } while (false);

  if (pkt_data) mem_free(pkt_data);

  if (kp) pkt_destroy(kp);

  if (!result && raw_pkt) mem_free(raw_pkt);

  return result;
}

bool
kadpkt_create_bootstrap_res(
                            UINT128* self_kad_id,
                            uint16_t tcp_port,
                            LIST* kn_lst,
                            void** raw_pkt_out,
                            uint32_t* raw_pkt_len_out
                           )
{
  bool result = false;
  uint32_t kn_cnt = 0;
  uint32_t rem_len = 0;
  void* pkt_data = NULL;
  uint32_t pkt_data_len = 0;
  KAD_NODE* kn = NULL;
  KAD_PACKET* kp = NULL;
  uint8_t* p = NULL;
  void* raw_pkt = NULL;
  uint32_t raw_pkt_len = 0;
  uint32_t bytes_emited = 0;

  do {

    if (!kn_lst || !raw_pkt_out || !raw_pkt_len_out) break;

    list_entries_count(kn_lst, &kn_cnt);

    if (!kn_cnt) break;

    rem_len = pkt_data_len = sizeof(UINT128) + // self kad id
                             2 +               // self tcp port
                             1 +               // self kad version
                             2 +               // nodes count in packet
                             kn_cnt * 25;      // nodes

    p = pkt_data = (uint8_t*)mem_alloc(pkt_data_len);

    if (!pkt_data){

      LOG_ERROR("Failed to allocate memory for bootstrap packet.");

      break;

    }

    uint128_emit(self_kad_id, p, rem_len); // kad id

    p += sizeof(UINT128);

    rem_len -= sizeof(UINT128);

    *(uint32_t*)p = tcp_port; // tcp port

    p += sizeof(uint16_t);

    rem_len -= sizeof(uint16_t);

    *p++ = KADEMLIA_VERSION; // version

    rem_len--;

    *(uint16_t*)p = (uint16_t)kn_cnt; // contacts count

    p += sizeof(uint16_t);

    rem_len -= sizeof(uint16_t);

    LIST_EACH_ENTRY_WITH_DATA_BEGIN(kn_lst, e, kn);

      // node id

      uint128_emit(&kn->id, p, rem_len);

      p += sizeof(UINT128);

      rem_len -= sizeof(UINT128);

      // node ip

      *(uint32_t*)p = kn->ip4_no;

      p += sizeof(uint32_t);

      rem_len -= sizeof(uint32_t);

      // node udp port
      
      *(uint16_t*)p = kn->udp_port_no;

      p += sizeof(uint16_t);

      rem_len -= sizeof(uint16_t);

      // node tcp port
      
      *(uint16_t*)p = kn->tcp_port_no;

      p += sizeof(uint16_t);

      rem_len -= sizeof(uint16_t);

      // node version
      
      *p++ = kn->version;

      rem_len--;

    LIST_EACH_ENTRY_WITH_DATA_END(e);

    if (!pkt_create(pkt_data, pkt_data_len, OP_KADEMLIAHEADER, KADEMLIA2_BOOTSTRAP_RES, &kp)){

      LOG_ERROR("pkt_create failed.");

      break;

    }

    raw_pkt_len = pkt_length_with_header(kp);

    raw_pkt = mem_alloc(raw_pkt_len);

    if (!raw_pkt){

      LOG_ERROR("Failed to allocate memory for raw packet.");

      break;

    }

    if (!pkt_emit(kp, (uint8_t*)raw_pkt, raw_pkt_len, &bytes_emited)){

      LOG_ERROR("Failed to emit packet to buffer");

      break;

    }

    *raw_pkt_out = raw_pkt;

    *raw_pkt_len_out = raw_pkt_len;

    result = true;

  } while (false);

  if (pkt_data) mem_free(pkt_data);

  if (kp) pkt_destroy(kp);

  if (!result && raw_pkt) mem_free(raw_pkt);

  return result;
}

bool
kadpkt_create_hello(
                    UINT128* self_kad_id,
                    uint16_t tcp_port,
                    uint16_t udp_port,
                    uint8_t opcode,
                    uint8_t target_kad_ver,
                    uint32_t target_udp_key,
                    UINT128* target_id,
                    bool req_ack_pkt,
                    bool fw,
                    bool fw_udp,
                    void** raw_pkt_out,
                    uint32_t* raw_pkt_len_out
                    )
{
  bool result = false;
  void* raw_pkt = NULL;
  uint32_t raw_pkt_len = 0;
  uint32_t bytes_emited = 0;
  KAD_PACKET* kp = NULL;
  uint8_t* pkt_data = NULL;
  uint32_t pkt_data_len = 0;
  TAG* src_uport_tag = NULL;
  uint32_t src_uport_tag_size = 0;
  TAG* opts_tag = NULL;
  uint32_t opts_tag_size = 0;
  uint8_t tag_cnt = 0;
  uint8_t opts = 0;
  uint8_t* p = NULL;
  uint32_t rem_len = 0;

  do {

    pkt_data_len = sizeof(UINT128) +  // self id
                   sizeof(uint16_t) + // self tcp port
                   1 +                // self version
                   1;                 // tag count

    if (udp_port){

      if (!tag_create(TAGTYPE_UINT16, 0, TAG_SOURCEUPORT, udp_port, &src_uport_tag)) {

        LOG_ERROR("Failed to create TAG_SOURCEPORT");

        break;

      }

      tag_calc_buf_size(src_uport_tag, &src_uport_tag_size);

      pkt_data_len += src_uport_tag_size;

      tag_cnt++;

    }

    if (target_kad_ver >= 8 && (req_ack_pkt || fw || fw_udp)){

      opts = ((req_ack_pkt?1:0) << 2) | (uint8_t)((uint8_t)fw << 1) | (uint8_t)((uint8_t)fw_udp);

      if (!tag_create(TAGTYPE_UINT8, 0, TAG_KADMISCOPTIONS, opts, &opts_tag)){

        LOG_ERROR("Failed to create TAG_KADMISCOPTIONS");

        break;

      }

      tag_calc_buf_size(opts_tag, &opts_tag_size);

      pkt_data_len += opts_tag_size;

      tag_cnt++;

    }

    pkt_data = (uint8_t*)mem_alloc(pkt_data_len);

    if (!pkt_data){

      LOG_ERROR("Failed to allocate memory for packet data.");

      break;

    }

    // Fill in the data.
    
    p = pkt_data;

    rem_len = pkt_data_len;

    // Self id.

    uint128_emit(self_kad_id, p, rem_len);

    p += sizeof(UINT128);

    rem_len -= sizeof(UINT128);

    // Self tcp port.

    *(uint16_t*)p = tcp_port;

    p += sizeof(uint16_t);

    rem_len -= sizeof(uint16_t);

    // Supported version.

    *p++ = KADEMLIA_VERSION;
    
    rem_len--;

    *p++ = tag_cnt;

    rem_len--;

    // Emit

    if (udp_port){

      if (!tag_emit(src_uport_tag, p, rem_len, NULL, NULL)){ // TAG_SOURCEPORT tag.

        LOG_ERROR("Failed to emit TAG_SOURCEPORT.");

        break;

      }

      p += src_uport_tag_size;

      rem_len -= src_uport_tag_size;

    }

    if (target_kad_ver >= 8 && (req_ack_pkt || fw || fw_udp)){

      // [TODO] Also need to add firewall opts.
      
      if (!tag_emit(opts_tag, p, rem_len, NULL, NULL)){

        LOG_ERROR("Failed to emit TAG_KADMISCOPTIONS");

        break;

      }

      p += opts_tag_size;

      rem_len -= opts_tag_size;

    }

    if (!pkt_create(pkt_data, pkt_data_len, OP_KADEMLIAHEADER, opcode, &kp)){

      LOG_ERROR("pkt_create failed.");

      break;

    }

    raw_pkt_len = pkt_length_with_header(kp);

    raw_pkt = mem_alloc(raw_pkt_len);

    if (!raw_pkt){

      LOG_ERROR("Failed to allocate memory for raw packet.");

      break;

    }

    if (!pkt_emit(kp, (uint8_t*)raw_pkt, raw_pkt_len, &bytes_emited)){

      LOG_ERROR("Failed to emit packet to buffer.");

      break;

    }

    *raw_pkt_out = raw_pkt;

    *raw_pkt_len_out = raw_pkt_len;

    result = true;

  } while (false);

  if (src_uport_tag) tag_destroy(src_uport_tag);

  if (opts_tag) tag_destroy(opts_tag);

  if (pkt_data) mem_free(pkt_data);

  if (kp) pkt_destroy(kp);

  if (!result && raw_pkt) mem_free(raw_pkt);

  return result;
}

bool
kadpkt_create_hello_ack(
                        UINT128* self_kad_id,
                        void** raw_pkt_out,
                        uint32_t* raw_pkt_len_out
                       )
{
  bool result = false;
  uint8_t* pkt_data = NULL;
  uint32_t pkt_data_len = 0;
  void* raw_pkt = NULL;
  uint32_t raw_pkt_len = 0;
  KAD_PACKET* kp = NULL;
  uint32_t bytes_emited = 0;

  do {

    if (!raw_pkt_out || !raw_pkt_len_out) break;

    pkt_data_len = sizeof(UINT128) + // self id
                   1;                // tags count

    pkt_data = (uint8_t*)mem_alloc(pkt_data_len);

    if (!pkt_data){

      LOG_ERROR("Failed to allocate memory for pong packet.");

      break;

    }

    // self id.

    uint128_emit(self_kad_id, pkt_data, pkt_data_len);

    // tags count.

    *(pkt_data + sizeof(UINT128)) = 0;

    if (!pkt_create(pkt_data, pkt_data_len, OP_KADEMLIAHEADER, KADEMLIA2_PONG, &kp)){

      LOG_ERROR("pkt_create failed.");

      break;
      
    }

    raw_pkt_len = pkt_length_with_header(kp);

    raw_pkt = mem_alloc(raw_pkt_len);

    if (!raw_pkt){

      LOG_ERROR("Failed to allocate memory for raw packet.");

      break;

    }

    if (!pkt_emit(kp, (uint8_t*)raw_pkt, raw_pkt_len, &bytes_emited)) {

      LOG_ERROR("Failed to emit packet to buffer.");

      break;

    }

    *raw_pkt_out = raw_pkt;

    *raw_pkt_len_out = raw_pkt_len;

    result = true;

  } while (false);

  if (pkt_data) mem_free(pkt_data);

  if (kp) pkt_destroy(kp);

  if (!result && raw_pkt) mem_free(raw_pkt);

  return result;
}

bool
kadpkt_parse_hello(
                   uint8_t* pkt,
                   uint32_t pkt_len,
                   UINT128* kn_id_out,
                   uint16_t* tcp_port_out,
                   uint16_t* udp_port_out,
                   uint8_t* ver_out,
                   bool* udp_fw_out,
                   bool* tcp_fw_out,
                   bool* ack_needed_out
                  )
{
  bool result = false;
  uint8_t* p = NULL;
  uint32_t rem_len = 0;
  uint16_t tcp_port = 0;
  uint16_t udp_port = 0;
  uint8_t ver = 0;
  uint8_t tag_cnt = 0;
  bool udp_fw = false;
  bool tcp_fw = false;
  bool ack_needed = false;
  TAG* tag = NULL;
  uint32_t tag_len = 0;
  wchar_t tag_name[128];
  uint64_t int_val = 0;
  KAD_NODE* kn = NULL;
  UINT128 kn_id;
  uint32_t hello_pkt_min_len = sizeof(UINT128) + sizeof(uint16_t) + sizeof(uint8_t) + sizeof(uint8_t);
  bool error = false;

  do {

    if (pkt_len < hello_pkt_min_len) break;

    p = pkt;

    rem_len = pkt_len;

    // Sender node id

    uint128_from_buffer(&kn_id, p, rem_len, false);

    LOG_DEBUG("id: ", ((UINT128*)&kn_id));

    p += sizeof(UINT128);

    rem_len -= sizeof(UINT128);

    // Tcp port

    tcp_port = *(uint16_t*)p;

    p += sizeof(uint16_t);

    rem_len -= sizeof(uint16_t);

    LOG_DEBUG("tcp_port: %d", tcp_port);

    // Sender version

    ver = *p++;

    rem_len--;

    LOG_DEBUG("version: %d", ver);

    // Tag count
    
    tag_cnt = *p++;

    rem_len--;

    LOG_DEBUG("tag_cnt: %d", tag_cnt);

    while (tag_cnt--){

      if (!tag_read(p, rem_len, false, &tag, &p, &tag_len)){

        error = true;

        LOG_ERROR("Failed to read tag.");

        break;

      }

      memset(tag_name, 0, sizeof(tag_name));

      tag_get_name(tag, tag_name, sizeof(tag_name));

      if (0 == str_wide_cmp(tag_name, TAG_SOURCEUPORT)){

        if (tag_is_integer(tag) && tag_get_integer(tag, &int_val)){

          udp_port = (uint16_t)int_val;

          LOG_DEBUG("TAG_SOURCEUPORT = %d", udp_port);

        }

      } else if (0 == str_wide_cmp(tag_name, TAG_KADMISCOPTIONS)){

        if (tag_is_integer(tag) && tag_get_integer(tag, &int_val)){

          udp_fw = (int_val & 1) > 0;

          tcp_fw = (int_val & 2) > 0;

          ack_needed = (ver >= 8) && ((int_val & 4) > 0);

          LOG_DEBUG("TAG_KADMISCOPTIONS = %d", int_val);

        }

      }

      if (tag) tag_destroy(tag);

      tag = NULL;

    }

    if (error) break;

    if (kn_id_out) uint128_copy(&kn_id, kn_id_out);

    if (tcp_port_out) *tcp_port_out = tcp_port;

    if (udp_port_out) *udp_port_out = udp_port;

    if (ver_out) *ver_out = ver;

    if (udp_fw_out) *udp_fw_out = udp_fw;

    if (tcp_fw_out) *tcp_fw_out = tcp_fw;

    if (ack_needed_out) *ack_needed_out = ack_needed;

    result = true;

  } while (false);

  return result;
}


bool
kadpkt_create_search_response(
                              UINT128* target,
                              LIST* kn_lst,
                              void** raw_pkt_out,
                              uint32_t* raw_pkt_len_out
                             )
{
  bool result = false;
  uint32_t kn_cnt = 0;
  uint8_t* pkt_data = NULL;
  uint8_t* p = NULL;
  uint32_t pkt_data_len = 0;
  uint32_t rem_len = 0;
  KAD_NODE* kn = NULL;
  void* raw_pkt = NULL;
  uint32_t raw_pkt_len = 0;
  uint32_t bytes_emited = 0;
  KAD_PACKET* kp = NULL;
  NODE_LIST_ENTRY* nle = NULL;

  do {
  
    if (!target || !kn_lst || !raw_pkt_out || !raw_pkt_len_out) break;

    list_entries_count(kn_lst, &kn_cnt);

    rem_len = pkt_data_len = sizeof(UINT128) + // Search target id
                             sizeof(uint8_t) + // Found nodes count
                             (25 * kn_cnt);    // Nodes data

    p = pkt_data = (uint8_t*)mem_alloc(pkt_data_len);

    if (!pkt_data){

      LOG_ERROR("Failed to allocate memory for search response packet.");

      break;

    }

    // Search target id.

    uint128_emit(target, p, rem_len);

    p += sizeof(UINT128);

    rem_len -= sizeof(UINT128);

    // Found contacts count.

    *p++ = (uint8_t)kn_cnt;

    rem_len--;

    // Nodes data

    LIST_EACH_ENTRY_WITH_DATA_BEGIN(kn_lst, e, nle);

      kn = &nle->kn;

      // Node id

      uint128_emit(&kn->id, p, rem_len);

      p += sizeof(UINT128);

      rem_len -= sizeof(UINT128);

      // Node ip
    
      *(uint32_t*)p = ntohl(kn->ip4_no);

      p += sizeof(uint32_t);

      rem_len -= sizeof(uint32_t);

      // Node udp port.

      *((uint16_t*)p) = ntohs(kn->udp_port_no);

      p += sizeof(uint16_t);

      rem_len -= sizeof(uint16_t);

      // Node tcp port.

      *((uint16_t*)p) = ntohs(kn->tcp_port_no);

      p += sizeof(uint16_t);

      rem_len -= sizeof(uint16_t);

      // Node version.

      *p++ = kn->version;

      rem_len--;

    LIST_EACH_ENTRY_WITH_DATA_END(e);

    if (!pkt_create(pkt_data, pkt_data_len, OP_KADEMLIAHEADER, KADEMLIA2_RES, &kp)){

      LOG_ERROR("pkt_create failed.");

      break;

    }

    raw_pkt_len = pkt_length_with_header(kp);

    raw_pkt = mem_alloc(raw_pkt_len);

    if (!raw_pkt){

      LOG_ERROR("Failed to allocate memory for raw packet.");

      break;

    }

    if (!pkt_emit(kp, (uint8_t*)raw_pkt, raw_pkt_len, &bytes_emited)){

      LOG_ERROR("Failed to emit packet to buffer");

      break;

    }

    *raw_pkt_out = raw_pkt;

    *raw_pkt_len_out = raw_pkt_len;

    result = true;

  } while (false);

  if (pkt_data) mem_free(pkt_data);

  if (kp) pkt_destroy(kp);

  if (!result && raw_pkt) mem_free(raw_pkt);

  return result;
  
}

bool
kadpkt_create_search_key_req(
                             UINT128* target,
                             uint8_t* search_terms_data,
                             uint32_t search_terms_data_size,
                             void** raw_pkt_out,
                             uint32_t* raw_pkt_len_out
                            )
{
  bool result = false;
  uint32_t rem_len = 0;
  void* raw_pkt = NULL;
  uint32_t raw_pkt_len = 0;
  uint8_t* p = NULL;
  KAD_PACKET* kp = NULL;
  uint32_t bytes_emited = 0;
  uint8_t* pkt_data = NULL;
  uint32_t pkt_data_len = 0;

  do {

    if (!target || !search_terms_data || !search_terms_data_size || !raw_pkt_out || !raw_pkt_len_out ) break;

    rem_len = pkt_data_len = sizeof(UINT128) + // Search target
                             2 +               // Range
                             search_terms_data_size;

    p = pkt_data = (uint8_t*)mem_alloc(pkt_data_len);

    if (!pkt_data){

      LOG_ERROR("Failed to allocate memory for packet data.");

      break;

    }

    // Search target.

    uint128_emit(target, p, rem_len);

    p += sizeof(UINT128);

    rem_len -= sizeof(UINT128);

    // Search terms

    *(uint16_t*)p = 0x8000;

    p += sizeof(uint16_t);

    rem_len -= sizeof(uint16_t);

    memcpy(p, search_terms_data, search_terms_data_size);

    p += search_terms_data_size;

    rem_len -= search_terms_data_size;

    if (!pkt_create(pkt_data, pkt_data_len, OP_KADEMLIAHEADER, KADEMLIA2_SEARCH_KEY_REQ, &kp)){

      LOG_ERROR("pkt_create failed.");

      break;

    }

    raw_pkt_len = pkt_length_with_header(kp);

    raw_pkt = mem_alloc(raw_pkt_len);

    if (!raw_pkt){

      LOG_ERROR("Failed to allocate memory for raw packet.");

      break;

    }

    if (!pkt_emit(kp, (uint8_t*)raw_pkt, raw_pkt_len, &bytes_emited)){

      LOG_ERROR("Failed to emit packet to buffer.");

      break;

    }

    *raw_pkt_out = raw_pkt;

    *raw_pkt_len_out = raw_pkt_len;
  
    result = true;

  } while (false);

  if (pkt_data) mem_free(pkt_data);

  if (kp) pkt_destroy(kp);

  if (!result && raw_pkt) mem_free(raw_pkt);

  return result;
}

bool
kadpkt_create_search_source_req(
                                UINT128* file_id,
                                uint64_t file_size,
                                void** raw_pkt_out,
                                uint32_t* raw_pkt_len_out
                               )
{
  bool result = false;
  uint8_t* pkt_data = NULL;
  uint32_t pkt_data_len = 0;
  uint8_t* p = NULL;
  uint32_t rem_len = 0;
  void* raw_pkt = NULL;
  uint32_t raw_pkt_len = 0;
  uint32_t bytes_emited = 0;
  KAD_PACKET* kp = NULL;
  
  do {

    if (!file_id || !raw_pkt_out) break;

    rem_len = pkt_data_len = sizeof(UINT128) + // Search file id
                             sizeof(uint16_t) + // Start position
                             sizeof(uint64_t);  //File size

    p = pkt_data = (uint8_t*)mem_alloc(pkt_data_len);

    if (!pkt_data){

      LOG_ERROR("Failed to allocate memory for search response packet.");

      break;

    }

    uint128_emit(file_id, p, rem_len); // Search file id

    p += sizeof(UINT128);

    rem_len -= sizeof(UINT128);

    // Start position

    *(uint16_t*)p = 0;

    p += sizeof(uint16_t);

    rem_len -= sizeof(uint16_t);

    // File size

    *(uint64_t*)p = file_size;

    p += sizeof(uint64_t);

    rem_len -= sizeof(uint64_t);

    if (!pkt_create(pkt_data, pkt_data_len, OP_KADEMLIAHEADER, KADEMLIA2_SEARCH_SOURCE_REQ, &kp)){

      LOG_ERROR("pkt_create failed.");

      break;

    }

    raw_pkt_len = pkt_length_with_header(kp);

    raw_pkt = mem_alloc(raw_pkt_len);

    if (!raw_pkt){

      LOG_ERROR("Failed to allocate memory for raw packet.");

      break;

    }

    if (!pkt_emit(kp, (uint8_t*)raw_pkt, raw_pkt_len, &bytes_emited)){

      LOG_ERROR("Failed to emit packet to buffer.");

      break;

    }

    *raw_pkt_out = raw_pkt;

    *raw_pkt_len_out = raw_pkt_len;

    result = true;

  } while (false);

  if (pkt_data) mem_free(pkt_data);

  if (kp) pkt_destroy(kp);

  if (!result && raw_pkt) mem_free(raw_pkt);

  return result;
}

bool
kadpkt_create_fw_check(
                       uint16_t tcp_port,
                       UINT128* cli_hash,
                       uint8_t conn_opts,
                       void** raw_pkt_out,
                       uint32_t* raw_pkt_len_out
                      )
{
  bool result = false;
  uint8_t* pkt_data = NULL;
  uint32_t pkt_data_len = 0;
  uint8_t* p = NULL;
  uint32_t rem_len = 0;
  void* raw_pkt = NULL;
  uint32_t raw_pkt_len = 0;
  KAD_PACKET* kp = NULL;
  uint32_t bytes_emited = 0;

  do {
      
    if (!raw_pkt_out || !raw_pkt_len_out) break;

    rem_len = pkt_data_len = sizeof(uint16_t) + // tcp port
                             sizeof(UINT128) +  // client hash
                             sizeof(uint8_t);   // conn options

    p = pkt_data = (uint8_t*)mem_alloc(pkt_data_len);

    if (!pkt_data){

      LOG_ERROR("Failed to allocate memory for raw packet.");

      break;

    }

    // tcp port

    *(uint16_t*)p = tcp_port;

    p += sizeof(uint16_t);

    rem_len -= sizeof(uint16_t);

    // client hash
    
    uint128_emit(cli_hash, p, rem_len);

    p += sizeof(UINT128);

    rem_len -= sizeof(UINT128);

    // connection options
    
    *p++ = conn_opts;

    rem_len--;
    
    if (!pkt_create(pkt_data, pkt_data_len, OP_KADEMLIAHEADER, KADEMLIA2_FIREWALLED_REQ, &kp)){

      LOG_ERROR("pkt_create failed.");

      break;

    }

    raw_pkt_len = pkt_length_with_header(kp);

    raw_pkt = mem_alloc(raw_pkt_len);

    if (!raw_pkt){

      LOG_ERROR("Failed to allocate memory for raw packet.");

      break;

    }

    if (!pkt_emit(kp, (uint8_t*)raw_pkt, raw_pkt_len, &bytes_emited)){

      LOG_ERROR("Failed to emit packet to buffer.");

      break;

    }

    *raw_pkt_out = raw_pkt;

    *raw_pkt_len_out = raw_pkt_len;

    result = true;

  } while (false);

  if (pkt_data) mem_free(pkt_data);

  if (kp) pkt_destroy(kp);

  if (!result && raw_pkt) mem_free(raw_pkt);

  return result;
}

bool
kadpkt_create_fw_check_udp(
                           bool already_known,
                           uint16_t port,
                           void** raw_pkt_out,
                           uint32_t* raw_pkt_len_out
                          )
{
  bool result = false;
  void* raw_pkt = NULL;
  uint32_t raw_pkt_len = 0;
  uint8_t* pkt_data = NULL;
  uint32_t pkt_data_len = 0;
  uint8_t* p = NULL;
  uint32_t rem_len = 0;
  uint32_t bytes_emited = 0;
  KAD_PACKET* kp = NULL;

  do {

    if (!raw_pkt_out || !raw_pkt_len_out) break;

    rem_len = pkt_data_len = sizeof(uint8_t) + // already known flag
                             sizeof(uint16_t); // udp port

    p = pkt_data = (uint8_t*)mem_alloc(pkt_data_len);

    if (!pkt_data){

      LOG_ERROR("Failed to allocate memory for packet data.");

      break;

    }

    // Already known flag
    
    *p++ = already_known?1:0;

    rem_len--;

    // Udp port
    
    *(uint16_t*)p = port;

    p += sizeof(uint16_t);

    rem_len -= sizeof(uint16_t);

    if (!pkt_create(pkt_data, pkt_data_len, OP_KADEMLIAHEADER, KADEMLIA2_FIREWALLUDP, &kp)){

      LOG_ERROR("pkt_create failed.");

      break;

    }

    raw_pkt_len = pkt_length_with_header(kp);

    raw_pkt = mem_alloc(raw_pkt_len);
    
    if (!raw_pkt){

      LOG_ERROR("Failed to allocate memory for raw packet.");

      break;

    }

    if (!pkt_emit(kp, (uint8_t*)raw_pkt, raw_pkt_len, &bytes_emited)){

      LOG_ERROR("Failed to emit packet to buffer.");

      break;

    }

    *raw_pkt_out = raw_pkt;

    *raw_pkt_len_out = raw_pkt_len;

    result = true;

  } while (false);

  if (pkt_data) mem_free(pkt_data);

  if (kp) pkt_destroy(kp);

  if (!result && raw_pkt) mem_free(raw_pkt);

  return result;
}

bool
kadpkt_create_search_source_resp(
                                 UINT128* file_id,
                                 int16_t src_cnt,
                                 LIST* cli_ids,
                                 LIST* lst_of_src_tag_lsts,
                                 void** raw_pkt_out,
                                 uint32_t* raw_pkt_len_out
                                )
{
  bool result = false;

  do {

    

    result = true;

  } while (false);

  return result;

}
