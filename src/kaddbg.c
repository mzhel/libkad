#include <stdint.h>
#include <stdbool.h>
#include <memory.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <uint128.h>
#include <list.h>
#include <queue.h>
#include <node.h>
#include <nodelist.h>
#include <kbucket.h>
#include <routing.h>
#include <tag.h>
#include <protocols.h>
#include <packet.h>
#include <kadqpkt.h>
#include <kadfw.h>
#include <kadses.h>
#include <kadproto.h>
#include <kadsrch.h>
#include <kadpkt.h>
#include <kadhlp.h>
#include <kadfile.h>
#include <random.h>
#include <ticks.h>
#include <mem.h>
#include <log.h>
#include <kaddbg.h>

bool
kaddbg_print_kn(
                char* desc,
                KAD_NODE* kn
               )
{
  bool result = false;
  struct in_addr in;

  do {

    if (!kn) break;

    if (desc){

      LOG_DEBUG(desc);

    }

    LOG_DEBUG_UINT128("id:", ((UINT128*)&kn->id));

    in.s_addr = kn->ip4_no;

    LOG_DEBUG("ip4: %s", inet_ntoa(in));

    LOG_DEBUG("tcp_port: %.4d", ntohs(kn->tcp_port_no));

    LOG_DEBUG("udp_port: %.4d", ntohs(kn->udp_port_no));

    LOG_DEBUG_UINT128("dist:", ((UINT128*)&kn->dist));

    result = true;

  } while (false);

  return result;
}

bool
kaddbg_get_proto_string(
                        uint8_t proto,
                        char** str_out
                        )
{
  bool result = false;

  do {

    if (!str_out) break;

    switch (proto){

      case OP_UDPRESERVEDPROT1:

        *str_out = "OP_UDPRESERVEDPROT1";

      break;

      case OP_UDPRESERVEDPROT2:

        *str_out = "OP_UDPRESERVEDPROT2";

      break;

      case OP_EMULEPROT:

        *str_out = "OP_EMULEPROT";

      break;

      case OP_PACKEDPROT:

        *str_out = "OP_PACKEDPROT";

      break;

      case OP_EDONKEYHEADER:

        *str_out = "OP_EDONKEYHEADER";

      break;

      case OP_KADEMLIAHEADER:

        *str_out = "OP_KADEMLIAHEADER";

      break;

      case OP_KADEMLIAPACKEDPROT:

        *str_out = "OP_KADEMLIAPACKEDPROT";

      break;

      case OP_ED2KV2HEADER:

        *str_out = "OP_ED2KV2HEADER";

      break;

      default:

        *str_out = "UNKNOWN";

    }

    result = true;

  } while (false);

  return result;
}

#define SOUT(str) *str_out = str

bool
kaddbg_get_opcode_string(
                         uint8_t opcode,
                         char** str_out
                         )
{
  bool result = false;

  do {

    if (!str_out) break;

    switch (opcode) {

      case  KADEMLIA_BOOTSTRAP_REQ:

        *str_out = "KADEMLIA_BOOTSTRAP_REQ";

      break;

      case KADEMLIA2_BOOTSTRAP_REQ:

        *str_out = "KADEMLIA2_BOOTSTRAP_REQ";

      break;

      case KADEMLIA_BOOTSTRAP_RES:

        *str_out = "KADEMLIA_BOOTSTRAP_RES";

      break;

      case KADEMLIA2_BOOTSTRAP_RES:

        *str_out = "KADEMLIA2_BOOTSTRAP_RES";

      break;

      case KADEMLIA_HELLO_REQ:

        *str_out = "KADEMLIA_HELLO_REQ";

      break;

      case KADEMLIA2_HELLO_REQ:

        *str_out = "KADEMLIA2_HELLO_REQ";

      break;

      case KADEMLIA_HELLO_RES:

        SOUT("KADEMLIA_HELLO_RES");

      break;

      case KADEMLIA2_HELLO_RES:

        SOUT("KADEMLIA2_HELLO_RES");

      break;

      case KADEMLIA_REQ:

        SOUT("KADEMLIA_REQ");

      break;

      case KADEMLIA2_REQ:

        SOUT("KADEMLIA2_REQ");

      break;

      case KADEMLIA2_HELLO_RES_ACK:

        SOUT("KADEMLIA2_HELLO_RES_ACK");

      break;

      case KADEMLIA_RES:

        SOUT("KADEMLIA_RES");

      break;

      case KADEMLIA2_RES:

        SOUT("KADEMLIA2_RES");

      break;

      case KADEMLIA_SEARCH_REQ:

        SOUT("KADEMLIA_SEARCH_REQ");

      break;

      case KADEMLIA_SEARCH_NOTES_REQ:

        SOUT("KADEMLIA_SEARCH_NOTES_REQ");

      break;

      case KADEMLIA2_SEARCH_KEY_REQ:

        SOUT("KADEMLIA2_SEARCH_KEY_REQ");

      break;

      case KADEMLIA2_SEARCH_SOURCE_REQ:

        SOUT("KADEMLIA2_SEARCH_SOURCE_REQ");
  
      break;

      case KADEMLIA2_SEARCH_NOTES_REQ:

        SOUT("KADEMLIA2_SEARCH_NOTES_REQ");

      break;

      case KADEMLIA_SEARCH_NOTES_RES:

        SOUT("KADEMLIA_SEARCH_NOTES_RES");

      break;

      case KADEMLIA2_SEARCH_RES:

        SOUT("KADEMLIA2_SEARCH_RES");

      break;

      case KADEMLIA_PUBLISH_REQ:

        SOUT("KADMLIA_PUBLISH_REQ");

      break;

      case KADEMLIA_PUBLISH_NOTES_REQ:

        SOUT("KADEMLIA_PUBLISH_NOTES_REQ");

      break;

      case KADEMLIA2_PUBLISH_KEY_REQ:

        SOUT("KADEMLIA2_PUBLISH_KEY_REQ");

      break;

      case KADEMLIA2_PUBLISH_SOURCE_REQ:

        SOUT("KADEMLIA2_PUBLISH_SOURCE_REQ");

      break;

      case KADEMLIA2_PUBLISH_NOTES_REQ:

        SOUT("KADMLIA2_PUBLISH_NOTES_REQ");

      break;

      case KADEMLIA_PUBLISH_RES:

        SOUT("KADEMLIA_PUBLISH_RES");

      break;

      case KADEMLIA_PUBLISH_NOTES_RES:

        SOUT("KADEMLIA_PUBLISH_NOTES_RES");

      break;

      case KADEMLIA2_PUBLISH_RES:

        SOUT("KADEMLIA2_PUBLISH_RES");

      break;

      case KADEMLIA2_PUBLISH_RES_ACK:

        SOUT("KADEMLIA2_PUBLISH_RES_ACK");

      break;

      case KADEMLIA_FIREWALLED_REQ:

        SOUT("KADEMLIA_FIREWALLED_REQ");

      break;

      case KADEMLIA_FINDBUDDY_REQ:

        SOUT("KADEMLIA_FIND_BUDDY_REQ");

      break;
      
      case KADEMLIA_CALLBACK_REQ:

        SOUT("KADEMLIA_CALLBACK_REQ");

      break;

      case KADEMLIA2_FIREWALLED_REQ:

        SOUT("KADEMLIA2_FIREWALLED_REQ");

      break;

      case KADEMLIA_FIREWALLED_RES:

        SOUT("KADEMLIA_FIREWALLED_RES");

      break;

      case KADEMLIA_FIREWALLED_ACK_RES:

        SOUT("KADEMLIA_FIREWALLED_ACK_RES");

      break;

      case KADEMLIA_FINDBUDDY_RES:

        SOUT("KADEMLIA_FINDBUDDY_RES");

      break;

      case KADEMLIA2_PING:

        SOUT("KADEMLIA2_PING");

      break;

      case KADEMLIA2_PONG:

        SOUT("KADEMLIA2_PONG");

      break;

      case KADEMLIA2_FIREWALLUDP:

        SOUT("KADEMLIA2_FIREWALLUDP");

      break;

      default:

        SOUT("UNKNOWN");

    }

    result = true;

  } while (false);

  return result;
}

bool
kaddbg_print_qpkt(
                  char* desc,
                  KAD_QUEUED_PACKET* qpkt,
                  bool ctrl
                  )
{
  bool result = false;
  struct in_addr in;
  char* proto_str = NULL;
  char* opcode_str = NULL;

  do {

    if (!qpkt) break;

    if (desc) LOG_DEBUG(desc);

    in.s_addr = qpkt->ip4_no;

    LOG_DEBUG("ip4: %s", inet_ntoa(in));

    LOG_DEBUG("port: %.4d", ntohs(qpkt->port_no));

    LOG_DEBUG("ts: %.8x", qpkt->ts);

    LOG_DEBUG("encrypt: %s", (qpkt->encrypt?"true":"false"));

    LOG_DEBUG("rcvr_verify_key: %.8x", qpkt->recv_verify_key);

    LOG_DEBUG_UINT128("kad_id:", ((UINT128*)&qpkt->kad_id));

    LOG_DEBUG("pkt = %.8x", qpkt->pkt);

    LOG_DEBUG("pkt_len = %.8x", qpkt->pkt_len);

    if (qpkt->pkt){

      kaddbg_get_proto_string(qpkt->pkt[0], &proto_str);

      kaddbg_get_opcode_string(qpkt->pkt[1], &opcode_str);
      
      LOG_DEBUG("proto: %s (0x%.2x)", proto_str, qpkt->pkt[0]);

      if (ctrl) LOG_DEBUG("opcode: %s (0x%.2x)", opcode_str, qpkt->pkt[1]);

    }

    result = true;

  } while (false);

  return result;
}
