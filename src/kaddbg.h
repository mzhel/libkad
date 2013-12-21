#ifndef _KADDBG_H_
#define _KADDBG_H_

bool
kaddbg_print_kn(
                char* desc,
                KAD_NODE* kn
               );

bool
kaddbg_print_qpkt(
                  char* desc,
                  KAD_QUEUED_PACKET* qpkt,
                  bool ctrl
                  );

bool
kaddbg_print_packet_header(
                           uint8_t* pkt,
                           uint32_t pkt_len,
                           char* desc
                           );

#ifdef CONFIG_VERBOSE

#define KADDBG_PRINT_KN(desc, kn) kaddbg_print_kn(desc, kn)

#define KADDBG_PRINT_QPKT(desc, qpkt, ctrl) kaddbg_print_qpkt(desc, qpkt, ctrl)

#define KADDBG_PRINT_PACKET_HEADER(pkt, pkt_len, desc) kaddbg_print_packet_header(pkt, pkt_len, desc)

#else

#define KADDBG_PRINT_KN(desc, kn)

#define KADDBG_PRINT_QPKT(desc, qpkt, ctrl)

#define KADDBG_PRINT_PACKET_HEADER(pkt, pkt_len, desc)

#endif


#endif // _KADDBG_H_
