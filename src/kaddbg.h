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

#ifdef CONFIG_VERBOSE

#define KADDBG_PRINT_KN kaddbg_print_kn

#define KADDBG_PRINT_QPKT kaddbg_print_qpkt

#else

#define KADDBG_PRINT_KN 

#define KADDBG_PRINT_QPKT

#endif


#endif // _KADDBG_H_
