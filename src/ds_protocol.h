#ifndef DSM_PROTOCOL_H
#define DSM_PROTOCOL_H
#include <stdint.h>

#define N_PAGES 16
#define PAGE_SIZE 4096

typedef enum { ST_INVALID=0, ST_READ, ST_OWNER } page_state_t;

enum {
    MSG_REQ_READ = 1,
    MSG_REQ_EXCL = 2,
    MSG_SEND_PAGE = 3,
    MSG_INVALIDATE = 4,
    MSG_INVAL_ACK = 5
};

struct msg_hdr { uint8_t type; uint8_t page_idx; };

#endif
