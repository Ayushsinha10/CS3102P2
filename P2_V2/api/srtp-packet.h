#ifndef __srtp_packet_h__
#define __srtp_packet_h__

/*
  CS3102 Coursework P2 : Simple, Reliable Transport Protocol (SRTP)
  saleem, Jan2024, Feb2023
  checked March 2025 (sjm55)

  These are suggested definitions only.
  Please modify as required.
*/

#include "srtp-common.h"

/* packet type values : bit field, but can be used as required */

#define SRTP_TYPE_req       ((uint8_t) 0x01)
#define SRTP_TYPE_ack       ((uint8_t) 0x02)

#define SRTP_TYPE_open      ((uint8_t) 0x10)
#define SRTP_TYPE_open_req  (SRTP_TYPE_open  | SRTP_TYPE_req)
#define SRTP_TYPE_open_ack  (SRTP_TYPE_open  | SRTP_TYPE_ack)

#define SRTP_TYPE_close     ((uint8_t) 0x20)
#define SRTP_TYPE_close_req (SRTP_TYPE_close | SRTP_TYPE_req)
#define SRTP_TYPE_close_ack (SRTP_TYPE_close | SRTP_TYPE_ack)

#define SRTP_TYPE_data      ((uint8_t) 0x40)
#define SRTP_TYPE_data_req  (SRTP_TYPE_data  | SRTP_TYPE_req)
#define SRTP_TYPE_data_ack  (SRTP_TYPE_data  | SRTP_TYPE_ack)


typedef struct Srtp_Header_s {
    uint8_t packet_type;  // SRTP packet type (open, close, data)
    uint16_t seq_num;     // Sequence number for data packets
    uint16_t ack_num;     // Acknowledgment number (for ack packets)
    uint16_t payload_len; // Length of the data in the payload
    uint8_t checksum;     // Simple checksum for error detection
} Srtp_Header_t;

#define SRTP_MAX_PAYLOAD_SIZE SRTP_MAX_DATA_SIZE

typedef struct Srtp_Packet_s {
  Srtp_Header_t header;  // Packet header
  uint8_t payload[SRTP_MAX_PAYLOAD_SIZE]; // Payload (data or empty for control packets)
} Srtp_Packet_t;


/* CS3012 : put in here whatever else you need */

#endif /* __srtp_packet_h__ */
