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
#include <stddef.h>  // For size_t
#include <string.h>  // For memcpy

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


#define SRTP_MAX_PAYLOAD_SIZE SRTP_MAX_DATA_SIZE

/* SRTP Header - Defines essential elements of each packet */
typedef struct Srtp_Header_s {
  uint8_t type;       // Type of packet (e.g., open, close, data, ack)
  uint8_t seq_num;    // Sequence number for reliable transmission
  uint8_t ack_num;    // Acknowledgment number (for receiving data)
  uint32_t checksum;  // Checksum for integrity check
  uint16_t data_size; // Size of the payload data
} Srtp_Header_t;

/* SRTP Packet - Contains the header and the data payload */
typedef struct Srtp_Packet_s {
  Srtp_Header_t header;  // Header of the packet
  uint8_t data[SRTP_MAX_PAYLOAD_SIZE];  // Data payload (variable size)
} Srtp_Packet_t;

/* Utility function to create a checksum (simple sum of bytes) */


#endif /* __srtp_packet_h__ */
