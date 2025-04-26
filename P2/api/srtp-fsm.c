#include <stdio.h>      // Include for printf
#include "srtp-fsm.h"
#include "srtp-pcb.h"
#include "srtp-packet.h"
#include "srtp.h"

// Declare the SRTP_STATE_STR function (if it doesn't already exist)
const char* SRTP_STATE_STR(SRTP_state_t state) {
    switch (state) {
        case SRTP_state_listening: return "listening";
        case SRTP_state_opening:   return "opening";
        case SRTP_state_connected: return "connected";
        case SRTP_state_closing_i: return "closing_i";
        case SRTP_state_closed:    return "closed";
        default: return "unknown";
    }
}

Srtp_Pcb_t G_pcb;

/* Function declarations */
static void transition_to(SRTP_state_t new_state);
static void handle_open_request(Srtp_Packet_t *packet);
static void handle_open_ack(Srtp_Packet_t *packet);
static void handle_data_request(Srtp_Packet_t *packet);
static void handle_data_ack(Srtp_Packet_t *packet);
static void handle_close_request(Srtp_Packet_t *packet);
static void handle_close_ack(Srtp_Packet_t *packet);
static void send_packet(Srtp_Packet_t *packet);

uint32_t calculate_checksum(Srtp_Packet_t *packet) {
  uint32_t checksum = 0;
  size_t total_size = sizeof(Srtp_Header_t) + packet->header.data_size;

  // Sum all bytes in header and data
  for (size_t i = 0; i < total_size; i++) {
    checksum += ((uint8_t*)packet)[i];
  }
  return checksum;
}

/* Function to set header values for an SRTP packet */
void set_srtp_header(Srtp_Header_t *header, uint8_t type, uint8_t seq_num, uint8_t ack_num, uint16_t data_size) {
  header->type = type;
  header->seq_num = seq_num;
  header->ack_num = ack_num;
  header->data_size = data_size;
  header->checksum = 0;  // Will be calculated later
}

/* Function to initialize the packet */
void init_srtp_packet(Srtp_Packet_t *packet, uint8_t type, uint8_t seq_num, uint8_t ack_num, uint16_t data_size, uint8_t *data) {
  set_srtp_header(&packet->header, type, seq_num, ack_num, data_size);

  // Copy data into the packet payload
  memcpy(packet->data, data, data_size);

  // Calculate checksum
  packet->header.checksum = calculate_checksum(packet);
}
void parse_srtp_packet(Srtp_Packet_t *packet, const void *data, uint16_t size) {
  // Example of parsing a packet (actual implementation will depend on packet format)
  // Ensure that the packet is properly initialized with the relevant fields
  memcpy(&packet->header, data, sizeof(packet->header));  // Copy the header
  memcpy(packet->data, (uint8_t *)data + sizeof(packet->header), size - sizeof(packet->header));  // Copy the data
}

/* Transition function: Changes the state of the connection */
static void transition_to(SRTP_state_t new_state) {
  if (G_pcb.state != new_state) {
    printf("Transitioning from %s to %s\n", SRTP_STATE_STR(G_pcb.state), SRTP_STATE_STR(new_state));
    G_pcb.state = new_state;
  }
}

/* Handle Open Request packet */
static void handle_open_request(Srtp_Packet_t *packet) {
  if (G_pcb.state == SRTP_state_listening) {
    // Respond with an open acknowledgment
    Srtp_Packet_t response;
    init_srtp_packet(&response, SRTP_TYPE_open_ack, 0, packet->header.seq_num, 0, 0);
    send_packet(&response);
    transition_to(SRTP_state_opening);
  } else {
    // Invalid state to receive open request
    printf("Error: Unexpected open request in state %s\n", SRTP_STATE_STR(G_pcb.state));
  }
}

/* Handle Open Acknowledgment packet */
static void handle_open_ack(Srtp_Packet_t *packet) {
  if (G_pcb.state == SRTP_state_opening) {
    // Open acknowledgment received, move to connected state
    transition_to(SRTP_state_connected);
  } else {
    // Invalid state to receive open acknowledgment
    printf("Error: Unexpected open acknowledgment in state %s\n", SRTP_STATE_STR(G_pcb.state));
  }
}

/* Handle Data Request packet */
static void handle_data_request(Srtp_Packet_t *packet) {
  if (G_pcb.state == SRTP_state_connected) {
    // Process data request and send acknowledgment
    Srtp_Packet_t response;
    init_srtp_packet(&response, SRTP_TYPE_data_ack, packet->header.seq_num, 0, 0, 0);
    send_packet(&response);

    // Continue handling data transfer (optional, depending on your application)
  } else {
    // Invalid state to receive data request
    printf("Error: Unexpected data request in state %s\n", SRTP_STATE_STR(G_pcb.state));
  }
}

/* Handle Data Acknowledgment packet */
static void handle_data_ack(Srtp_Packet_t *packet) {
  if (G_pcb.state == SRTP_state_connected) {
    // Acknowledge the data transfer and potentially update state
    printf("Data acknowledgment received, processing...\n");
  } else {
    // Invalid state to receive data acknowledgment
    printf("Error: Unexpected data acknowledgment in state %s\n", SRTP_STATE_STR(G_pcb.state));
  }
}

/* Handle Close Request packet */
static void handle_close_request(Srtp_Packet_t *packet) {
  if (G_pcb.state == SRTP_state_connected) {
    // Send close acknowledgment and move to closing state
    Srtp_Packet_t response;
    init_srtp_packet(&response, SRTP_TYPE_close_ack, 0, packet->header.seq_num, 0, 0);
    send_packet(&response);
    transition_to(SRTP_state_closing_i);
  } else {
    // Invalid state to receive close request
    printf("Error: Unexpected close request in state %s\n", SRTP_STATE_STR(G_pcb.state));
  }
}

/* Handle Close Acknowledgment packet */
static void handle_close_ack(Srtp_Packet_t *packet) {
  if (G_pcb.state == SRTP_state_closing_i) {
    // Connection has been closed, move to closed state
    transition_to(SRTP_state_closed);
  } else {
    // Invalid state to receive close acknowledgment
    printf("Error: Unexpected close acknowledgment in state %s\n", SRTP_STATE_STR(G_pcb.state));
  }
}

/* Send a packet over the network (stub function, implementation may vary) */
static void send_packet(Srtp_Packet_t *packet) {
  // In a real implementation, this function would send the packet via UDP or another transport layer
  printf("Sending packet: Type = %d, Seq = %d, Ack = %d\n", packet->header.type, packet->header.seq_num, packet->header.ack_num);
}

/* Main FSM function to handle incoming packets and trigger transitions */
void handle_srtp_fsm(Srtp_Packet_t *packet) {
  switch (packet->header.type) {
    case SRTP_TYPE_open_req:
      handle_open_request(packet);
      break;

    case SRTP_TYPE_open_ack:
      handle_open_ack(packet);
      break;

    case SRTP_TYPE_data_req:
      handle_data_request(packet);
      break;

    case SRTP_TYPE_data_ack:
      handle_data_ack(packet);
      break;

    case SRTP_TYPE_close_req:
      handle_close_request(packet);
      break;

    case SRTP_TYPE_close_ack:
      handle_close_ack(packet);
      break;

    default:
      printf("Error: Unknown packet type %d\n", packet->header.type);
      break;
  }
}
