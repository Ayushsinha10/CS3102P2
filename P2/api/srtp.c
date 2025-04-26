/*
  CS3201 Coursework P2 : Simpler Reliable Transport Protocol (SRTP).
  saleem, Jan2024, Feb2023.
  checked March 2025 (sjm55)

  API for SRTP.

  Underneath, it MUST use UDP. 
*/

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <netdb.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/select.h>

#include "srtp.h"
#include "srtp-packet.h"
#include "srtp-common.h"
#include "srtp-fsm.h"
#include "srtp-pcb.h"

#include "byteorder64.h"
#include "d_print.h"

extern Srtp_Pcb_t G_pcb; /* in srtp-pcb.c */
static uint16_t bound_port = 0;
/*
  Must be called before any other srtp_zzz() API calls.

  For use by client and server process.
*/
void srtp_initialise() {
  reset_SrtpPcb();
  printf("SRTP protocol initialized.\n");
  // Add any additional initialization steps if necessary
}

int srtp_start(uint16_t port) {
  int server_fd;
  struct sockaddr_in server_addr;

  // Create a UDP socket
  server_fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (server_fd < 0) {
      perror("Socket creation failed");
      return SRTP_ERROR;
  }

  memset(&server_addr, 0, sizeof(server_addr));
  server_addr.sin_family = AF_INET;
  server_addr.sin_addr.s_addr = INADDR_ANY;  // Bind to any available interface
  server_addr.sin_port = htons(port);  // Use the provided port number

  // Bind the socket to the port
  if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
      perror("Bind failed");
      close(server_fd);
      return SRTP_ERROR;
  }

  // Store the bound port number for comparison in accept
  bound_port = port;

  printf("Server listening on port %d\n", port);
  return server_fd;  // Return the server socket descriptor
}

// Accept function to handle incoming connections and compare the port number
int srtp_accept(int sd) {
  struct sockaddr_in src_addr;
  socklen_t addr_len = sizeof(src_addr);
  char buffer[SRTP_MAX_DATA_SIZE];

  if (sd < 0) {
      return SRTP_ERROR_api;
  }

  // Wait for a packet (this is a non-blocking receive, adjust as needed)
  int received_bytes = srtp_rx(sd, buffer, sizeof(buffer));
  if (received_bytes < 0) {
      return SRTP_ERROR_data;
  }

  // Set remote address
  memcpy(&G_pcb.remote, &src_addr, sizeof(src_addr));

  // Handle the incoming packet with FSM logic
  Srtp_Packet_t packet;
  // Parse the packet based on the buffer contents (not shown in code here)
  parse_srtp_packet(&packet, buffer, received_bytes);

  // Handle the FSM transition based on packet type
  handle_srtp_fsm(&packet);

  return sd;
}

int srtp_open(const char *fqdn, uint16_t port) {
  int client_fd;
  struct sockaddr_in server_addr, client_addr;
  struct hostent *host;
  char *ip_address;

  // Resolve the hostname to an IP address
  host = gethostbyname(fqdn);
  if (host == NULL) {
      herror("gethostbyname failed");
      return SRTP_ERROR_api;
  }

  ip_address = inet_ntoa(*(struct in_addr*)host->h_addr_list[0]);
  printf("Resolved IP address for %s: %s\n", fqdn, ip_address);

  // Create a UDP socket for the client
  client_fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (client_fd < 0) {
      perror("Client socket creation failed");
      return SRTP_ERROR;
  }

  // Bind the client socket to the desired port
  memset(&client_addr, 0, sizeof(client_addr));
  client_addr.sin_family = AF_INET;
  client_addr.sin_addr.s_addr = INADDR_ANY;  // Bind to any available interface
  client_addr.sin_port = htons(port);  // Bind to the same port as the server

  if (bind(client_fd, (struct sockaddr *)&client_addr, sizeof(client_addr)) < 0) {
      perror("Client bind failed");
      close(client_fd);
      return SRTP_ERROR;
  }

  memset(&server_addr, 0, sizeof(server_addr));
  server_addr.sin_family = AF_INET;
  server_addr.sin_addr.s_addr = inet_addr(ip_address);  // Convert IP address to binary form
  server_addr.sin_port = htons(port);  // Set the destination port (server's port)

  // Store the server address in the PCB for the client
  memcpy(&G_pcb.remote, &server_addr, sizeof(server_addr));

  printf("Server address: %s:%d\n", ip_address, port);
  return client_fd;  // Return the socket descriptor
}

int srtp_tx(int sd, void *data, uint16_t data_size) {
  if (G_pcb.state != SRTP_state_connected) {
      printf("Error: Cannot send data, not in connected state.\n");
      return SRTP_state_error;
  }

  // Retrieve the remote address from the PCB
  struct sockaddr_in dest_addr;
  memcpy(&dest_addr, &G_pcb.remote, sizeof(dest_addr));

  // Send the data using sendto()
  int sent_bytes = sendto(sd, data, data_size, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
  if (sent_bytes < 0) {
      perror("Data transmission failed");
      return SRTP_ERROR_data;
  }

  return sent_bytes;  // Return the number of bytes sent
}

int srtp_rx(int sd, void *data, uint16_t data_size) {
  struct sockaddr_in src_addr;
  socklen_t addr_len = sizeof(src_addr);

  // Receive data
  int received_bytes = recvfrom(sd, data, data_size, 0, (struct sockaddr *)&src_addr, &addr_len);
  if (received_bytes < 0) {
      perror("Data reception failed");
      return SRTP_ERROR_data;
  }

  // Update remote address with the sender's address
  memcpy(&G_pcb.remote, &src_addr, sizeof(src_addr));

  // Handle the received packet
  Srtp_Packet_t packet;
  parse_srtp_packet(&packet, data, received_bytes);

  // Process the packet with FSM logic
  handle_srtp_fsm(&packet);

  return received_bytes;  // Return the number of bytes received
}


int srtp_close(int sd) {
  if (sd < 0) {
      return SRTP_ERROR_closed;
  }

  // Close the socket
  if (close(sd) < 0) {
      perror("Socket close failed");
      return SRTP_ERROR;
  }
  return SRTP_SUCCESS;  // Return success if everything was closed properly
}
