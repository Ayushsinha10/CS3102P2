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

/* CS3201 Coursework P2: Simpler Reliable Transport Protocol (SRTP) */

/* Helper function to retrieve the local port */


/* Initialization of SRTP - called at the beginning */
void srtp_initialise() {
    reset_SrtpPcb();
}

/* Server side - Start listening on the given port */
int srtp_start(uint16_t port) {
    int sd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sd < 0) {
        perror("socket");
        return SRTP_ERROR;
    }

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);

    if (bind(sd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind");
        close(sd);
        return SRTP_ERROR;
    }

    G_pcb.local = server_addr;
    G_pcb.sd = sd;
    G_pcb.state = SRTP_state_listening; // Important!

    return sd;
}
/* Server side - Accept incoming connections */
int srtp_accept(int sd) {
    Srtp_Packet_t packet;
    memset(&packet, 0, sizeof(packet));
    
    struct sockaddr_in client_addr;
    socklen_t addrlen = sizeof(client_addr);

    // Block until receive
    ssize_t n = recvfrom(sd, &packet, sizeof(packet), 0,
                         (struct sockaddr*)&client_addr, &addrlen);
    if (n < 0) {
        perror("recvfrom");
        return SRTP_ERROR;
    }

    uint8_t event = packet.header.packet_type;
    printf("Received packet of type 0x%x\n", event);

    // Use FSM to decide
    SRTP_state_t new_state = handle_state_transition(G_pcb.state, event);
    if (new_state == SRTP_state_error) {
        printf("Invalid FSM transition\n");
        return SRTP_ERROR_fsm;
    }

    G_pcb.state = new_state;

    if (G_pcb.state == SRTP_state_opening) {
        // Server needs to reply with open_ack
        Srtp_Packet_t open_ack;
        memset(&open_ack, 0, sizeof(open_ack));

        open_ack.header.packet_type = SRTP_TYPE_open_ack;
        open_ack.header.seq_num = packet.header.seq_num;
        open_ack.header.ack_num = packet.header.seq_num + 1;
        open_ack.header.payload_len = 0;
        open_ack.header.checksum = 0;

        if (sendto(sd, &open_ack, sizeof(Srtp_Header_t), 0,
                   (struct sockaddr*)&client_addr, addrlen) < 0) {
            perror("sendto");
            return SRTP_ERROR;
        }

        printf("Sent open_ack\n");

        // After sending open_ack, transition to connected
   
    }

    memcpy(&G_pcb.remote, &client_addr, sizeof(struct sockaddr_in));
    return sd;
}

/* Client side - Open connection to a remote server */
int srtp_open(const char *fqdn, uint16_t port) {
    int sd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sd < 0) {
        perror("socket");
        return SRTP_ERROR;
    }

    struct sockaddr_in server_addr;
    struct hostent *host = gethostbyname(fqdn);
    if (!host) {
        perror("gethostbyname");
        close(sd);
        return SRTP_ERROR;
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    memcpy(&server_addr.sin_addr, host->h_addr, host->h_length);

    if (connect(sd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("connect");
        close(sd);
        return SRTP_ERROR;
    }

    G_pcb.remote = server_addr;
    G_pcb.sd = sd;
    G_pcb.state = SRTP_state_opening;

    // Build open_req packet
    Srtp_Packet_t open_req;
    memset(&open_req, 0, sizeof(open_req));
    open_req.header.packet_type = SRTP_TYPE_open_req;
    open_req.header.seq_num = 1;
    open_req.header.ack_num = 1;
    open_req.header.payload_len = 0;
    open_req.header.checksum = 0; // checksum can be computed if needed

    // Send open_req
    if (send(sd, &open_req, sizeof(Srtp_Header_t), 0) < 0) {
        perror("send");
        close(sd);
        return SRTP_ERROR;
    }

    printf("open_req sent, now waiting for open_ack...\n");

    // Now block and wait for open_ack
    Srtp_Packet_t recv_packet;
    memset(&recv_packet, 0, sizeof(recv_packet));

    ssize_t n = recv(sd, &recv_packet, sizeof(recv_packet), 0);
    if (n < 0) {
        perror("recv");
        close(sd);
        return SRTP_ERROR;
    }

    if (recv_packet.header.packet_type != SRTP_TYPE_open_ack) {
        printf("Unexpected packet type 0x%x\n", recv_packet.header.packet_type);
        close(sd);
        return SRTP_ERROR_protocol;
    }

    printf("Received open_ack, connection established!\n");

    // Now transition to connected state using FSM
    SRTP_state_t new_state = handle_state_transition(G_pcb.state, SRTP_TYPE_open_ack);
    if (new_state == SRTP_state_error) {
        printf("FSM error after open_ack\n");
        close(sd);
        return SRTP_ERROR_fsm;
    }
    G_pcb.state = new_state;

    return sd; // success
}


int srtp_tx(int sd, void *data, uint16_t data_size) {
    if (G_pcb.state != SRTP_state_connected) {
        printf("Error: Cannot transmit, not in connected state.\n");
        return SRTP_ERROR_api;
    }

    Srtp_Packet_t packet;
    memset(&packet, 0, sizeof(packet));

    // Fill packet
    packet.header.packet_type = SRTP_TYPE_data_req;
    packet.header.seq_num = G_pcb.seq_tx + 1;
    packet.header.ack_num = G_pcb.seq_rx;
    packet.header.payload_len = data_size;
    packet.header.checksum = 0;  // Optional: you can calculate real checksum if you want

    if (data_size > SRTP_MAX_PAYLOAD_SIZE) {
        printf("Error: Payload size too big\n");
        return SRTP_ERROR_data;
    }

    memcpy(packet.payload, data, data_size);

    int attempts = 0;

    while (attempts < SRTP_MAX_RE_TX) {
        // Send the packet
        ssize_t sent = send(sd, &packet, sizeof(Srtp_Header_t) + data_size, 0);
        if (sent < 0) {
            perror("send");
            return SRTP_ERROR;
        }

        printf("Sent data_req (seq=%u), waiting for data_ack...\n", packet.header.seq_num);

        // Now wait for ack
        fd_set readfds;
        struct timeval timeout;

        FD_ZERO(&readfds);
        FD_SET(sd, &readfds);

        timeout.tv_sec = 0;
        timeout.tv_usec = SRTP_RTO_FIXED; // 500 ms timeout

        int ready = select(sd + 1, &readfds, NULL, NULL, &timeout);

        if (ready < 0) {
            perror("select");
            return SRTP_ERROR;
        } else if (ready == 0) {
            // Timeout
            printf("Timeout waiting for data_ack, retransmitting...\n");
            attempts++;
            continue;  // Resend
        } else {
            // Something to read
            Srtp_Packet_t ack_packet;
            memset(&ack_packet, 0, sizeof(ack_packet));

            ssize_t n = recv(sd, &ack_packet, sizeof(ack_packet), 0);
            if (n < 0) {
                perror("recv");
                return SRTP_ERROR;
            }

            if (ack_packet.header.packet_type != SRTP_TYPE_data_ack) {
                printf("Unexpected packet type 0x%x\n", ack_packet.header.packet_type);
                return SRTP_ERROR_protocol;
            }

            // Check if ack matches our packet
            if (ack_packet.header.ack_num != G_pcb.seq_tx + 1) {
                printf("Data ack mismatch! Expected ack_num=%u, got ack_num=%u\n",
                       G_pcb.seq_tx + 1, ack_packet.header.ack_num);
                return SRTP_ERROR_data;
            }

            printf("Received valid data_ack for seq=%u!\n", G_pcb.seq_tx);

            // Success: move seq_tx forward
            G_pcb.seq_tx++;
            G_pcb.seq_rx++;

            return data_size;  // Success: all bytes transmitted
        }
    }

    printf("Failed to get data_ack after %d attempts\n", SRTP_MAX_RE_TX);
    return SRTP_ERROR_data;  // After max retransmissions
}


/* Receive data over UDP (synchronous) */

int srtp_rx(int sd, void *data, uint16_t data_size) {
    if (G_pcb.state != SRTP_state_connected) {
        printf("Error: Cannot receive, not in connected state.\n");
        return SRTP_ERROR_api;
    }

    Srtp_Packet_t packet;
    memset(&packet, 0, sizeof(packet));

    // Wait and receive incoming packet
    ssize_t n = recv(sd, &packet, sizeof(packet), 0);
    if (n < 0) {
        perror("recv");
        return SRTP_ERROR;
    }

    // Check if the packet is a data_req
    if (packet.header.packet_type != SRTP_TYPE_data_req) {
        printf("Error: Unexpected packet type 0x%x (expected data_req)\n", packet.header.packet_type);
        return SRTP_ERROR_api;
    }

    printf("Received data_req with seq_num=%u\n", packet.header.seq_num);

    // Check payload length
    if (packet.header.payload_len > data_size) {
        printf("Error: Payload length %u exceeds buffer size %u\n", packet.header.payload_len, data_size);
        return SRTP_ERROR_data;
    }

    // Copy payload into the user's buffer
    memcpy(data, packet.payload, packet.header.payload_len);

    // Now build a data_ack packet
    Srtp_Packet_t ack_packet;
    memset(&ack_packet, 0, sizeof(ack_packet));

    ack_packet.header.packet_type = SRTP_TYPE_data_ack;
    ack_packet.header.seq_num = packet.header.seq_num;
    ack_packet.header.ack_num = packet.header.seq_num + 1;
    ack_packet.header.payload_len = 0;
    ack_packet.header.checksum = 0; // Optional checksum

    // Send data_ack back
    ssize_t sent = send(sd, &ack_packet, sizeof(Srtp_Header_t), 0);
    if (sent < 0) {
        perror("send");
        return SRTP_ERROR;
    }

    printf("Sent data_ack for seq_num=%u\n", packet.header.seq_num);

    // Update expected next sequence number
  //  G_pcb.seq_rx = packet.header.seq_num + 1;

    return packet.header.payload_len; // Success: number of bytes received
}

int srtp_close(int sd) {
    if (G_pcb.state == SRTP_state_connected) {
        printf("[SRTP] In CONNECTED state: sending close_req.\n");

        // Build and send close_req
        Srtp_Packet_t close_req;
        memset(&close_req, 0, sizeof(close_req));
        close_req.header.packet_type = SRTP_TYPE_close_req;
        close_req.header.seq_num = G_pcb.seq_tx;
        close_req.header.ack_num = G_pcb.seq_rx;
        close_req.header.payload_len = 0;
        close_req.header.checksum = 0;

        if (send(sd, &close_req, sizeof(Srtp_Header_t), 0) < 0) {
            perror("send close_req");
            return SRTP_ERROR;
        }
        printf("[SRTP] Sent close_req packet.\n");

        // Update FSM: move to closing_i
        SRTP_state_t new_state = handle_state_transition(G_pcb.state, SRTP_TYPE_close_req);
        if (new_state == SRTP_state_error) {
            printf("[SRTP] FSM error after sending close_req.\n");
            return SRTP_ERROR_fsm;
        }
        G_pcb.state = new_state;

        // Now wait for close_ack
        Srtp_Packet_t packet;
        memset(&packet, 0, sizeof(packet));

        ssize_t n = recv(sd, &packet, sizeof(packet), 0);
        if (n < 0) {
            perror("recv");
            return SRTP_ERROR;
        }

        if (packet.header.packet_type != SRTP_TYPE_close_ack) {
            printf("[SRTP] Unexpected packet type 0x%x, expected close_ack.\n", packet.header.packet_type);
            return SRTP_ERROR_protocol;
        }

        printf("[SRTP] Received close_ack.\n");

        // Update FSM: closing_r -> closed
        new_state = handle_state_transition(G_pcb.state, SRTP_TYPE_close_ack);
        if (new_state == SRTP_state_error) {
            printf("[SRTP] FSM error after receiving close_ack.\n");
            return SRTP_ERROR_fsm;
        }
        G_pcb.state = new_state;

        new_state = handle_state_transition(G_pcb.state, SRTP_TYPE_close_ack);
        if (new_state == SRTP_state_error) {
            printf("[SRTP] FSM error after final close_ack transition.\n");
            return SRTP_ERROR_fsm;
        }
        G_pcb.state = new_state;

        // Now socket can be closed
        if (close(sd) < 0) {
            perror("close");
            return SRTP_ERROR;
        }

        printf("[SRTP] Socket closed successfully.\n");
        return SRTP_SUCCESS;
    }
    else if (G_pcb.state == SRTP_state_closing_i) {
        printf("[SRTP] In CLOSING_I state: waiting for close_req from peer.\n");

        // Just wait for the peer's close_req
        Srtp_Packet_t packet;
        memset(&packet, 0, sizeof(packet));

        ssize_t n = recv(sd, &packet, sizeof(packet), 0);
        if (n < 0) {
            perror("recv");
            return SRTP_ERROR;
        }

        if (packet.header.packet_type != SRTP_TYPE_close_req) {
            printf("[SRTP] Unexpected packet type 0x%x, expected close_req.\n", packet.header.packet_type);
            return SRTP_ERROR_protocol;
        }

        printf("[SRTP] Received close_req, replying with close_ack.\n");

        // Build and send close_ack
        Srtp_Packet_t close_ack;
        memset(&close_ack, 0, sizeof(close_ack));
        close_ack.header.packet_type = SRTP_TYPE_close_ack;
        close_ack.header.seq_num = G_pcb.seq_tx;
        close_ack.header.ack_num = G_pcb.seq_rx;
        close_ack.header.payload_len = 0;
        close_ack.header.checksum = 0;

        if (send(sd, &close_ack, sizeof(Srtp_Header_t), 0) < 0) {
            perror("send close_ack");
            return SRTP_ERROR;
        }
        printf("[SRTP] Sent close_ack in response.\n");

        // Update FSM: closing_i -> closing_r -> closed
        SRTP_state_t new_state = handle_state_transition(G_pcb.state, SRTP_TYPE_close_ack);
        if (new_state == SRTP_state_error) {
            printf("[SRTP] FSM error after sending close_ack.\n");
            return SRTP_ERROR_fsm;
        }
        G_pcb.state = new_state;

        new_state = handle_state_transition(G_pcb.state, SRTP_TYPE_close_ack);
        if (new_state == SRTP_state_error) {
            printf("[SRTP] FSM error after final close_ack transition.\n");
            return SRTP_ERROR_fsm;
        }
        G_pcb.state = new_state;

        // Now socket can be closed
        if (close(sd) < 0) {
            perror("close");
            return SRTP_ERROR;
        }

        printf("[SRTP] Socket closed successfully after responding.\n");
        return SRTP_SUCCESS;
    }
    else {
        printf("[SRTP] Error: Cannot close from state %d\n", G_pcb.state);
        return SRTP_ERROR_api;
    }
}