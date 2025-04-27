#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <netdb.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <time.h> 

#include "srtp.h"
#include "srtp-packet.h"
#include "srtp-common.h"
#include "srtp-fsm.h"
#include "srtp-pcb.h"

#include "byteorder64.h"
#include "d_print.h"

int g_drop_rate_percent = 0;
extern Srtp_Pcb_t G_pcb; /* in srtp-pcb.c */

/* CS3201 Coursework P2: Simpler Reliable Transport Protocol (SRTP) */

/* Helper function to retrieve the local port */
const char* srtp_state_to_string(SRTP_state_t state) {
    switch (state) {
        case SRTP_state_listening: return "LISTENING";
        case SRTP_state_opening:   return "OPENING";
        case SRTP_state_connected: return "CONNECTED";
        case SRTP_state_closing_i: return "CLOSING_I";
        case SRTP_state_closing_r: return "CLOSING_R";
        case SRTP_state_closed:    return "CLOSED";
        case SRTP_state_error:     return "ERROR";
        default:                   return "UNKNOWN";
    }
}

/* Initialization of SRTP - called at the beginning */
void srtp_initialise() {
    reset_SrtpPcb();
    srandom(time(NULL) ^ getpid());
}
int packet_drop() {
    if (g_drop_rate_percent <= 0) return 0; // no drop if disabled

    if ((random() % 100) < g_drop_rate_percent)
        return 1; // drop the packet
    else
        return 0; // send normally
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
    G_pcb.port = port;
    G_pcb.local = server_addr;
    G_pcb.sd = sd;
    G_pcb.state = SRTP_state_listening; // Important!

    return sd;
}
/* Server side - Accept incoming connections */
int srtp_accept(int sd) {
    if(G_pcb.state == SRTP_state_error){
        return SRTP_ERROR_fsm;
    }

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

    G_pcb.state = handle_state_transition(G_pcb.state, packet.header.packet_type);

    // Respond with open_ack if in 'opening' state
    if (G_pcb.state == SRTP_state_opening) {
        // Server needs to reply with open_ack
        Srtp_Packet_t open_ack;
        memset(&open_ack, 0, sizeof(open_ack));

        open_ack.header.packet_type = SRTP_TYPE_open_ack;
        open_ack.header.seq_num = packet.header.seq_num;
        open_ack.header.ack_num = packet.header.seq_num + 1;
        open_ack.header.payload_len = 0;
        open_ack.header.checksum = 0;

        // Send open_ack back to the client
        if (sendto(sd, &open_ack, sizeof(Srtp_Header_t) + open_ack.header.payload_len, 0,
                   (struct sockaddr*)&client_addr, addrlen) < 0) {
            perror("sendto");
            return SRTP_ERROR;
        }

        printf("Sent open_ack\n");

        // After sending open_ack, transition to connected
        G_pcb.state = handle_state_transition(G_pcb.state, open_ack.header.packet_type);
        
    }

    // Update the remote address information
    memcpy(&G_pcb.remote, &client_addr, sizeof(struct sockaddr_in));
    G_pcb.remote = client_addr;
    //G_pcb.remote.sin_port = htons(G_pcb.port);
    
    //G_pcb.state = handle_state_transition(G_pcb.state, SRTP_TYPE_open_ack);
    G_pcb.start_time = srtp_timestamp();

    return sd;
}

/* Client side - Open connection to a remote server */
int srtp_open(const char *fqdn, uint16_t port) {
    if(G_pcb.state == SRTP_state_error){
        return SRTP_ERROR_fsm;
    }

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
    struct sockaddr_in local_addr;
    memset(&local_addr, 0, sizeof(local_addr));
    local_addr.sin_family = AF_INET;
    local_addr.sin_addr.s_addr = INADDR_ANY; // Bind to any local IP
    local_addr.sin_port = htons(port); 
    G_pcb.local = local_addr;

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);  // Use the same port as the server

    if (bind(sd, (struct sockaddr*)&local_addr, sizeof(local_addr)) < 0) {
        perror("bind");
        close(sd);
        return SRTP_ERROR;
    }

    memcpy(&server_addr.sin_addr, host->h_addr_list[0], host->h_length);


    // Connect to the server
    if (connect(sd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("connect");
        close(sd);
        return SRTP_ERROR;
    }

    // Save the remote address and port in the global PCB
    G_pcb.port = port;
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
    if (send(sd, &open_req, sizeof(Srtp_Header_t) + open_req.header.payload_len, 0) < 0) {
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
   // G_pcb.state = SRTP_state_connected;
   G_pcb.state = handle_state_transition(G_pcb.state, SRTP_TYPE_open_ack);
   G_pcb.start_time = srtp_timestamp();




    return sd; // success
}


int srtp_tx(int sd, void *data, uint16_t data_size) {
    if (G_pcb.state != SRTP_state_connected) {
        printf(srtp_state_to_string(G_pcb.state));
        return SRTP_ERROR_api;
    }
    if(G_pcb.state == SRTP_state_error){
        return SRTP_ERROR_fsm;
    }

    Srtp_Packet_t packet;
    memset(&packet, 0, sizeof(packet));

    // Fill the packet
    //uint32_t my_seq = G_pcb.seq_tx + 1;
    G_pcb.seq_tx++;
    packet.header.packet_type = SRTP_TYPE_data_req;
    packet.header.seq_num = G_pcb.seq_tx;
    packet.header.ack_num = G_pcb.seq_rx;
    packet.header.payload_len = data_size;
    packet.header.checksum = 0;

    if (data_size > SRTP_MAX_PAYLOAD_SIZE) {
        printf("Error: Payload size too big\n");
        return SRTP_ERROR_data;
    }

    memcpy(packet.payload, data, data_size);

    // Set socket receive timeout
    struct timeval timeout;
    timeout.tv_sec = 0;
    timeout.tv_usec = SRTP_RTO_FIXED;  // 0.5 seconds

    if (setsockopt(sd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
        perror("setsockopt");
        return SRTP_ERROR;
    }

    int attempts = 0;

    while (attempts < SRTP_MAX_RE_TX) {
        uint64_t start = srtp_timestamp();
        if (packet_drop()) {
            printf("[DROP] Simulating outgoing packet loss!\n");
            attempts++;
            continue; // Pretend it was dropped
        }

        ssize_t sent = sendto(sd, &packet, sizeof(Srtp_Header_t)+data_size, 0,
        (struct sockaddr*)&G_pcb.remote, sizeof(G_pcb.remote));
        if (sent < 0) {
            perror("send");
            return SRTP_ERROR;
        }

        printf("Sent data_req (seq=%u), waiting for data_ack...\n", packet.header.seq_num);

        // Now wait for data_ack
        Srtp_Packet_t ack_packet;
        memset(&ack_packet, 0, sizeof(ack_packet));

        ssize_t n = recv(sd, &ack_packet, sizeof(ack_packet), 0);
        if (n < 0) {
            if (errno == EWOULDBLOCK || errno == EAGAIN) {
                printf("Timeout waiting for data_ack, retransmitting...\n");
                attempts++;
                continue; // Retry
            } else {
                perror("recv");
                return SRTP_ERROR;
            }
        }

        if (ack_packet.header.packet_type != SRTP_TYPE_data_ack) {
            printf("Unexpected packet type 0x%x\n", ack_packet.header.packet_type);
            return SRTP_ERROR_protocol;
        }
        

        if (ack_packet.header.ack_num != packet.header.seq_num) {
           printf("Data ack mismatch! Expected ack_num=%u, got ack_num=%u\n",
                   ack_packet.header.ack_num, packet.header.seq_num);
          return SRTP_ERROR_data;
        }

        printf("Received valid data_ack for seq=%u!\n", G_pcb.seq_tx);
        uint64_t end = srtp_timestamp();

        
      
        G_pcb.state = SRTP_state_connected;
        G_pcb.data_req_bytes_tx = G_pcb.data_req_bytes_tx + packet.header.payload_len;
        G_pcb.rtt = end - start;

        return data_size; // SUCCESS
    }

    printf("Failed to get data_ack after %d attempts\n", SRTP_MAX_RE_TX);
    return SRTP_ERROR_data; // Failure after retries
}


/* Receive data over UDP (synchronous) */

int srtp_rx(int sd, void *data, uint16_t data_size) {
    if (G_pcb.state != SRTP_state_connected) {
        printf("Error: Cannot receive, not in connected state.\n");
       return SRTP_ERROR_api;
    }
    if(G_pcb.state == SRTP_state_error){
        return SRTP_ERROR_fsm;
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
      //  return SRTP_ERROR_api;
    }

    printf("Received data_req with seq_num=%u\n", packet.header.seq_num);

    // Check payload length
    if (packet.header.payload_len > data_size) {
        printf("Error: Payload length %u exceeds buffer size %u\n", packet.header.payload_len, data_size);
        return SRTP_ERROR_data;
    }
     G_pcb.seq_rx++;

    // Copy payload into the user's buffer
    memcpy(data, packet.payload, packet.header.payload_len);

    // Now build a data_ack packet
    Srtp_Packet_t ack_packet;
    memset(&ack_packet, 0, sizeof(ack_packet));

    ack_packet.header.packet_type = SRTP_TYPE_data_ack;
    ack_packet.header.seq_num = G_pcb.seq_tx;
    ack_packet.header.ack_num = G_pcb.seq_rx;
    ack_packet.header.payload_len = 0;
    ack_packet.header.checksum = 0; // Optional checksum

   // struct sockaddr_in client_addr;
  //  socklen_t addrlen = sizeof(client_addr);

    // Send data_ack back
    ssize_t sent =  sendto(sd, &ack_packet, sizeof(Srtp_Header_t), 0,
    (struct sockaddr*)&G_pcb.remote, sizeof(G_pcb.remote));
    if (sent < 0) {
        perror("send");
        return SRTP_ERROR;
    }

    printf("Sent data_ack for seq_num=%u\n", packet.header.seq_num);
    G_pcb.state = SRTP_state_connected;


    G_pcb.data_req_bytes_rx = G_pcb.data_req_bytes_rx + packet.header.payload_len;
    return packet.header.payload_len; // Success: number of bytes received
}

int srtp_close(int sd) {
    if (G_pcb.state != SRTP_state_connected) {
        printf("Error: srtp_close() can only be called in CONNECTED state.\n");
        return SRTP_ERROR_api;
    }
    if(G_pcb.state == SRTP_state_error){
        return SRTP_ERROR_fsm;
    }


    // 1. Send close_req
    Srtp_Packet_t close_req;
    memset(&close_req, 0, sizeof(close_req));
    close_req.header.packet_type = SRTP_TYPE_close_req;
    close_req.header.seq_num = G_pcb.seq_tx;
    close_req.header.ack_num = G_pcb.seq_rx;
    close_req.header.payload_len = 0;
    close_req.header.checksum = 0;

    if (sendto(sd, &close_req, sizeof(Srtp_Header_t), 0,
               (struct sockaddr*)&G_pcb.remote, sizeof(G_pcb.remote)) < 0) {
        perror("sendto close_req");
        return SRTP_ERROR;
    }

    printf("[SRTP] Sent close_req.\n");

    // 2. Transition state to closing_i
    G_pcb.state = handle_state_transition(G_pcb.state, SRTP_TYPE_close_req);

    // 3. Wait for close_ack
    Srtp_Packet_t recv_packet;
    memset(&recv_packet, 0, sizeof(recv_packet));

    ssize_t n = recv(sd, &recv_packet, sizeof(recv_packet), 0);
    if (n < 0) {
        perror("recv close_ack");
        return SRTP_ERROR;
    }

    if (recv_packet.header.packet_type != SRTP_TYPE_close_req) {
        printf("[SRTP] Unexpected packet type 0x%x (expected close_ack).\n", recv_packet.header.packet_type);
        return SRTP_ERROR_protocol;
    }

    printf("[SRTP] Received close_req.\n");
    Srtp_Packet_t close_ack;
    memset(&close_ack, 0, sizeof(close_ack));
    close_ack.header.packet_type = SRTP_TYPE_close_ack;
    close_ack.header.seq_num = G_pcb.seq_tx;
    close_ack.header.ack_num = G_pcb.seq_rx;
    close_ack.header.payload_len = 0;
    close_ack.header.checksum = 0;
        if (sendto(sd, &close_ack, sizeof(Srtp_Header_t), 0,
               (struct sockaddr*)&G_pcb.remote, sizeof(G_pcb.remote)) < 0) {
        perror("sendto close_req");
        return SRTP_ERROR;
    }


    // 4. Transition state to closing_r
    G_pcb.state = handle_state_transition(G_pcb.state, SRTP_TYPE_close_ack);
    Srtp_Packet_t recv_packet2;
    memset(&recv_packet2, 0, sizeof(recv_packet2));

    ssize_t n2 = recv(sd, &recv_packet2, sizeof(recv_packet2), 0);
    if (n2 < 0) {
        perror("recv close_ack2222");
        return SRTP_ERROR;
    }

    if (recv_packet2.header.packet_type != SRTP_TYPE_close_ack) {
        printf("[SRTP] Unexpected packet type 0x%x (expected close_ack).\n", recv_packet2.header.packet_type);
        return SRTP_ERROR_protocol;
    }

    // 5. Transition to closed
    G_pcb.state = handle_state_transition(G_pcb.state, SRTP_TYPE_close_ack);
    G_pcb.finish_time = srtp_timestamp();


    // 6. Close socket
    if (close(sd) < 0) {
        perror("close socket");
        return SRTP_ERROR;
    }

    printf("[SRTP] Socket closed successfully.\n");
    return SRTP_SUCCESS;
}