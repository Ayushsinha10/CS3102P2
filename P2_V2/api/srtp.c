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
static int adaptive_rto_enabled = 1;
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
    if (G_pcb.state != SRTP_state_connected)     return SRTP_ERROR_api;
    if (data_size > SRTP_MAX_PAYLOAD_SIZE)       return SRTP_ERROR_data;

    // give send() calls a 500ms recv‐timeout so we can retry
    struct timeval tv = { 0, SRTP_RTO_FIXED };
    if(!adaptive_rto_enabled){
    setsockopt(sd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    }

    // our “next” sequence is old seq_tx + 1, modulo 2^16
    uint16_t seq = (uint16_t)(G_pcb.seq_tx + 1);
    uint64_t start = srtp_timestamp();
    static uint64_t rtt_estimated = 0;
    static uint64_t rtt_dev = 0;

    for (int attempt = 0; attempt < SRTP_MAX_RE_TX; ++attempt) {
        // build the packet
        Srtp_Packet_t pkt;
        memset(&pkt,0,sizeof(pkt));
        pkt.header.packet_type = SRTP_TYPE_data_req;
        pkt.header.seq_num      = seq;
        pkt.header.ack_num      = (uint16_t)G_pcb.seq_rx;
        pkt.header.payload_len  = data_size;
        pkt.header.checksum     = 0;               // optional
        memcpy(pkt.payload, data, data_size);

        // simulate loss
        if (packet_drop()) {
            printf("[DROP] data_req(seq=%u)\n", seq);
        } else {
            
            sendto(sd, &pkt,
                   sizeof(Srtp_Header_t) + data_size,
                   0,
                  (struct sockaddr*)&G_pcb.remote,
                  sizeof(G_pcb.remote));
        }

        // wait for an ACK
        Srtp_Packet_t ack;
        ssize_t n = recv(sd, &ack, sizeof(ack), 0);
        if (n < 0) {
            // timeout or other recv error
            if (errno == EWOULDBLOCK || errno == EAGAIN) {
                printf("timeout, retransmitting seq=%u\n", seq);
                continue;
            }
            perror("recv");
            return SRTP_ERROR;
        }

        // only DATA_ACK with matching ack_num lets us advance
        if (ack.header.packet_type  != SRTP_TYPE_data_ack ||
            ack.header.ack_num       != seq)
        {
            printf("got pkt type=0x%x ack_num=%u (want %u), retrying\n",
                   ack.header.packet_type,
                   ack.header.ack_num,
                   seq);
            continue;
        }

        // success!
        uint64_t end = srtp_timestamp();
        G_pcb.seq_tx = seq;
        G_pcb.data_req_bytes_tx += data_size;
        G_pcb.rtt = end - start;   /* your start timestamp if you stored it */
        if(adaptive_rto_enabled){
        uint64_t rtt = G_pcb.rtt;
        uint64_t rtt_diff = (rtt > rtt_estimated) ? (rtt - rtt_estimated) : (rtt_estimated - rtt);
        rtt_estimated = (rtt_estimated * 7 + rtt) / 8;
        rtt_dev = (rtt_dev * 7 + rtt_diff) / 8;

        uint64_t adaptive_rto = rtt_estimated + 4 * rtt_dev;

        // If adaptive RTO is greater than 0, use it; otherwise, use the fixed RTO
        if (adaptive_rto > 0) {
            tv.tv_usec = adaptive_rto;  // Set adaptive timeout based on RTT
        } else {
            tv.tv_usec = SRTP_RTO_FIXED;  // Use fixed timeout if adaptive RTO is 0
        }

        setsockopt(sd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        }
        return data_size;
    }

    // out of retries
    printf("srtp_tx: giving up on seq=%u\n", seq);
    G_pcb.state = SRTP_state_error;

    // Close the socket immediately
    if (close(sd) < 0) {
        perror("Failed to close socket");
        return SRTP_ERROR;
    }

    printf("Connection forcefully closed. State set to SRTP_state_error.\n");
    return SRTP_ERROR_data;
}

int srtp_rx(int sd, void *data, uint16_t data_size) {
    if (G_pcb.state != SRTP_state_connected)   return SRTP_ERROR_api;
    struct timeval timeout;
    timeout.tv_sec = 1;  // Wait for 2 seconds
    timeout.tv_usec = 500000; // No microsecond precision

    while (1) {
        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(sd, &read_fds);
        int select_result = select(sd + 1, &read_fds, NULL, NULL, &timeout);
        if (select_result == 0) {
            // Timeout has occurred, no data received within 2 seconds
            printf("Timeout waiting for data, closing connection...\n");
            G_pcb.state = SRTP_state_error;

            // Close the socket immediately
            if (close(sd) < 0) {
                perror("Failed to close socket");
                return SRTP_ERROR;
            }
        
            printf("Connection forcefully closed. State set to SRTP_state_error.\n");
            return SRTP_ERROR_data;
        }

        if (select_result < 0) {
            perror("select error");
            return SRTP_ERROR;
        }
        Srtp_Packet_t pkt;
        ssize_t n = recv(sd, &pkt, sizeof(pkt), 0);
        if (n < 0) {
            perror("recv");
            return SRTP_ERROR;
        }

        if (pkt.header.packet_type != SRTP_TYPE_data_req)
            continue;  // ignore anything else

        uint16_t expected = (uint16_t)(G_pcb.seq_rx + 1);

        if (pkt.header.seq_num == expected) {
            // — in‐order packet —
            if (pkt.header.payload_len > data_size)
                return SRTP_ERROR_data;
            memcpy(data, pkt.payload, pkt.header.payload_len);
            G_pcb.seq_rx = expected;
            G_pcb.data_req_bytes_rx += pkt.header.payload_len;

            // send ACK for this new packet
            Srtp_Packet_t ack = {0};
            ack.header.packet_type = SRTP_TYPE_data_ack;
            ack.header.seq_num     = expected;
            ack.header.ack_num     = expected;
            sendto(sd, &ack, sizeof(Srtp_Header_t), 0,
                   (struct sockaddr*)&G_pcb.remote, sizeof(G_pcb.remote));

            return pkt.header.payload_len;
        }
        else if ((int16_t)(pkt.header.seq_num - expected) < 0) {
            // — duplicate (seq_num ≤ seq_rx) —
            // re-ACK the last in‐order packet so the sender can recover
            Srtp_Packet_t dup_ack = {0};
            dup_ack.header.packet_type = SRTP_TYPE_data_ack;
            dup_ack.header.seq_num     = G_pcb.seq_rx;
            dup_ack.header.ack_num     = G_pcb.seq_rx;
            sendto(sd, &dup_ack, sizeof(Srtp_Header_t), 0,
                   (struct sockaddr*)&G_pcb.remote, sizeof(G_pcb.remote));
            // and keep waiting for the real next packet
            continue;
        }
        else {
            // pkt.seq_num > expected (a future packet) — just drop it
            continue;
        }
    }
}


int srtp_close(int sd) {
    // only allowed in CONNECTED
    if (G_pcb.state != SRTP_state_connected) {
        printf("Error: srtp_close() can only be called in CONNECTED state.\n");
        return SRTP_ERROR_api;
    }

    // 1) turn off any recv‐timeout so we block indefinitely in the close handshake
    struct timeval tv = { 0, 0 };
    if (setsockopt(sd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        perror("setsockopt");
        // not fatal, but beware it might still time out
    }

    // 2) send our close_req
    Srtp_Packet_t pkt = {0};
    pkt.header.packet_type = SRTP_TYPE_close_req;
    pkt.header.seq_num     = (uint16_t)G_pcb.seq_tx;
    pkt.header.ack_num     = (uint16_t)G_pcb.seq_rx;
    sendto(sd, &pkt, sizeof(Srtp_Header_t), 0,
           (struct sockaddr*)&G_pcb.remote, sizeof(G_pcb.remote));
    printf("[SRTP] Sent close_req.\n");

    // 3) transition
    G_pcb.state = handle_state_transition(G_pcb.state, SRTP_TYPE_close_req);

    // 4) now loop until we reach CLOSED
    while (G_pcb.state != SRTP_state_closed) {
        Srtp_Packet_t in = {0};
        ssize_t n = recv(sd, &in, sizeof(in), 0);
        if (n < 0) {
            perror("recv in close");
            return SRTP_ERROR;
        }

        switch (in.header.packet_type) {
          case SRTP_TYPE_close_req:
            // peer also wants to close → reply with close_ack
            {
              Srtp_Packet_t ack = {0};
              ack.header.packet_type = SRTP_TYPE_close_ack;
              ack.header.seq_num     = (uint16_t)G_pcb.seq_tx;
              ack.header.ack_num     = (uint16_t)G_pcb.seq_rx;
              sendto(sd, &ack, sizeof(Srtp_Header_t), 0,
                     (struct sockaddr*)&G_pcb.remote, sizeof(G_pcb.remote));
              printf("[SRTP] Received close_req, sent close_ack.\n");
              G_pcb.state = handle_state_transition(G_pcb.state, SRTP_TYPE_close_ack);
            }
            break;

          case SRTP_TYPE_close_ack:
            // we got an ack for our close_req, or a final ack after our ack
            printf("[SRTP] Received close_ack.\n");
            G_pcb.state = handle_state_transition(G_pcb.state, SRTP_TYPE_close_ack);
            break;

          default:
            // ignore anything else
            continue;
        }
    }

    // 5) fully closed → tear down
    if (close(sd) < 0) {
        perror("close");
        return SRTP_ERROR;
    }
    printf("[SRTP] Socket closed, state=CLOSED.\n");
    return SRTP_SUCCESS;
}
