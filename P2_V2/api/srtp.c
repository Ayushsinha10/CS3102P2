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
static uint16_t get_local_port() {
    return ntohs(G_pcb.local.sin_port);  // Accessing local port from G_pcb.local.sin_port
}

/* Helper function to resolve FQDN */
static int resolve_fqdn(const char *fqdn, struct sockaddr_in *addr) {
    struct hostent *host = gethostbyname(fqdn);
    if (host == NULL) {
        perror("gethostbyname");
        return SRTP_ERROR;
    }
    addr->sin_family = AF_INET;
    addr->sin_port = htons(get_local_port());  // Use the helper function here
    memcpy(&addr->sin_addr, host->h_addr_list[0], host->h_length);
    return SRTP_SUCCESS;
}

/* Initialization of SRTP - called at the beginning */
void srtp_initialise() {
    reset_SrtpPcb();
}

/* Server side - Start listening on the given port */
int srtp_start(uint16_t port) {
    struct sockaddr_in server_addr;

    /* Create a socket */
    int sd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sd < 0) {
        perror("socket");
        return SRTP_ERROR;
    }

    /* Set up server address */
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);

    /* Bind socket */
    if (bind(sd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind");
        close(sd);
        return SRTP_ERROR;
    }

    /* Update the G_pcb local port using the new port */
    G_pcb.local.sin_port = htons(port);  // Setting port directly in G_pcb.local
    return sd;
}

/* Server side - Accept incoming connections */
int srtp_accept(int sd) {
    /* For SRTP, we only need to handle a single connection; just return the socket. */
    return sd;
}

/* Client side - Open connection to a remote server */
int srtp_open(const char *fqdn, uint16_t port) {
    struct sockaddr_in server_addr;
    int sd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sd < 0) {
        perror("socket");
        return SRTP_ERROR;
    }

    /* Update the G_pcb local port using the given port number */
    G_pcb.local.sin_port = htons(port);  // Setting port directly in G_pcb.local
    

    /* Resolve FQDN and set up server address */
    if (resolve_fqdn(fqdn, &server_addr) < 0) {
        close(sd);
        return SRTP_ERROR;
    }

    /* Try connecting to the server */
    if (connect(sd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("connect");
        close(sd);
        return SRTP_ERROR;
    }

    return sd;
}

/* Close connection */
int srtp_close(int sd) {
    if (close(sd) < 0) {
        perror("close");
        return SRTP_ERROR;
    }
    return SRTP_SUCCESS;
}

/* Transmit data over UDP (synchronous) */
int srtp_tx(int sd, void *data, uint16_t data_size) {
    ssize_t bytes_sent = send(sd, data, data_size, 0);
    if (bytes_sent < 0) {
        perror("send");
        return SRTP_ERROR;
    }
    return (int)bytes_sent;
}

/* Receive data over UDP (synchronous) */
int srtp_rx(int sd, void *data, uint16_t data_size) {
    ssize_t bytes_received = recv(sd, data, data_size, 0);
    if (bytes_received < 0) {
        perror("recv");
        return SRTP_ERROR;
    }
    return (int)bytes_received;
}
