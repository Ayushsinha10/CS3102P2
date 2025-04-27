
#include <stdio.h>
#include "srtp-fsm.h" // include the header defining states and events
#include "srtp-common.h" // include common definitions like packet types
#include "srtp-packet.h"
// Function to handle state transitions
SRTP_state_t handle_state_transition(SRTP_state_t *state, uint8_t event) {
    switch (*state) {
        case SRTP_state_listening:
            if (event == SRTP_TYPE_open_req) {
                printf("Transition from LISTENING to OPENING\n");
                *state = SRTP_state_opening;
                return SRTP_state_opening;
            
            } else {
                printf("Invalid event in LISTENING state\n");
                return SRTP_state_error;
    
            }
            break;

        case SRTP_state_opening:
            if (event == SRTP_TYPE_open_ack) {
                printf("Transition from OPENING to CONNECTED\n");
                *state = SRTP_state_connected;
                return SRTP_state_connected;
            } else {
                printf("Invalid event in OPENING state\n");
                return SRTP_state_error;
            }
            break;

        case SRTP_state_connected:
            if (event == SRTP_TYPE_data_req || event == SRTP_TYPE_data_ack) {
                // Stay in CONNECTED state on receiving data requests or acknowledgments
                printf("In CONNECTED state, handling data\n");
                *state = SRTP_state_connected;
                return SRTP_state_connected;
            } else if (event == SRTP_TYPE_close_req) {
                printf("Transition from CONNECTED to CLOSING_I\n");
                *state = SRTP_state_closing_i;
                return SRTP_state_closing_i;
            } else {
                printf("Invalid event in CONNECTED state\n");
                return SRTP_state_error;
            }
            break;

        case SRTP_state_closing_i:
            if (event == SRTP_TYPE_close_ack) {
                printf("Transition from CLOSING_I to CLOSING_R\n");
                *state = SRTP_state_closing_r;
                return SRTP_state_closing_r;
            } else {
                printf("Invalid event in CLOSING_I state\n");
                return SRTP_state_error;
            }
            break;

        case SRTP_state_closing_r:
            if (event == SRTP_TYPE_close_ack) {
                printf("Transition from CLOSING_R to CLOSED\n");
                *state = SRTP_state_closed;
                return SRTP_state_closed;
            } else {
                printf("Invalid event in CLOSING_R state\n");
                return SRTP_state_error;
            }
            break;

        case SRTP_state_closed:
            printf("Already in CLOSED state, no transitions allowed\n");
            return SRTP_state_error;
            break;

        default:
            printf("Error: Unknown state\n");
            return SRTP_state_error;
            break;
    }
}