/****************************************************************************
 * apps/netutils/cmux/cmux.h
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.  The
 * ASF licenses this file to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance with the
 * License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
 * License for the specific language governing permissions and limitations
 * under the License.
 *
 ****************************************************************************/

#ifndef __APPS_NETUTILS_CMUX_FRAME_H
#define __APPS_NETUTILS_CMUX_FRAME_H

#include <sys/time.h>
#include <stdbool.h>
#include <debug.h>
#include <errno.h>

#define CMUX_BIT0 (0)
#define CMUX_BIT1 (1)
#define CMUX_BIT2 (2)
#define CMUX_BIT3 (3)
#define CMUX_BIT4 (4)
#define CMUX_BIT5 (5) 
#define CMUX_BIT6 (6)
#define CMUX_BIT7 (7)

#define CMUX_BUFFER_SZ          (2048)
#define CMUX_FRAME_MAX_SIZE     (127) /* Maximum frame size. Range: 1–32768. Default value: 127 */

/**
 * Mux Frame
 *
 * |Open flag |Address  |Control  |Length       |Infomation (payload) |FCS      |Close flag
	 |1 octet   |1 octet  |1 octet  |1-2 octet    |Multiples octets     |1 octed  |1 octed
	 | 0xF9     |-------  |-------  |---------    |----------------     |-------  |0xF9
*/

/* Flag Field - Each frame begins and ends with a flag sequence octet. */
#define F_FLAG (0xF9)

/**
 * Address Field
 *
 * |Bit 1 |Bit 2 |Bit 3 |Bit 4 |Bit 5 |Bit 6 |Bit 7 |Bit 8
	 |ADDR_FIELD_BIT_EA    | C/R  |      |      |      | DLCI |      |
 */

 /**
 * The C/R (command/response) bit identifies the frame as either a command or a response.
 * ______________________________
 * ________| Direction| CR Value
 * Command | TE -> UE | 1
 * Command | TE <- UE | 0
 * ______________________________
 * Response | TE -> UE | 1
 * Response | TE <- UE | 0
 */
#define ADDR_FIELD_BIT_CR (CMUX_BIT2)

/*
* EA bit extends the range of the address field. When the EA bit is set to 1 in an octet,
* it signifies that this octet is the last octet of the length field.
* When the EA bit is set to 0, it signifies that another octet of the address field follows.
*/
#define ADDR_FIELD_BIT_EA (CMUX_BIT1)


/* Control field
* |Bit 1 |Bit 2| Bit 3 |Bit 4 |Bit 5 |Bit 6 |Bit 7 |Bit 8
*    -     -      -      -      PF     -      -      -
* P/F (Poll/Final)
* - The Poll bit set to 1 shall be used by one station to solicit poll a response
		or sequence of responses from the other station.
* - The final bit set to 1 shall be used by a station to indicate the response frame
		transmitted as the result of a soliciting (poll) command.
*/
#define CONTROL_FIELD_BIT_PF    (0x10) /* Poll/Final */
/* Set Asynchronous Balanced Mode :  establish DLC between TE and UE */
#define FRAME_TYPE_SABM         (0x2F)
/* Unnumbered Acknowledgement:  is a response to SABM or DISC frame */
#define FRAME_TYPE_UA           (0x63)
/* Disconnected Mode :  frame is used to report a status where the station \
                        is logically disconnected from the data link. When in disconnected mode, \
                        no commands are accepted until the disconnected mode is terminated by    \
                        the receipt of a SABM command. If a DISC command is received while       \
                        in disconnected mode, a DM response is sent*/
#define FRAME_TYPE_DM (0x0F) 
/* Disconnect : is a command frame and is used to close down DLC. */
#define FRAME_TYPE_DISC (0x43)
/* Unnumbered Information with Header check :  command/response sends user data at either station*/
#define FRAME_TYPE_UIH (0xEF)
/* Unnumbered Information */
#define FRAME_TYPE_UI (0x03)

/**
 * | UE          | <---------   SABM (DLC 1)         -------------  | TE
 * |             | ----------   UA (Response)        ------------>  |
 * | Multiplexer | <----------  DISC (Close DLC 1)   ------------   |  Receiver
 * |             | <----------- UA(Response)         -----------    |
 */

/*
 * Note : Some manufactures doesn't support UI frame.
 */

/* Length Field
* |Bit 1 |Bit 2| Bit 3 |Bit 4 |Bit 5 |Bit 6 |Bit 7 |Bit 8
*    E/A    L1    L2     L3      L4     L5     L6     L7
* - L1 - L7 : The L1 to L7 bits indicate the length of the
		following data field for the information field less than 128 bytes
* - EA bit = 1 in an octet, it signifies that this octet is the last octet of the length field.
* - EA bit = 0, it signifies that a second octet of the length field follows.
* The total length of the length field is 15 bits in that case.
*/
#define LENGTH_FIELD_MAX_VALUE (0x7F)

/**
 * Information Field
 * The information field is the payload of the frame and carries the user data and
 * any convergence layer information. The field is octet structured and only presents in UIH frames.
 */

/**
 * FSC field
 * In the case of the UIH frame, the contents of the information field shall not be included in the FCS
 * calculation. FCS is calculated on the contents of the address, control and length fields only. This means
 * that only the delivery to the correct DLCI is protected, but not the information.
 */

#define CMUX_FRAME_TYPE(type, frame) ((frame->control & ~CONTROL_FIELD_BIT_PF) == type)

struct cmux_parse_s 
{
  unsigned char address;
  unsigned char control;
  int data_length;
  unsigned char *data;
};

struct cmux_stream_buffer_s {
  unsigned char data[CMUX_BUFFER_SZ];
  unsigned char *readp;
  unsigned char *writep;
  unsigned char *endp;
  int flag_found;
  unsigned long received_count;
  unsigned long dropped_count;
};

struct cmux_stream_buffer_s *cmux_stream_buffer_create(void);
int cmux_decode_frame(struct cmux_stream_buffer_s *cmux_buffer, struct cmux_parse_s *cmux_parse);
int cmux_buffer_write(struct cmux_stream_buffer_s *cmux_buffer, const char *input, int count);
void cmux_parse_delete(struct cmux_parse_s *cmux_parse);
int cmux_encode_frame(int fd, int channel, char *buffer, int frame_size, unsigned char type);

#endif /* __APPS_NETUTILS_CMUX_FRAME_H */
