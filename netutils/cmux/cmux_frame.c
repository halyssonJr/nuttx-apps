/****************************************************************************
 * apps/netutils/cmux/cmux_parse.c
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

/****************************************************************************
 * Included Files
 ****************************************************************************/

#include <nuttx/config.h>

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <sys/param.h>
#include <sys/types.h>

#include "cmux_frame.h"

#define CMUX_MIN_FRAME_LEN (5)
#define CMUX_FRAME_PREFIX (5)
#define CMUX_FRAME_POSFIX (2)

#define cmux_inc_buffer(buf, p) \
	p++;                          \
	if (p == buf->endp)           \
		p = buf->data;
#define cmux_buffer_length(buf) ((buf->readp > buf->writep) ? (CMUX_BUFFER_SZ - (buf->readp - buf->writep)) : (buf->writep - buf->readp))
#define cmux_buffer_free(buf) ((buf->readp > buf->writep) ? (buf->readp - buf->writep) : (CMUX_BUFFER_SZ - (buf->writep - buf->readp)))

static const unsigned char g_cmux_crc_table[256] = {/* reversed, 8-bit, poly=0x07 */
																			 0x00, 0x91, 0xE3, 0x72, 0x07, 0x96, 0xE4, 0x75, 0x0E, 0x9F, 0xED, 0x7C, 0x09, 0x98, 0xEA, 0x7B,
																			 0x1C, 0x8D, 0xFF, 0x6E, 0x1B, 0x8A, 0xF8, 0x69, 0x12, 0x83, 0xF1, 0x60, 0x15, 0x84, 0xF6, 0x67,
																			 0x38, 0xA9, 0xDB, 0x4A, 0x3F, 0xAE, 0xDC, 0x4D, 0x36, 0xA7, 0xD5, 0x44, 0x31, 0xA0, 0xD2, 0x43,
																			 0x24, 0xB5, 0xC7, 0x56, 0x23, 0xB2, 0xC0, 0x51, 0x2A, 0xBB, 0xC9, 0x58, 0x2D, 0xBC, 0xCE, 0x5F,
																			 0x70, 0xE1, 0x93, 0x02, 0x77, 0xE6, 0x94, 0x05, 0x7E, 0xEF, 0x9D, 0x0C, 0x79, 0xE8, 0x9A, 0x0B,
																			 0x6C, 0xFD, 0x8F, 0x1E, 0x6B, 0xFA, 0x88, 0x19, 0x62, 0xF3, 0x81, 0x10, 0x65, 0xF4, 0x86, 0x17,
																			 0x48, 0xD9, 0xAB, 0x3A, 0x4F, 0xDE, 0xAC, 0x3D, 0x46, 0xD7, 0xA5, 0x34, 0x41, 0xD0, 0xA2, 0x33,
																			 0x54, 0xC5, 0xB7, 0x26, 0x53, 0xC2, 0xB0, 0x21, 0x5A, 0xCB, 0xB9, 0x28, 0x5D, 0xCC, 0xBE, 0x2F,
																			 0xE0, 0x71, 0x03, 0x92, 0xE7, 0x76, 0x04, 0x95, 0xEE, 0x7F, 0x0D, 0x9C, 0xE9, 0x78, 0x0A, 0x9B,
																			 0xFC, 0x6D, 0x1F, 0x8E, 0xFB, 0x6A, 0x18, 0x89, 0xF2, 0x63, 0x11, 0x80, 0xF5, 0x64, 0x16, 0x87,
																			 0xD8, 0x49, 0x3B, 0xAA, 0xDF, 0x4E, 0x3C, 0xAD, 0xD6, 0x47, 0x35, 0xA4, 0xD1, 0x40, 0x32, 0xA3,
																			 0xC4, 0x55, 0x27, 0xB6, 0xC3, 0x52, 0x20, 0xB1, 0xCA, 0x5B, 0x29, 0xB8, 0xCD, 0x5C, 0x2E, 0xBF,
																			 0x90, 0x01, 0x73, 0xE2, 0x97, 0x06, 0x74, 0xE5, 0x9E, 0x0F, 0x7D, 0xEC, 0x99, 0x08, 0x7A, 0xEB,
																			 0x8C, 0x1D, 0x6F, 0xFE, 0x8B, 0x1A, 0x68, 0xF9, 0x82, 0x13, 0x61, 0xF0, 0x85, 0x14, 0x66, 0xF7,
																			 0xA8, 0x39, 0x4B, 0xDA, 0xAF, 0x3E, 0x4C, 0xDD, 0xA6, 0x37, 0x45, 0xD4, 0xA1, 0x30, 0x42, 0xD3,
																			 0xB4, 0x25, 0x57, 0xC6, 0xB3, 0x22, 0x50, 0xC1, 0xBA, 0x2B, 0x59, 0xC8, 0xBD, 0x2C, 0x5E, 0xCF};

/****************************************************************************
 * Private Functions
 ****************************************************************************/

/****************************************************************************
 * Name: cmux_calulate_fcs
 *
 * Description:
 *   .
 *
 *	Input Parameters:
 *   cmux_buffer:
 * 	 cmux_parse:
 *
 * Returned Value:
 ****************************************************************************/

static unsigned char cmux_calulate_fcs(const unsigned char *input, int count)
{
	unsigned char fcs = 0xFF;
	int i;
	for (i = 0; i < count; i++)
	{
		fcs = g_cmux_crc_table[fcs ^ input[i]];
	}
	return (0xFF - fcs);
}

/****************************************************************************
 * Public Functions
 ****************************************************************************/

/****************************************************************************
 * Name: cmux_parse_create
 *
 * Description:
 *   .
 *
 * Returned Value:
 *
 ****************************************************************************/

struct cmux_stream_buffer_s *cmux_stream_buffer_create(void)
{
	struct cmux_stream_buffer_s *cmux_buffer = malloc(sizeof(struct cmux_stream_buffer_s));
	if (cmux_buffer)
	{
		memset(cmux_buffer, 0, sizeof(struct cmux_stream_buffer_s));
		cmux_buffer->readp = cmux_buffer->data;
		cmux_buffer->writep = cmux_buffer->data;
		cmux_buffer->endp = cmux_buffer->data + CMUX_BUFFER_SZ;
	}
	return cmux_buffer;
}

/****************************************************************************
 * Name: cmux_buffer_delete
 *
 * Description:
 *   .
 * Input Parameters:
 *   cmux_buffer:
 *
 * Returned Value:
 *
 ****************************************************************************/

void cmux_buffer_delete(struct cmux_stream_buffer_s *cmux_buffer)
{
	if (cmux_buffer)
	{
		free(cmux_buffer);
	}
}

/****************************************************************************
 * Name: cmux_buffer_write
 *
 * Description:
 *   .
 * Input Parameters:
 *   cmux_buffer:
 *	 input:
 *   count:
 *
 * Returned Value:
 *
 ****************************************************************************/

int cmux_buffer_write(struct cmux_stream_buffer_s *cmux_buffer, const char *input, int count)
{
	int c = cmux_buffer->endp - cmux_buffer->writep;

	count = MIN(count, cmux_buffer_free(cmux_buffer));
	if (count > c)
	{
		memcpy(cmux_buffer->writep, input, c);
		memcpy(cmux_buffer->data, input + c, count - c);
		cmux_buffer->writep = cmux_buffer->data + (count - c);
	}
	else
	{
		memcpy(cmux_buffer->writep, input, count);
		cmux_buffer->writep += count;
		if (cmux_buffer->writep == cmux_buffer->endp)
		{
			cmux_buffer->writep = cmux_buffer->data;
		}
	}
	printf ("Buffer writep :%s \n", cmux_buffer->writep);
	return count;
}

/****************************************************************************
 * Name: cmux_parse_delete
 *
 * Description:
 *   .
 * Input Parameters:
 *   cmux_parse:
 *
 ****************************************************************************/

void cmux_parse_delete(struct cmux_parse_s *cmux_parse)
{
	if (cmux_parse)
	{
		if (cmux_parse->data_length > 0 && cmux_parse->data)
		{
			free(cmux_parse->data);
		}
		free(cmux_parse);
	}
}

/****************************************************************************
 * Name: cmux_parse_reset
 *
 * Description:
 *   .
 * Input Parameters:
 *   cmux_parse:
 *
 ****************************************************************************/

static void cmux_parse_reset(struct cmux_parse_s *cmux_parse)
{
	if (cmux_parse)
	{
		if (cmux_parse->data)
		{
			free(cmux_parse->data);
		}
		memset(cmux_parse, 0x00, sizeof(struct cmux_parse_s));
	}
}

/****************************************************************************
 * Name: cmux_decode_frame
 *
 * Description:
 *   .
 * Input Parameters:
 *   cmux_buffer:
 * 	 cmux_parse:
 *
 * Returned Value:
 *
 ****************************************************************************/

int cmux_decode_frame(struct cmux_stream_buffer_s *cmux_buffer, struct cmux_parse_s *cmux_parse)
{
	/* Minimal length to CMUX Frame : address, type, length, FCS and flag */
	int length = CMUX_MIN_FRAME_LEN;
	unsigned char *data = NULL;
	unsigned char fcs = 0xFF;
	int end = 0;

	if (!cmux_buffer || !cmux_parse)
	{
		return -EACCES;
	}

	while (cmux_buffer_length(cmux_buffer) >= CMUX_MIN_FRAME_LEN)
	{
		cmux_buffer->flag_found = 0;
		length = CMUX_MIN_FRAME_LEN;

		while (!cmux_buffer->flag_found &&
					 cmux_buffer_length(cmux_buffer) > 0)
		{
			if (*cmux_buffer->readp == F_FLAG)
			{
				cmux_buffer->flag_found = 1;
			}
			cmux_inc_buffer(cmux_buffer, cmux_buffer->readp);
		}
		printf("Open Flag Found\n");
		if (!cmux_buffer->flag_found)
		{
			return ERROR;
		}

		while (cmux_buffer_length(cmux_buffer) > 0 &&
					 (*cmux_buffer->readp == F_FLAG))
		{
			cmux_inc_buffer(cmux_buffer, cmux_buffer->readp);
		}

		if (cmux_buffer_length(cmux_buffer) < length)
		{
			return ERROR;
		}

		data = cmux_buffer->readp;
		fcs = 0xFF;
		cmux_parse->address = ((*data & 0xFC) >> 2);
		fcs = g_cmux_crc_table[fcs ^ *data];
		cmux_inc_buffer(cmux_buffer, data);

		cmux_parse->control = *data;
		fcs = g_cmux_crc_table[fcs ^ *data];
		cmux_inc_buffer(cmux_buffer, data);

		cmux_parse->data_length = (*data & 0xFE) >> 1;
		fcs = g_cmux_crc_table[fcs ^ *data];

		/* EA bit, should alwyas have the value 1 */
		if (!(*data & 1))
		{
			cmux_buffer->readp = data;
			cmux_buffer->flag_found = 0;
			printf("EA bit != 1 \n");
			continue;
		}
		printf("Data length = %d \n", length);
		length += cmux_parse->data_length;
		if (!(cmux_buffer_length(cmux_buffer) >= length))
		{
			return ERROR;
		}

		cmux_inc_buffer(cmux_buffer, data);
		if (cmux_parse->data_length > 0)
		{
			cmux_parse->data = malloc((sizeof(char) * cmux_parse->data_length));
			if (!cmux_parse->data)
			{
				cmux_parse->data_length = 0;
				cmux_parse_delete(cmux_parse);
				return -ENOMEM;
			}

			end = cmux_buffer->endp - data;
			if (cmux_parse->data_length > end)
			{
				memcpy(cmux_parse->data, data, end);
				memcpy(cmux_parse->data + end, cmux_buffer->data, cmux_parse->data_length - end);
				data = cmux_buffer->data + (cmux_parse->data_length - end);
			}
			else
			{
				memcpy(cmux_parse->data, data, cmux_parse->data_length);
				data += cmux_parse->data_length;
				if (data == cmux_buffer->endp)
				{
					data = cmux_buffer->data;
				}
			}

			if (CMUX_FRAME_TYPE(FRAME_TYPE_UI, cmux_parse))
			{
				int i;
				for (i = 0; i < cmux_parse->data_length; i++)
				{
					fcs = g_cmux_crc_table[fcs ^ (cmux_parse->data[i])];
				}
			}
		}

		if (g_cmux_crc_table[fcs ^ (*data)] != 0xCF)
		{
			cmux_buffer->dropped_count++;
			cmux_buffer->readp = data;
			cmux_parse_reset(cmux_parse);
			continue;
		}

		cmux_inc_buffer(cmux_buffer, data);
		if (*data != F_FLAG)
		{
			cmux_buffer->readp = data;
			cmux_buffer->dropped_count++;
			cmux_parse_reset(cmux_parse);
			continue;
		}
		cmux_buffer->received_count++;
		cmux_inc_buffer(cmux_buffer, data);
		cmux_buffer->readp = data;
		return OK;
	}

	return ERROR;
}

/****************************************************************************
 * Name: cmux_encode_frame
 *
 * Description:
 *   .
 * Input Parameters:
 *   cmux_buffer:
 * 	 cmux_parse:
 *
 * Returned Value:
 *
 ****************************************************************************/

int cmux_encode_frame(int fd, int channel, char *buffer, int frame_size, unsigned char type)
{
	unsigned char frame_prefix[CMUX_FRAME_PREFIX] = {F_FLAG, (ADDR_FIELD_BIT_EA | ADDR_FIELD_BIT_CR),
																									 0x00, 0x00, 0x00};
	unsigned char frame_posfix[CMUX_FRAME_POSFIX] = {0xFF, F_FLAG};
	int prefix_len = 4;

	frame_prefix[CMUX_BIT1] = (frame_prefix[CMUX_BIT1] | ((0x3F & (unsigned char)channel) << 2));
	frame_prefix[CMUX_BIT2] = type;

	if (frame_size <= CMUX_FRAME_MAX_SIZE)
	{
		frame_prefix[CMUX_BIT3] = ADDR_FIELD_BIT_EA | (frame_size << 1);
		prefix_len = 4;
	}
	else
	{
		frame_prefix[CMUX_BIT3] = (frame_size << 1) & 0xFE;
		frame_prefix[CMUX_BIT4] = ADDR_FIELD_BIT_EA | ((frame_size >> 7) << 1);
		prefix_len = 5;
	}

	frame_posfix[CMUX_BIT0] = cmux_calulate_fcs(frame_prefix + 1, prefix_len - 1);

	int ret = write(fd, frame_prefix, prefix_len);
	if (ret != prefix_len)
	{
		return ERROR;
	}

	if (frame_size > 0 && buffer != NULL)
	{
		ret = write(fd, buffer, frame_size);
		if (ret != frame_size)
		{
			printf("Failed to write buffer (wrote %d, expected %d)\n", ret, frame_size);
			return ERROR;
		}
	}

	ret = write(fd, frame_posfix, CMUX_FRAME_POSFIX);
	if (ret != CMUX_FRAME_POSFIX)
	{
		return ERROR;
	}

 	printf("PREFIX : [%02x %02x %02x %02x %02x]\n",
    frame_prefix[CMUX_BIT0], frame_prefix[CMUX_BIT1], frame_prefix[CMUX_BIT2],
    frame_prefix[CMUX_BIT3], frame_prefix[CMUX_BIT4]);

    if (buffer)
    {
        for (int i = 0; i < frame_size; i++)
            printf(" %02x ", buffer[i]);
        printf("\n");
    }

	printf("POSFIX : [%02x %02x]\n", frame_posfix[CMUX_BIT0], frame_posfix[CMUX_BIT1]);
	return OK;
}
