/****************************************************************************
 * apps/netutils/cmux/cmux.c
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
#include <fcntl.h>

#include <sys/param.h>
#include <sys/types.h>
#include <pthread.h>
#include <sched.h>
#include <pty.h>

#include "netutils/chat.h"
#include "netutils/cmux.h"
#include "cmux.h"

/****************************************************************************
 * Private Data
 ****************************************************************************/

#define CMUX_MIN_FRAME_LEN (5)
#define CMUX_FRAME_PREFIX (5)
#define CMUX_FRAME_POSFIX (2)

#define CMUX_TASK_NAME ("cmux")
#define CMUX_THREAD_PRIOR (100)
#define CMUX_THREAD_STACK_SIZE (3072)

#define cmux_inc_buffer(buf, p) \
  p++;                          \
  if (p == buf->endp)           \
    p = buf->data;

#define cmux_buffer_length(buf) \
  ((buf->readp > buf->writep) ? (CMUX_BUFFER_SZ - (buf->readp - buf->writep)) : (buf->writep - buf->readp))

#define cmux_buffer_free(buf) \
  ((buf->readp > buf->writep) ? (buf->readp - buf->writep) : (CMUX_BUFFER_SZ - (buf->writep - buf->readp)))

/* reversed, 8-bit, poly=0x07 */
static const unsigned char g_cmux_crc_table[256] = {
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

struct cmux_ctl_s
{
  int fd;
  int total_ports;
  struct cmux_parse_s *parse;
  struct cmux_channel_s *channels;
  struct cmux_stream_buffer_s *stream;
};

/****************************************************************************
 * Private Functions
 ****************************************************************************/

/****************************************************************************
 * Name: cmux_calulate_fcs
 *
 * Description:
 *  Calculate the frame checking sequence.
 *
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
 * Name: cmux_parse_create
 *
 * Description:
 *  Create a circular buffer to receive incoming packets.
 *
 ****************************************************************************/

static struct cmux_stream_buffer_s *cmux_stream_buffer_create(void)
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
 * Name: cmux_buffer_write
 *
 * Description:
 *  Write the input frames to the circular buffer.
 *
 ****************************************************************************/

static int cmux_buffer_write(struct cmux_stream_buffer_s *cmux_buffer, const char *input, int length)
{
  int c = cmux_buffer->endp - cmux_buffer->writep;

  length = MIN(length, cmux_buffer_free(cmux_buffer));
  if (length > c)
  {
    memcpy(cmux_buffer->writep, input, c);
    memcpy(cmux_buffer->data, input + c, length - c);
    cmux_buffer->writep = cmux_buffer->data + (length - c);
  }
  else
  {
    memcpy(cmux_buffer->writep, input, length);
    cmux_buffer->writep += length;
    if (cmux_buffer->writep == cmux_buffer->endp)
    {
      cmux_buffer->writep = cmux_buffer->data;
    }
  }

  return length;
}

/****************************************************************************
 * Name: cmux_parse_reset
 *
 * Description:
 *  Reset data buffer and parse struct.
 *
 ****************************************************************************/

static void cmux_parse_reset(struct cmux_parse_s *cmux_parse)
{
  if (cmux_parse)
  {
    memset(cmux_parse->data, 0x00, CMUX_BUFFER_SZ);
    memset(cmux_parse, 0x00, sizeof(struct cmux_parse_s));
  }
}

/****************************************************************************
 * Name: cmux_decode_frame
 *
 * Description:
 *  Decode CMUX frame.
 *
 ****************************************************************************/

static int cmux_decode_frame(struct cmux_stream_buffer_s *cmux_buffer, struct cmux_parse_s *cmux_parse)
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
      continue;
    }

    length += cmux_parse->data_length;
    if (!(cmux_buffer_length(cmux_buffer) >= length))
    {
      return ERROR;
    }

    cmux_inc_buffer(cmux_buffer, data);
    if (cmux_parse->data_length > 0 && cmux_parse->data_length < CMUX_BUFFER_SZ)
    {
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
 *  Encode a buffer to the CMUX protocol..
 *
 ****************************************************************************/

static int cmux_encode_frame(int fd, int channel, char *buffer, int frame_size, unsigned char type)
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
      ninfo("Failed to write buffer (wrote %d, expected %d)\n", ret, frame_size);
      return ERROR;
    }
  }

  ret = write(fd, frame_posfix, CMUX_FRAME_POSFIX);
  if (ret != CMUX_FRAME_POSFIX)
  {
    return ERROR;
  }

  return OK;
}

/****************************************************************************
 * Name: cmux_open_pseudo_tty
 *
 * Description:
 *  Open pseudo-terminals according to the number of channels.
 *
 ****************************************************************************/

static int cmux_open_pseudo_tty(struct cmux_channel_s *channel, int total_channels)
{
  int ret = 0;
  struct termios options;

  if (!channel)
  {
    return -EACCES;
  }

  options.c_lflag &= ~(ICANON | ECHO | ECHOE | ISIG);
  options.c_iflag &= ~(INLCR | ICRNL | IGNCR);

  options.c_oflag &= ~OPOST;
  options.c_oflag &= ~OLCUC;
  options.c_oflag &= ~ONLRET;
  options.c_oflag &= ~ONOCR;
  options.c_oflag &= ~OCRNL;

  for (int i = 0; i < total_channels; i++)
  {
    ret = openpty(&channel[i].master_fd, &channel[i].slave_fd,
                  (FAR char *)&channel[i].slave_path, &options, NULL);
    if (ret < 0)
    {
      perror("Failed to open pseudo terminal \n");
      break;
    }
    else
    {
      ninfo("Open pseudo tty name: %s\n", channel[i].slave_path);

      channel[i].dlci = i + 1;
      channel[i].active = true;
      channel[i].last_activity = time(NULL);
    }
  }

  return ret;
}

/****************************************************************************
 * Name: cmux_open_channels
 *
 * Description:
 *  Open the controller and the logic channels.
 *
 ****************************************************************************/

static int cmux_open_channels(int fd, int total_channels)
{
  int ret = 0;
  for (int i = 0; i < total_channels; i++)
  {
    ret = cmux_encode_frame(fd, i,
                            NULL, 0x00,
                            (FRAME_TYPE_SABM | CONTROL_FIELD_BIT_PF));
    if (ret != OK)
    {
      perror("ERROR: Failed to open channel\n");
      break;
    }
    sleep(1);
  }
  return ret;
}

/****************************************************************************
 * Name: cmux_extract
 *
 * Description:
 *  Extract a frame from the circular buffer according to the input and length.
 *
 ****************************************************************************/

static int cmux_extract(struct cmux_ctl_s *ctl, char *input, int len)
{
  int ret;
  int frames_extracted = 0;

  if (!input)
  {
    return ERROR;
  }

  ret = cmux_buffer_write(ctl->stream, input, len);
  if (ret < 0)
  {
    return ret;
  }

  while (cmux_decode_frame(ctl->stream, ctl->parse) >= 0)
  {

    if (CMUX_FRAME_TYPE(FRAME_TYPE_UI, ctl->parse) || CMUX_FRAME_TYPE(FRAME_TYPE_UIH, ctl->parse))
    {
      if (ctl->parse->address > 0)
      {
        /* Logic channel */
        ret = write(ctl->channels[ctl->parse->address].master_fd,
                    ctl->parse->data,
                    ctl->parse->data_length);
        if (ret != ctl->parse->data_length)
        {
          ninfo("Frame length less than expected\n");
          continue;
        }
      }
      else
      {
        /* Control channel */
      }
    }
    else
    {
      switch ((ctl->parse->control & ~CONTROL_FIELD_BIT_PF))
      {
      case FRAME_TYPE_UA:
        ninfo("Frame type: UA \n");

        break;
      case FRAME_TYPE_DM:
        ninfo("Frame type: DM \n");
        if (ctl->channels[ctl->parse->address].active)
        {
          ctl->channels[ctl->parse->address].active = 0;
        }
        break;
      case FRAME_TYPE_DISC:
        ninfo("Frame type: DISC \n");

        if (ctl->channels[ctl->parse->address].active)
        {
          ctl->channels[ctl->parse->address].active = false;
          ret = cmux_encode_frame(ctl->fd,
                                  ctl->parse->address, NULL, 0x00,
                                  (FRAME_TYPE_UA | CONTROL_FIELD_BIT_PF));
        }
        else
        {
          ret = cmux_encode_frame(ctl->fd,
                                  ctl->parse->address, NULL, 0x00,
                                  (FRAME_TYPE_DM | CONTROL_FIELD_BIT_PF));
        }

        if (ret < 0)
        {
          nwarn("Failed to encode the frame. Address (%d) \n", ctl->parse->address);
        }
        break;
      case FRAME_TYPE_SABM:
        ninfo("Frame type: SABM\n");

        if (!ctl->channels[ctl->parse->address].active)
        {
          if (!ctl->parse->address)
          {
            ninfo("Control channel opened.\n");
          }
          else
          {
            ninfo("Logical channel %d opened.\n", ctl->parse->address);
          }
        }
        else
        {
          nwarn("SABM even though channel %d was already closed.\n", ctl->parse->address);
        }
        ctl->channels[ctl->parse->address].active = 1;
        ret = cmux_encode_frame(ctl->fd,
                                ctl->parse->address, NULL, 0x00,
                                FRAME_TYPE_UA | CONTROL_FIELD_BIT_PF);
        if (ret < 0)
        {
          nwarn("Failed to encode the frame. Address (%d) \n", ctl->parse->address);
        }

        break;
      default:
        ninfo("Frane type: UNKNOWN\n");
        break;
      }
    }
    frames_extracted++;
  }
  cmux_parse_reset(ctl->parse);

  return frames_extracted;
}

/****************************************************************************
 * Name: cmux_protocol_send
 *
 * Description:
 *  Send encoded messages to a specific address.
 *
 ****************************************************************************/

static int cmux_send(struct cmux_ctl_s *ctl, char *buffer, int lenght, int address)
{
  int ret;
  if (!buffer)
  {
    return ERROR;
  }

  ret = cmux_encode_frame(ctl->fd,
                          address,
                          buffer,
                          lenght, FRAME_TYPE_UIH);
  return ret;
}

/****************************************************************************
 * Name: cmux_thread
 *
 * Description:
 *   Start cmux thread.
 *
 ****************************************************************************/

static void *cmux_thread(void *args)
{
  struct cmux_ctl_s *ctl = (struct cmux_ctl_s *)args;
  int ret = 0;
  fd_set rfds;
  struct timeval timeout;
  char buffer[CMUX_BUFFER_SZ];

  for (;;)
  {
    FD_ZERO(&rfds);
    FD_SET(ctl->fd, &rfds);

    int max_fd = ctl->fd;
    for (int i = 0; i < ctl->total_ports; i++)
    {
      if (ctl->channels[i].active)
      {
        FD_SET(ctl->channels[i].master_fd, &rfds);
        FD_SET(ctl->channels[i].slave_fd, &rfds);

        if (ctl->channels[i].master_fd > max_fd)
          max_fd = ctl->channels[i].master_fd;
        if (ctl->channels[i].slave_fd > max_fd)
          max_fd = ctl->channels[i].slave_fd;
      }
    }

    timeout.tv_usec = 100;
    timeout.tv_sec = 0;

    ret = select(max_fd + 1, &rfds, NULL, NULL, &timeout);
    if (ret > 0)
    {
      if (FD_ISSET(ctl->fd, &rfds))
      {
        int bytes_read = read(ctl->fd, buffer, sizeof(buffer) - 1);

        if (bytes_read > 0)
        {
          buffer[bytes_read] = '\0';
          ret = cmux_extract(ctl, buffer, bytes_read);
          if (ret < 0)
          {
            perror("ERROR: Failed to extract frames \n");
          }
        }
      }

      for (int i = 0; i < ctl->total_ports; i++)
      {
        if (ctl->channels[i].active && FD_ISSET(ctl->channels[i].master_fd, &rfds))
        {
          memset(buffer, 0, sizeof(buffer));
          int bytes_read = read(ctl->channels[i].master_fd, buffer, sizeof(buffer) - 1);
          if (bytes_read > 0)
          {
            ret = cmux_send(ctl, buffer, bytes_read, i);
            if (ret < 0)
            {
              nwarn("WANING: Failed to retransmit from /dev/pty/%d.\n", i);
            }
          }
        }
      }
    }
  }
  return NULL;
}

/****************************************************************************
 * Public Functions
 ****************************************************************************/

/****************************************************************************
 * Name: cmux_create
 *
 * Description:
 *  Create CMUX context.
 *
 ****************************************************************************/

int cmux_create(struct cmux_settings_s *settings)
{
  int ret = 0;
  struct chat_ctl ctl;
  struct cmux_ctl_s *cmux_ctl = NULL;
  pthread_t cmux_thread_id;
  struct sched_param param;
  pthread_attr_t attr;

  cmux_ctl = malloc(sizeof(struct cmux_ctl_s));
  if (!cmux_ctl)
  {
    perror("ERROR: Failed to allocate memory for CMUX daemon\n");
    ret = -ENOMEM;
    return ret;
  }

  memset(cmux_ctl, 0, sizeof(struct cmux_ctl_s));
  cmux_ctl->fd = open(settings->tty_name, O_RDWR | O_NONBLOCK);
  if (cmux_ctl->fd < 0)
  {
    perror("ERROR: Unable to open file %s\n");
    goto exit;
  }

  ctl.echo = false;
  ctl.verbose = false;
  ctl.fd = cmux_ctl->fd;
  ctl.timeout = 30;

  ret = chat(&ctl, settings->script);
  if (ret < 0)
  {
    perror("ERROR:Failed to run cmux script\n");
    goto exit;
  }

  cmux_ctl->channels = malloc(sizeof(struct cmux_channel_s) * settings->total_channels);
  if (!cmux_ctl->channels)
  {
    perror("ERROR:Failed to allocate memory to channels\n");
    ret = -ENOMEM;
    goto exit;
  }

  cmux_ctl->parse = malloc(sizeof(struct cmux_parse_s));
  if (!cmux_ctl->parse)
  {
    perror("ERROR: Failed to allocate memory to parse\n");
    ret = -ENOMEM;
    goto exit;
  }

  cmux_parse_reset(cmux_ctl->parse);

  ret = cmux_open_pseudo_tty(cmux_ctl->channels, settings->total_channels);
  if (ret < 0)
  {
    perror("ERROR: Failed to open pseudo tty.\n");
    goto exit;
  }

  cmux_ctl->stream = cmux_stream_buffer_create();
  if (!cmux_ctl->stream)
  {
    perror("ERROR: Failed to allocate memory to stream\n");
    ret = -ENOMEM;
    goto exit;
  }

  ret = cmux_open_channels(cmux_ctl->fd, settings->total_channels);
  if (ret < 0)
  {
    perror("ERROR: Failed to open virtual channels.\n");
    goto exit;
  }

  cmux_ctl->total_ports = settings->total_channels;

  pthread_attr_init(&attr);
  param.sched_priority = CMUX_THREAD_PRIOR;
  pthread_attr_setschedparam(&attr, &param);
  pthread_attr_setstacksize(&attr, CMUX_THREAD_STACK_SIZE);

  ret = pthread_create(&cmux_thread_id, &attr, cmux_thread, cmux_ctl);

  return ret;

exit:

  if (cmux_ctl->channels)
  {
    for (int i = 0; i < settings->total_channels; i++)
    {
      if (cmux_ctl->channels[i].master_fd > 0)
        close(cmux_ctl->channels[i].master_fd);
      if (cmux_ctl->channels[i].slave_fd > 0)
        close(cmux_ctl->channels[i].slave_fd);
    }
    free(cmux_ctl->channels);
  }

  if (cmux_ctl->stream)
  {
    free(cmux_ctl->stream);
  }

  close(cmux_ctl->fd);

  return ret;
}