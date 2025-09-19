/****************************************************************************
 * apps/netutils/cmux/cmux_protocol.c
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
#include <pty.h>

#include "netutils/chat.h"

#include "cmux_frame.h"

/****************************************************************************
 * Name: open_pseudo_tty
 *
 * Description:
 *
 * Input Parameters:
 *   channel:
 *   total_channels:
 *
 * Returned Value:
 *
 ****************************************************************************/

static int open_pseudo_tty(struct cmux_channel_s* channel, int total_channels)
{
  int ret = 0;
  int master_fd, slave_fd = 0;
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
                  &channel[i].slave_path, &options, NULL);
    if (ret < 0)
    {
      ninfo("Failed to opent pseudo terminal \n");
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
 * Name: open_cmux_channels
 *
 * Description:
 *
 * Input Parameters:
 *   fd:
 *   total_channels:
 *
 * Returned Value:
 *
 ****************************************************************************/

static int open_cmux_channels(int fd, int total_channels)
{
  int ret = 0;
  for (int i = 0; i < total_channels; i++)
  {
    ret = cmux_encode_frame(fd, i,
                          NULL, 0x00,
                          (FRAME_TYPE_SABM | CONTROL_FIELD_BIT_PF));
    if(ret != OK)
    {
      ninfo("Failed to open channel\n");
      break;
    }
  }
  return ret;
}

/****************************************************************************
 * Name: cmux_protocol_extract
 *
 * Description:
 *
 * Input Parameters:
 *   cmux_handle:
 *   input:
 *   count:
 *
 * Returned Value:
 *
 ****************************************************************************/

int cmux_protocol_extract(struct cmux_handle_s *cmux_handle, char *input, int count)
{
  int ret;
  struct cmux_parse_s *parse = NULL;
  int frames_extracted = 0;

  if (!input || !cmux_handle || count <= 0)
  {
    return ERROR;
  }

  ret = cmux_buffer_write(cmux_handle->stream, input, count);
  if (ret < 0)
  {
    return ret;
  }

  parse = malloc(sizeof(struct cmux_parse_s));
  if (!parse)
  {
    return -ENOMEM;
  }

  while (cmux_decode_frame(cmux_handle->stream, parse) >= 0)
  {
    if (CMUX_FRAME_TYPE(FRAME_TYPE_UI, parse) || CMUX_FRAME_TYPE(FRAME_TYPE_UIH, parse))
    {
      if (parse->address > 0)
      {
        /* Logic channel */
        ret = write(cmux_handle->channels[parse->address].master_fd,
                    parse->data,
                    parse->data_length);
        if (ret != parse->data_length)
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
      switch ((parse->control & ~CONTROL_FIELD_BIT_PF))
      {
      case FRAME_TYPE_UA:

        break;
      case FRAME_TYPE_DM:
        if (cmux_handle->channels[parse->address].active)
        {
          cmux_handle->channels[parse->address].active = 0;
        }
        break;
      case FRAME_TYPE_DISC:
        if (cmux_handle->channels[parse->address].active)
        {
          cmux_handle->channels[parse->address].active = false;
          ret = cmux_encode_frame(cmux_handle->fd,
                                  parse->address, NULL, 0x00,
                                  (FRAME_TYPE_UA | CONTROL_FIELD_BIT_PF));
        }
        else
        {
          ret = cmux_encode_frame(cmux_handle->fd,
                                  parse->address, NULL, 0x00,
                                  (FRAME_TYPE_DM | CONTROL_FIELD_BIT_PF));
        }

        if (ret < 0)
        {
          ninfo("Failed to encode the frame. Address (%d) \n", parse->address);
        }
        break;
      case FRAME_TYPE_SABM:
        if (!cmux_handle->channels[parse->address].active)
        {
          if (!parse->address)
          {
            ninfo("Control channel opened.\n");
          }
          else
          {
            ninfo("Logical channel %d opened.\n", parse->address);
          }
        }
        else
        {
          ninfo("SABM even though channel %d was already closed.\n", parse->address);
        }
        cmux_handle->channels[parse->address].active = 1;
        ret = cmux_encode_frame(cmux_handle->fd,
                                parse->address, NULL, 0x00,
                                FRAME_TYPE_UA | CONTROL_FIELD_BIT_PF);
        if (ret < 0)
        {
          ninfo("Failed to encode the frame. Address (%d) \n", parse->address);
        }

        break;
      }
    }
    frames_extracted++;
  }

  cmux_parse_delete(parse);

  return frames_extracted;
}

/****************************************************************************
 * Name: cmux_protocol_send
 *
 * Description:
 *
 * Input Parameters:
 *   cmux_handle:
 *   buffer:
 *   lenght:
 *    address:
 *
 * Returned Value:
 *
 ****************************************************************************/

int cmux_protocol_send(struct cmux_handle_s *cmux_handle, char *buffer, int lenght, int address)
{
  int ret;
  if (!buffer || !cmux_handle)
  {
    return ERROR;
  }

  ret = cmux_encode_frame(cmux_handle->fd,
                          address ,
                          buffer,
                          lenght, FRAME_TYPE_UIH);
  return ret;
}

/****************************************************************************
 * Name: cmux_protocol_create
 *
 * Description:
 *
 * Input Parameters:
 *   cmux_handle:
 *   tty_name:
 *   total_channels: 
 *
 * Returned Value:
 *
 ****************************************************************************/

int cmux_protocol_create(struct cmux_handle_s *cmux_handle, char *tty_name, int total_channels)
{
  struct chat_ctl ctl;
  int ret;

  cmux_handle->fd = open(tty_name, O_RDWR | O_NONBLOCK);
  if (cmux_handle->fd < 0)
  {
    ninfo("Unable to open file %s\n", tty_name);
    return -ENODEV;
  }

  ctl.echo = false;
  ctl.verbose = false;
  ctl.fd = cmux_handle->fd;
  ctl.timeout = 30;

  ret = chat(&ctl, &cmux_handle->cmux_script);
  if (ret < 0)
  {
    ninfo("Failed to run cmux script\n");
    goto exit;
  }

  cmux_handle->channels = malloc(sizeof(struct cmux_channel_s) * total_channels);
  if (!cmux_handle->channels)
  {
    ninfo("Failed to allocate memory to channels\n");
    goto exit;
  }

  ret = open_pseudo_tty(cmux_handle->channels, total_channels);
  if (ret < 0)
  {
    goto exit;
  }

  cmux_handle->stream = cmux_stream_buffer_create();
  if (!cmux_handle->stream)
  {
    ninfo("Failed to allocate memory to stream\n");
    goto exit;
  }

  ret = open_cmux_channels(cmux_handle->fd, total_channels );

  return ret;

  exit:

  if (cmux_handle->channels)
  {
    free(cmux_handle->channels);
  }

  if (cmux_handle->stream)
  {
    free(cmux_handle->stream);
  }

  close(cmux_handle->fd);

  return ret;

}
