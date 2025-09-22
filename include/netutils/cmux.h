/****************************************************************************
 * apps/include/netutils/chat.h
 *
 * SPDX-License-Identifier: BSD-3-Clause
 * SPDX-FileCopyrightText: 2016 Vladimir Komendantskiy. All rights reserved.
 * SPDX-FileContributor: Vladimir Komendantskiy <vladimir@moixaenergy.com>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 * 3. Neither the name NuttX nor the names of its contributors may be
 *    used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 ****************************************************************************/

#ifndef __APPS_INCLUDE_NETUTILS_CMUX_H
#define __APPS_INCLUDE_NETUTILS_CMUX_H

/****************************************************************************
 * Included Files
 ****************************************************************************/

#include <sys/time.h>
#include <stdbool.h>
#include <debug.h>
#include <errno.h>

#define CMUX_CHANNEL_NAME_SZ    (64)

/****************************************************************************
 * Public Types
 ****************************************************************************/

/* Type of chat control parameters. */
struct cmux_channel_s
{
    int master_fd;
    int slave_fd;
    int dlci; /* Data Link Connection Identifier */
    char slave_path[CMUX_CHANNEL_NAME_SZ]; /* Path do slave (/dev/pts/X) */
    bool active;
    time_t last_activity;
};

struct cmux_handle_s
{
    int fd;
    FAR const char * cmux_script;
    struct cmux_channel_s *channels;
    struct cmux_stream_buffer_s *stream;
};

/****************************************************************************
 * Public Function Prototypes
 ****************************************************************************/

#undef EXTERN
#if defined(__cplusplus)
#define EXTERN extern "C"
extern "C"
{
#else
#define EXTERN extern
#endif

int cmux_create(struct cmux_handle_s *cmux_handle, FAR const char * script, char *tty_name, int total_channels);
int cmux_send(struct cmux_handle_s *cmux_handle, char *buffer, int lenght, int address);
int cmux_extract(struct cmux_handle_s *cmux_handle, char *input, int count);

#undef EXTERN
#ifdef __cplusplus
}
#endif

#endif /* __APPS_INCLUDE_NETUTILS_CMUX_H */
