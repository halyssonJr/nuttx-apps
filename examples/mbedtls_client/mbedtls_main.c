/****************************************************************************
 * apps/examples/mbedtls_client/mbedtls_main.c
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
#include <stdio.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdarg.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <netdb.h>

#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/debug.h"
#include "mbedtls/error.h"

#include "mbedtls_crt.h"
#define SERVER_PORT 80
#define SERVER_NAME "postman-echo.com"
#define SERVER_PATH "get?foo1=bar1&foo2=bar2"
#define BUFFER_SIZE  4096

mbedtls_net_context *server_fd;
mbedtls_ssl_context ssl;
mbedtls_entropy_context entropy;
mbedtls_ctr_drbg_context ctr_drbg;
mbedtls_ssl_config conf;
mbedtls_x509_crt cacert;
int root_ca_pems_len = sizeof(root_ca_pems);

static void my_debug( void *ctx, int level, const char *file, int line, const char *str )
{
    ((void) level);
    fprintf( (FILE *) ctx, "%s:%04d: %s", file, line, str );
    fflush( (FILE *) ctx );
}

int mbedtls_init(void)
{
    int ret = 0;

    mbedtls_ssl_config_init(&conf);
    mbedtls_ssl_init(&ssl);
    mbedtls_x509_crt_init( &cacert);
    mbedtls_ctr_drbg_init( &ctr_drbg);
    mbedtls_entropy_init( &entropy);
    mbedtls_debug_set_threshold(4);
    mbedtls_ssl_conf_dbg( &conf, my_debug, stdout );

    if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                        NULL, 0)) != 0)
    {
        printf("Falied, mbedtls_ctr_drbg_seed ret=%d\n", ret);
        return -ret;
    }
    
    printf("Loading the CA root certificate ...\n");

    ret = mbedtls_x509_crt_parse( &cacert, (const unsigned char *)root_ca_pems, root_ca_pems_len);
    if (ret < 0)
    {
        printf ("Failed, mbedtls_x509_crt_parse ret= %d\n", ret);
        return -ret;
    }
    mbedtls_ssl_conf_ca_chain( &conf, &cacert, NULL);
    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
    mbedtls_ssl_config_defaults(&conf, 
                                    MBEDTLS_SSL_IS_CLIENT, 
                                    MBEDTLS_SSL_TRANSPORT_STREAM,
                                    MBEDTLS_SSL_PRESET_DEFAULT);
    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
    if (ret < 0)
    {
        printf("Failed, mbedtls_ssl_config_defaults ret=%d\n");
        fflush(stdout);
        return -ret;
    }
    return ret;
}

void mbedtls_free(void)
{
    mbedtls_net_free(&server_fd);
    mbedtls_x509_crt_free(&cacert );
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
}

int init_server(char *host_name, int port)
{
    struct sockaddr_in addr;
    struct addrinfo hints, *server_info;
    FAR struct addrinfo *itr;
    int fd, ret;

    memset (&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    ret = getaddrinfo (host_name, "80", &hints, &server_info);
    if (ret != 0)
    {
        printf("Falied, getaddrinfo ret = 0x%x\n",ret);
        return -1;
    }
    itr = server_info;
    do
    {
        fd = socket (itr->ai_family, itr->ai_socktype, itr->ai_protocol);
        if (fd < 0)
        {
            continue;
        }
        ret = connect(fd, itr->ai_addr, itr->ai_addrlen);
        if (ret == 0)
        {
            break;
        }
        close(fd);
        fd = -1;
    } while ((itr = itr->ai_next) != NULL);
    freeaddrinfo(server_info);

    // fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
    {
        printf("Falied, socket ret = %d\n", fd);
        return -1;
    }

    // struct hostent *host = gethostbyname(host_name);
    
    // if(host == NULL)
    // {
    //     printf("Falied, gethostbyname \n");
    //     close(fd);
    //     return -1;
    // }
    
    // addr.sin_family = AF_INET;
    // addr.sin_port   = htons(SERVER_PORT);

    // memcpy( (void *) &addr.sin_addr,
    //         (void *) host->h_addr,
    //                 host->h_length);

    // if(inet_pton(AF_INET, "13.248.169.48", &addr.sin_addr) < 0)
    // {
    //     printf("Failed, inet_pton \n");
    //     return -1;
    // }

    // if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    // {
    //     printf("Falied, connect \n");
    //     close(fd);
    //     return -1;
    // }
    printf("passed\n");
    return fd;
}

int main(int argc, char *argv[])
{

    int ret = 0, len;
    char buffer[BUFFER_SIZE];
    ret =  mbedtls_init();
    
    if (ret < 0)
    {
        printf("Falied, mbedtls_init ret = 0x%x\n", ret);
        goto exit;
    }
    server_fd = (mbedtls_net_context *)malloc(sizeof(mbedtls_net_context));
    mbedtls_net_init(server_fd);

    ret = mbedtls_ssl_setup(&ssl, &conf);
    if (ret < 0)
    {
        printf("Falied, mbedtls_ssl_setup ret = 0x%x\n", -ret);
        goto exit;
    }

    ret = mbedtls_ssl_set_hostname(&ssl, SERVER_NAME);
    if (ret < 0)
    {
        printf("Falied, mbedtls_ssl_set_hostname ret = 0x%x\n", -ret);
        goto exit;
    }

    mbedtls_net_connect(server_fd, SERVER_NAME, "80", MBEDTLS_NET_PROTO_TCP);

    if ( ret < 0)
    {
        printf( "Falied, mbedtls_net_connect \n", ret );
        goto exit;
    }

    mbedtls_ssl_set_bio(&ssl, 
                            server_fd, 
                            mbedtls_net_send, 
                            mbedtls_net_recv, NULL);
    do
    {
        ret = mbedtls_ssl_handshake(&ssl);
    } 
    while (ret!= 0 && (ret == MBEDTLS_ERR_SSL_WANT_WRITE || 
             ret == MBEDTLS_ERR_SSL_WANT_WRITE));

    if (ret < 0)
    {
        printf("Falied, mbedtls_ssl_handshake returned -0x%04x\n", -ret);
        goto exit;
    }

    printf("Handshake Completed \n");
    memset(&buffer, 0, sizeof (buffer));

    // len = sprintf(buffer, "GET %s HTTP/1.1\r\nHost: %s\r\n\r\n", SERVER_PATH, SERVER_NAME);
    // printf("Request: %s\n", buffer);

    // do
    // {
    //     ret = mbedtls_ssl_write(&ssl, buffer, len);
    // } while (ret!= 0 && (ret == MBEDTLS_ERR_SSL_WANT_WRITE || 
    //          ret == MBEDTLS_ERR_SSL_WANT_WRITE));
    
    // if (ret < 0)
    // {
    //      printf("Falied, mbedtls_ssl_write returned -0x%04x\n", -ret);
    //     goto exit;
    // }

    // do
    // {
    //     len = sizeof(buffer) - 1;
    //     memset(buffer, 0, sizeof(buffer));
    //     ret = mbedtls_ssl_read(&ssl, buffer, len);

    //     if (ret == MBEDTLS_ERR_SSL_WANT_WRITE || ret == MBEDTLS_ERR_SSL_WANT_WRITE)
    //     {
    //         continue;
    //     }
        
    //     if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY)
    //     {
    //         break;
    //     }

    //     if (ret < 0)
    //     {
    //         printf("Falied, mbedtls_ssl_write returned %d\n",ret);
    //         break;
    //     }

    //     if (ret == 0)
    //     {
    //         printf("EOF\n");
    //         break;
    //     }

    //     len = ret;
    //     printf(" %d bytes read\n%s", len, (char*)buffer);

    // } while (1);

    // mbedtls_ssl_close_notify(&ssl);

    return (ret);

    exit:
    mbedtls_free();
    return 0; 
}
