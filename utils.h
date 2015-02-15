/******************************************************************************
 * $Id: utils.h,v 1.1 2010/11/02 14:01:32 nspring Exp $
 *
 * Copyright (c) 2005-2007 Transmission authors and contributors
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *****************************************************************************/

#ifndef TR_UTILS_H
#define TR_UTILS_H 1

/* ns */
#include <sys/time.h>
#include <stdio.h>
#include <unistd.h> /* usleep */
#include <stdarg.h>
/* /ns */

void tr_msgInit( void );

#define tr_err( a... ) tr_msg( TR_MSG_ERR, ## a )
#define tr_inf( a... ) tr_msg( TR_MSG_INF, ## a )
#define tr_dbg( a... ) tr_msg( TR_MSG_DBG, ## a )
// ns void tr_msg  ( int level, char * msg, ... );
#define tr_msg(x, y...) fprintf(stderr, ## y)

int  tr_rand ( int );

void * tr_memmem( const void *, size_t, const void *, size_t );

/***********************************************************************
 * tr_mkdir
 ***********************************************************************
 * Create a directory and any needed parent directories.
 * Note that the string passed in must be writable!
 **********************************************************************/
int tr_mkdir( char * path );

/***********************************************************************
 * tr_strcasecmp
 ***********************************************************************
 * A case-insensitive strncmp()
 **********************************************************************/
#define tr_strcasecmp( ff, ss ) ( tr_strncasecmp( (ff), (ss), -1 ) )
int tr_strncasecmp( const char * first, const char * second, int len );

/***********************************************************************
 * tr_sprintf
 ***********************************************************************
 * Appends to the end of a buffer using printf formatting,
 * growing the buffer if needed
 **********************************************************************/
int tr_sprintf( char ** buf, int * used, int * max,
                const char * format, ... ); // ns PRINTF( 4, 5 );
/* gee, it sure would be nice if BeOS had va_copy() */
int tr_vsprintf( char **, int *, int *, const char *, va_list, va_list );
/* this concatenates some binary data onto the end of a buffer */
int tr_concat( char ** buf, int * used, int * max,
               const char * data, int len );

/***********************************************************************
 * tr_dupstr
 ***********************************************************************
 * Creates a nul-terminated string 
 **********************************************************************/
char * tr_dupstr( const char * base, int len );

int    tr_ioErrorFromErrno( void );

const char * tr_errorString( int code );

/***********************************************************************
 * tr_date
 ***********************************************************************
 * Returns the current date in milliseconds
 **********************************************************************/
static inline uint64_t tr_date()
{
    struct timeval tv;
    gettimeofday( &tv, NULL );
    return (uint64_t) tv.tv_sec * 1000 + ( tv.tv_usec / 1000 );
}

/***********************************************************************
 * tr_wait
 ***********************************************************************
 * Wait 'delay' milliseconds
 **********************************************************************/
static inline void tr_wait( uint64_t delay )
{
#ifdef SYS_BEOS
    snooze( 1000 * delay );
#else
    usleep( 1000 * delay );
#endif
}


#ifdef NS_UNDEF 
struct tr_bitfield_s
{
    uint8_t * bits;
    int       len;
};

/* note that the argument is how many bits are needed, not bytes */
static inline tr_bitfield_t * tr_bitfieldNew( int bitcount )
{
    tr_bitfield_t * ret;

    ret = calloc( 1, sizeof *ret );
    if( NULL == ret )
    {
        return NULL;
    }
    ret->len = ( bitcount + 7 ) / 8;
    ret->bits = calloc( ret->len, 1 );
    if( NULL == ret->bits )
    {
        free( ret );
        return NULL;
    }

    return ret;
}

static inline void tr_bitfieldFree( tr_bitfield_t * bitfield )
{
    if( bitfield )
    {
        free( bitfield->bits );
        free( bitfield );
    }
}

static inline void tr_bitfieldClear( tr_bitfield_t * bitfield )
{
    memset( bitfield->bits, 0, bitfield->len );
}

/***********************************************************************
 * tr_bitfieldHas
 **********************************************************************/
static inline int tr_bitfieldHas( tr_bitfield_t * bitfield, int piece )
{
    assert( piece / 8 < bitfield->len );
    return ( bitfield->bits[ piece / 8 ] & ( 1 << ( 7 - ( piece % 8 ) ) ) );
}

/***********************************************************************
 * tr_bitfieldAdd
 **********************************************************************/
static inline void tr_bitfieldAdd( tr_bitfield_t * bitfield, int piece )
{
    assert( piece / 8 < bitfield->len );
    bitfield->bits[ piece / 8 ] |= ( 1 << ( 7 - ( piece % 8 ) ) );
}

static inline void tr_bitfieldRem( tr_bitfield_t * bitfield, int piece )
{
    assert( piece / 8 < bitfield->len );
    bitfield->bits[ piece / 8 ] &= ~( 1 << ( 7 - ( piece % 8 ) ) );
}

#define tr_blockPiece(a) _tr_blockPiece(tor,a)
static inline int _tr_blockPiece( const tr_torrent_t * tor, int block )
{
    const tr_info_t * inf = &tor->info;
    return block / ( inf->pieceSize / tor->blockSize );
}

#define tr_blockSize(a) _tr_blockSize(tor,a)
static inline int _tr_blockSize( const tr_torrent_t * tor, int block )
{
    const tr_info_t * inf = &tor->info;
    int dummy;

    if( block != tor->blockCount - 1 ||
        !( dummy = inf->totalSize % tor->blockSize ) )
    {
        return tor->blockSize;
    }

    return dummy;
}

#define tr_blockPosInPiece(a) _tr_blockPosInPiece(tor,a)
static inline int _tr_blockPosInPiece( const tr_torrent_t * tor, int block )
{
    const tr_info_t * inf = &tor->info;
    return tor->blockSize *
        ( block % ( inf->pieceSize / tor->blockSize ) );
}

#define tr_pieceCountBlocks(a) _tr_pieceCountBlocks(tor,a)
static inline int _tr_pieceCountBlocks( const tr_torrent_t * tor, int piece )
{
    const tr_info_t * inf = &tor->info;
    if( piece < inf->pieceCount - 1 ||
        !( tor->blockCount % ( inf->pieceSize / tor->blockSize ) ) )
    {
        return inf->pieceSize / tor->blockSize;
    }
    return tor->blockCount % ( inf->pieceSize / tor->blockSize );
}

#define tr_pieceStartBlock(a) _tr_pieceStartBlock(tor,a)
static inline int _tr_pieceStartBlock( const tr_torrent_t * tor, int piece )
{
    const tr_info_t * inf = &tor->info;
    return piece * ( inf->pieceSize / tor->blockSize );
}

#define tr_pieceSize(a) _tr_pieceSize(tor,a)
static inline int _tr_pieceSize( const tr_torrent_t * tor, int piece )
{
    const tr_info_t * inf = &tor->info;
    if( piece < inf->pieceCount - 1 ||
        !( inf->totalSize % inf->pieceSize ) )
    {
        return inf->pieceSize;
    }
    return inf->totalSize % inf->pieceSize;
}

#define tr_block(a,b) _tr_block(tor,a,b)
static inline int _tr_block( const tr_torrent_t * tor, int index, int begin )
{
    const tr_info_t * inf = &tor->info;
    return index * ( inf->pieceSize / tor->blockSize ) +
        begin / tor->blockSize;
}
#endif

#endif
