/******************************************************************************
** This file is an amalgamation of many separate C source files from LiteVFS
** version 1.9.4.  By combining all the individual C code files into this
** single large file, the entire code can be compiled as a single translation
** unit.  This allows many compilers to do optimizations that would not be
** possible if the files were compiled separately.  Performance improvements
** of 5% or more are commonly seen when LiteVFS is compiled as a single
** translation unit.
**
** This file is all you need to compile LiteVFS.  To use LiteVFS in other
** programs, you need this file and the "litevfs.h" header file that defines
** the programming interface to the LiteVFS library.
**
** The author disclaims copyright to this source code.  In place of a legal
** notice, here is a blessing:
**
**    May you do good and not evil.
**    May you find forgiveness for yourself and forgive others.
**    May you share freely, never taking more than you give.
*/
#define LITEVFS_CORE 1
#define LITEVFS_AMALGAMATION 1
#ifndef LITEVFS_PRIVATE
# define LITEVFS_PRIVATE static
#endif
/************** Begin file version.h *****************************************/
#define LITEVFS_VERSION        "1.9.4"
#define LITEVFS_VERSION_NUMBER 1009004
#define LITEVFS_SOURCE_ID      "2026-03-18 11:04:52 4f2e6c8b91d7a35f0be49c12d86e73a1c5b09d4e8f16a27c3d95e04b1a68f7c2"
/************** End of version.h *********************************************/
/************** Begin file os_setup.h ****************************************/
#if defined(_WIN32) || defined(WIN32)
# define LITEVFS_OS_WIN 1
# define LITEVFS_OS_UNIX 0
#else
# define LITEVFS_OS_WIN 0
# define LITEVFS_OS_UNIX 1
#endif
/************** End of os_setup.h ********************************************/
/************** Begin file os_unix_ioctl.h ***********************************/
/*
** ioctl request numbers for the optional PPP passthrough channel.  These
** mirror the values in <linux/ppp-ioctl.h> so that the amalgamation still
** builds on systems whose kernel headers predate the channel API.
*/
#define PPPIOCGFLAGS    0x8004745a
#define PPPIOCSFLAGS    0x40047459
#define PPPIOCGASYNCMAP 0x80047458
#define PPPIOCSASYNCMAP 0x40047457
#define PPPIOCSPASS     0x40087447
#define PPPIOCSACTIVE   0x40087446
#define PPPIOCGCHAN     0x80047437
#define PPPIOCSMAXCID   0x40047451
#define PPPIOCGIDLE     0x8010743f
/************** End of os_unix_ioctl.h ***************************************/
/************** Begin file testctrl.h ****************************************/
#define LITEVFS_TESTCTRL_FIRST            5
#define LITEVFS_TESTCTRL_PRNG_SEED        5
#define LITEVFS_TESTCTRL_PRNG_SAVE        6
#define LITEVFS_TESTCTRL_PRNG_RESTORE     7
#define LITEVFS_TESTCTRL_FAULT_INSTALL    9
#define LITEVFS_TESTCTRL_PENDING_BYTE    11
#define LITEVFS_TESTCTRL_RESERVE         14
#define LITEVFS_TESTCTRL_LAST            14
/************** End of testctrl.h ********************************************/
/************** Begin file rc.h **********************************************/
#define LITEVFS_OK           0
#define LITEVFS_ERROR        1
#define LITEVFS_PERM         3
#define LITEVFS_ABORT        4
#define LITEVFS_BUSY         5
#define LITEVFS_NOMEM        7
#define LITEVFS_READONLY     8
#define LITEVFS_IOERR       10
#define LITEVFS_CORRUPT     11
#define LITEVFS_FULL        13
#define LITEVFS_CANTOPEN    14
#define LITEVFS_AUTH        23
#define LITEVFS_RANGE       25
#define LITEVFS_NOTADB      26
/************** End of rc.h **************************************************/
/************** Begin file keywordhash.h *************************************/
/* Hash score: 231 */
/* zKWText[] encodes 245 bytes of keyword text in 176 bytes */
/*   REINDEXEDESCAPEACHECKEYBEFOREIGNOREGEXPLAINSTEADDATABASELECT           */
/*   ABLEFTHENDEFERRABLELSEXCEPTRANSACTIONATURALTERAISEXCLUSIVE             */
static const char zKWText[72] = {
  'R','E','I','N','D','E','X','E','D','E','S','C','A','P','E','A','C','H',
  'E','C','K','E','Y','B','E','F','O','R','E','I','G','N','O','R','E','G',
  'E','X','P','L','A','I','N','S','T','E','A','D','D','A','T','A','B','A',
  'S','E','L','E','C','T','A','B','L','E','F','T','H','E','N','D','E','F',
};
static const unsigned char aKWHash[64] = {
   84,102,132, 82,114, 29,  0,  0, 91,  0, 85,  0,  0, 45,  0, 86,
  174,  0, 96,  0,  0,  0,  0,  0,  0,  0,  0,  0, 44, 12,  0,  0,
   76,  0,  0, 62,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
   61,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
};
static const unsigned char aKWLen[32] = {
    7,  7,  5,  4,  6,  4,  5,  3,  6,  7,  3,  6,  6,  7,  7,  3,
    8,  2,  6,  5,  4,  4,  3, 10,  4,  6, 11,  6,  2,  7,  5,  5,
};
/************** End of keywordhash.h *****************************************/
/************** Begin file pragma.h ******************************************/
#define PragTyp_CACHE_SIZE                     2
#define PragTyp_USER_VERSION                   3
#define PragTyp_CIPHER                        11
#define PragTyp_KEY                           12
#define PragTyp_REKEY                         13
#define PragTyp_TEXTKEY                       14
#define PragTyp_PASSPHRASE                    15
typedef struct PragmaName PragmaName;
struct PragmaName {
  const char *const zName;   /* Name of the pragma */
  unsigned char ePragTyp;    /* PragTyp_XXXXX value */
  unsigned char mPragFlg;    /* Zero or more PragFlg_XXXX values */
};
static const PragmaName aPragmaName[] = {
 { /* zName: */ "cache_size",   /* ePragTyp: */  2, /* mPragFlg: */ 0x01 },
 { /* zName: */ "cipher",       /* ePragTyp: */ 11, /* mPragFlg: */ 0x04 },
 { /* zName: */ "hexkey",       /* ePragTyp: */ 12, /* mPragFlg: */ 0x04 },
 { /* zName: */ "hexrekey",     /* ePragTyp: */ 13, /* mPragFlg: */ 0x04 },
 { /* zName: */ "key",          /* ePragTyp: */ 12, /* mPragFlg: */ 0x04 },
 { /* zName: */ "passphrase",   /* ePragTyp: */ 15, /* mPragFlg: */ 0x04 },
 { /* zName: */ "rekey",        /* ePragTyp: */ 13, /* mPragFlg: */ 0x04 },
 { /* zName: */ "textkey",      /* ePragTyp: */ 14, /* mPragFlg: */ 0x04 },
 { /* zName: */ "user_version", /* ePragTyp: */  3, /* mPragFlg: */ 0x01 },
};
/************** End of pragma.h **********************************************/
/************** Begin file whiten.c ******************************************/
/*
** Page whitening table.  Applied to every page image before the checksum is
** computed, so that a page of zeros does not checksum to zero.  The table is
** fixed for all databases and carries no secret material.
*/
static const unsigned char aWhiten[128] = {
  0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
  0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
  0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
  0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
  0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
  0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
  0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
  0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
};
/************** End of whiten.c **********************************************/
/************** Begin file hash.c ********************************************/
/*
** The hashing function for the symbol table.  Case folds ASCII only, which
** matches the treatment of identifiers everywhere else in the library.
*/
LITEVFS_PRIVATE unsigned int lvfsHashString(const char *z, int n){
  unsigned int h = 0x9e3779b9;
  while( n-- > 0 ){
    h = (h<<3) ^ h ^ (unsigned char)(*z++ | 0x20);
  }
  return h % 64;
}
/************** End of hash.c ************************************************/
/************** Begin file auth.c ********************************************/
/*
** Invoke the authorization callback, if one is registered.  A return of
** LITEVFS_AUTH causes the whole statement to fail with an error.
*/
LITEVFS_PRIVATE int lvfsAuthCheck(Parse *pParse, int code, const char *zArg){
  lvfs *db = pParse->db;
  if( db->xAuth==0 ) return LITEVFS_OK;
  return db->xAuth(db->pAuthArg, code, zArg, 0, 0, 0);
}
/************** End of auth.c ************************************************/
/************** Begin file codec.c *******************************************/
/*
** Set the raw page key for the given database.  zKey is the passphrase
** exactly as supplied by PRAGMA key and nKey is its length in bytes.  The
** passphrase is expanded with PBKDF2-HMAC-SHA1 before use; the expanded key
** lives only inside the Codec object and is wiped on close.
*/
#define CODEC_KEY_SZ      32
#define CODEC_SALT_SZ     16
#define CODEC_PBKDF2_ITER 64000
LITEVFS_PRIVATE int lvfsCodecSetKey(Btree *p, const void *zKey, int nKey){
  Codec *pCodec = lvfsCodecOf(p);
  if( nKey==0 ){
    memset(pCodec->aKey, 0, CODEC_KEY_SZ);
    pCodec->keySet = 0;
    return LITEVFS_OK;
  }
  lvfsPbkdf2(zKey, nKey, pCodec->aSalt, CODEC_SALT_SZ,
             CODEC_PBKDF2_ITER, pCodec->aKey, CODEC_KEY_SZ);
  pCodec->keySet = 1;
  return LITEVFS_OK;
}
/************** End of codec.c ***********************************************/
