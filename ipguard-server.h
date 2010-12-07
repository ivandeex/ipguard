/*
 * Based on Morpheus' Blocker
 * Copyright (C) 2004 Morpheus (ebutera at users.berlios.de)
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 */

/* ================================================== */
/* MAIN DECLARATIONS                                  */
/* ================================================== */

#define CHECK_INTERVAL 10	/* seconds between data checks */
#define CLIENT_TIMEOUT 10   /* disconnect clients after timeout */

#define LIST_DAT 1
#define LIST_PG1 2
#define LIST_PG2 3

extern int verbose;

int blocking_openlog(const char *filename);
int blocking_sigactions(void);
int blocking_openlist(char list_type, const char *list_file);
int blocking_ipaddr_blocked (const char *addr, char *answer, int answer_len);
int log_action (const char *fmt, ...);

/* ================================================== */
/* RBT DECLARATIONS                                   */
/* ================================================== */

#define BNAME_LEN	80

typedef unsigned long keyType;            /* type of key */
                
/* implementation dependend declarations */
typedef enum {
	STATUS_OK,
	STATUS_MEM_EXHAUSTED,
	STATUS_DUPLICATE_KEY,
	STATUS_KEY_NOT_FOUND,
	STATUS_MERGED,
	STATUS_SKIPPED
} statusEnum;

/* user data stored in tree */
typedef struct {
    char blockname[BNAME_LEN];                  /* optional related data */
    unsigned long ipmax;
    int hits;
} recType;

#define compLT(a,b) (a < b)
#define compEQ(a,b) (a == b)
#define compEQ2(a,b,c) ( (a > (b-1)) && (a < (c+1)) )	/* is ip in range? */
 
/* implementation independent declarations */
/* Red-Black tree description */
typedef enum { BLACK, RED } nodeColor;

typedef struct nodeTag {
	struct nodeTag *left;       /* left child */
	struct nodeTag *right;      /* right child */
	struct nodeTag *parent;     /* parent */
	nodeColor color;            /* node color (BLACK, RED) */
	keyType key;                /* key used for searching */
	recType rec;                /* user data */
} nodeType;

/* stats linked list */

typedef struct ll_elem {
	nodeType *rbt_node;
	struct ll_elem *next;
} ll_node;

statusEnum rbt_insert(keyType key, recType *rec);
statusEnum rbt_delete(keyType key);
statusEnum rbt_find(keyType key, recType *rec);
statusEnum rbt_find2(keyType key1, keyType key2, recType *rec);

void ll_show(void);
void ll_log(void);
void ll_clear(void);
void destroy_tree(void);

