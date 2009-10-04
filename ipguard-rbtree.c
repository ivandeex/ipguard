/* ================================================== */
/* RED-BLACK TREE                                     */
/* ================================================== */

/*
 * rbt.c Red-Black Trees implementation
 *
 * Author: Thomas Niemann <thomasn at epaperpress.com>
 * Modified by: Morpheus <ebutera at users.berlios.de>
 *
 * From Thomas guide about reb-black trees on oopweb.com:
 *
 * "Source code, when part of a software project, may be used 
 * freely without reference to the author.
 *
 * Thomas Niemann
 * Portland, Oregon"
 */

#define _GNU_SOURCE 1
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>
#include <string.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <signal.h>
#include <regex.h>
#include <time.h>
#include <syslog.h>

#include "ipguard-server.h"

/* Red-Black tree description */
#define NIL &sentinel           /* all leafs are sentinels */
static nodeType sentinel = { NIL, NIL, 0, BLACK, 0};

/* last node found, optimizes find/delete operations */
static nodeType *lastFind;

static nodeType *root = NIL;    /* root of Red-Black tree */

/* stats linked list */
static ll_node *ll_top;
static ll_node *ll_last;

int rbt_verbose = 0;


void
ll_clear(void)
{
	ll_node *current,*next;

	current = ll_top;
	if (current == NULL) {
		log_action("Warning! Empty blocklist, nothing to clear!");
	} else {
		do {
			next = current->next;
			free(current);
			current = next;
		} while(current);
		ll_top = NULL;
		ll_last = NULL;
	}
}


short int
ll_insert(nodeType *nt)
{
	ll_node *current;
        
	if (ll_top == NULL) {
		ll_top = (ll_node *)malloc(sizeof(ll_node));
		ll_top->rbt_node = nt;
		ll_top->next = NULL;
		ll_last = ll_top;
		return 0;
    } else {
		current = ll_top;
		while (current != NULL) {
			if (current->rbt_node->key == nt->key)
				return 1;	/* range already in stats */
			else
				current = current->next;
		}
		/* range not in stats, insert it */
		ll_last->next = (ll_node *)malloc(sizeof(ll_node));
		ll_last->next->rbt_node = nt;
		ll_last->next->next = NULL;
		ll_last = ll_last->next;
	}
	return 0;
}


void
ll_show()
{
	ll_node *current = ll_top;

	log_action("IPGuard Stats");

	while (current != NULL) {
		log_action("   %s - %d hits",
					current->rbt_node->rec.blockname,
					current->rbt_node->rec.hits);
		current = current->next;
	}
	log_action("----------------------------------------");
}


void
ll_log()
{
	ll_node *current = ll_top;
	log_action("IPGuard Stats");

    while (current != NULL) {
		log_action("   %s - %d hits",
					current->rbt_node->rec.blockname,
					current->rbt_node->rec.hits);
		current=current->next;
	}
	log_action("----------------------------------------");
}


static void
do_destroy_tree(nodeType *leaf)
{
	if (leaf != NIL && leaf) {
		do_destroy_tree(leaf->left);
		do_destroy_tree(leaf->right);
		free(leaf);
	}
}


void
destroy_tree()
{
	do_destroy_tree(root);
	root = NIL;
}


/**************************
 *  rotate node x to left *
 **************************/
static void
rotateLeft(nodeType *x)
{
	nodeType *y = x->right;

	/* establish x->right link */
	x->right = y->left;
	if (y->left != NIL) y->left->parent = x;

	/* establish y->parent link */
	if (y != NIL) y->parent = x->parent;
	if (x->parent) {
		if (x == x->parent->left)
			x->parent->left = y;
		else
			x->parent->right = y;
	} else {
		root = y;
	}

	/* link x and y */
	y->left = x;
	if (x != NIL) x->parent = y;
}


/****************************
 *  rotate node x to right  *
 ****************************/
static void
rotateRight(nodeType *x)
{
	nodeType *y = x->left;

	/* establish x->left link */
	x->left = y->right;
	if (y->right != NIL) y->right->parent = x;

	/* establish y->parent link */
	if (y != NIL) y->parent = x->parent;
	if (x->parent) {
		if (x == x->parent->right)
			x->parent->right = y;
		else
			x->parent->left = y;
	} else {
		root = y;
	}

	/* link x and y */
	y->right = x;
	if (x != NIL) x->parent = y;
}


/*************************************
 *  maintain Red-Black tree balance  *
 *  after inserting node x           *
 *************************************/
static void
insertFixup(nodeType *x)
{
	/* check Red-Black properties */
	while (x != root && x->parent->color == RED) {
		/* we have a violation */
		if (x->parent == x->parent->parent->left) {
			nodeType *y = x->parent->parent->right;
            if (y->color == RED) {
				/* uncle is RED */
				x->parent->color = BLACK;
				y->color = BLACK;
				x->parent->parent->color = RED;
				x = x->parent->parent;
			} else {
				/* uncle is BLACK */
				if (x == x->parent->right) {
					/* make x a left child */
					x = x->parent;
					rotateLeft(x);
				}

				/* recolor and rotate */
				x->parent->color = BLACK;
				x->parent->parent->color = RED;
				rotateRight(x->parent->parent);
			}
		} else {
			/* mirror image of above code */
			nodeType *y = x->parent->parent->left;
			if (y->color == RED) {
				/* uncle is RED */
				x->parent->color = BLACK;
				y->color = BLACK;
				x->parent->parent->color = RED;
				x = x->parent->parent;
			} else {
				/* uncle is BLACK */
				if (x == x->parent->left) {
					x = x->parent;
					rotateRight(x);
				}
				x->parent->color = BLACK;
				x->parent->parent->color = RED;
				rotateLeft(x->parent->parent);
			}
		}
	}
	root->color = BLACK;
}


/*************************************
 *  maintain Red-Black tree balance  *
 *  after deleting node x            *
 *************************************/
static void
deleteFixup(nodeType *x)
{
	while (x != root && x->color == BLACK) {
		if (x == x->parent->left) {
			nodeType *w = x->parent->right;
			if (w->color == RED) {
				w->color = BLACK;
				x->parent->color = RED;
				rotateLeft(x->parent);
				w = x->parent->right;
			}
			if (w->left->color == BLACK && w->right->color == BLACK) {
				w->color = RED;
				x = x->parent;
			} else {
				if (w->right->color == BLACK) {
					w->left->color = BLACK;
					w->color = RED;
					rotateRight(w);
					w = x->parent->right;
				}
				w->color = x->parent->color;
				x->parent->color = BLACK;
				w->right->color = BLACK;
				rotateLeft(x->parent);
				x = root;
			}
		} else {
			nodeType *w = x->parent->left;
			if (w->color == RED) {
				w->color = BLACK;
				x->parent->color = RED;
				rotateRight(x->parent);
				w = x->parent->left;
			}
			if (w->right->color == BLACK && w->left->color == BLACK) {
				w->color = RED;
				x = x->parent;
			} else {
				if (w->left->color == BLACK) {
					w->right->color = BLACK;
					w->color = RED;
					rotateLeft(w);
					w = x->parent->left;
				}
				w->color = x->parent->color;
				x->parent->color = BLACK;
				w->left->color = BLACK;
				rotateRight(x->parent);
				x = root;
			}
		}
	}
	x->color = BLACK;
}


/*****************************
 *  delete node z from tree  *
 *****************************/
statusEnum
rbt_delete(keyType key)
{
	nodeType *x, *y, *z;

	/* find node in tree */
	if (lastFind && compEQ(lastFind->key, key)) {
		/* if we just found node, use pointer */
		z = lastFind;
	} else {
		z = root;
		while (z != NIL) {
			if (compEQ(key, z->key)) 
				break;
			else
				z = compLT(key, z->key) ? z->left : z->right;
		}
		if (z == NIL)
			return STATUS_KEY_NOT_FOUND;
	}

	if (z->left == NIL || z->right == NIL) {
		/* y has a NIL node as a child */
		y = z;
	} else {
		/* find tree successor with a NIL node as a child */
		y = z->right;
		while (y->left != NIL) y = y->left;
	}

	/* x is y's only child */
	if (y->left != NIL)
		x = y->left;
	else
		x = y->right;

	/* remove y from the parent chain */
	x->parent = y->parent;
	if (y->parent) {
		if (y == y->parent->left)
			y->parent->left = x;
		else
			y->parent->right = x;
	} else {
		root = x;
	}

	if (y != z) {
		z->key = y->key;
		z->rec = y->rec;
	}

	if (y->color == BLACK)
		deleteFixup(x);

	free(y);
	lastFind = NULL;

	return STATUS_OK;
}


/***********************************************
 *  allocate node for data and insert in tree  *
 ***********************************************/
statusEnum
rbt_insert(keyType key, recType *rec)
{
	nodeType *current, *parent, *x;
	recType tmprec;
	int ret;
	
	/* find future parent */
	current = root;
	parent = 0;
	while (current != NIL) {
		if (compEQ2(current->key, key, rec->ipmax)) {
			/* current node key is inside new range to be inserted */
			strcpy(tmprec.blockname, rec->blockname);	/* block name from new range */
			if (compLT(current->rec.ipmax, rec->ipmax))
				tmprec.ipmax = rec->ipmax;
			else tmprec.ipmax = current->rec.ipmax;
			tmprec.hits = 0;
			/* printf("deleting node :%lu\n", current->key); */
			ret = rbt_delete(current->key);
			if ( ret != STATUS_OK )
				return (statusEnum)ret;
			ret = rbt_insert(key, &tmprec);
			if ( ret == STATUS_OK ) {
				return(STATUS_MERGED);
			}
			else
				return (statusEnum)ret;
		}
        if (compEQ(key, current->key)) {
			if ( rec->ipmax > current->rec.ipmax ) {
				current->rec.ipmax=rec->ipmax;
				strcpy(current->rec.blockname,rec->blockname);
				if (rbt_verbose) {
					log_action("Merged range '%s', with range '%s'",
								rec->blockname, current->rec.blockname);
				}
				return STATUS_MERGED;
			}
			if ( rec->ipmax == current->rec.ipmax )
				return STATUS_DUPLICATE_KEY;
			if ( rec->ipmax < current->rec.ipmax )
				return STATUS_SKIPPED;
		}
		/* check if lower ip (key) is already in a range */
		if (compEQ2(key, current->key,current->rec.ipmax)) {
			if (rec->ipmax > current->rec.ipmax) {
				current->rec.ipmax=rec->ipmax;
				if (rbt_verbose) {
					log_action("Merged range '%s', with range '%s'",
								rec->blockname, current->rec.blockname);
				}
				return STATUS_MERGED;
			}
			else {
				if (rbt_verbose) {
					log_action("Skipping useless range: %s", rec->blockname);
				}
				return STATUS_SKIPPED;
			}
		}
		/* check if higher ip (ipmax) is already in a range */
        parent = current;
        current = compLT(key, current->key) ?
            current->left : current->right;
    }

	/* setup new node */
	x = (nodeType *)malloc(sizeof(nodeType));
	if (x == NULL)
		return STATUS_MEM_EXHAUSTED;
	x->parent = parent;
	x->left = NIL;
	x->right = NIL;
	x->color = RED;
	x->key = key;
	x->rec = *rec;

	/* insert node in tree */
	if (parent) {
		if(compLT(key, parent->key))
			parent->left = x;
		else
			parent->right = x;
	} else {
		root = x;
	}
	/* printf("new node, key: %lu, parent: %lu\n", x->key, parent ? parent->key : 0); */
	insertFixup(x);
	lastFind = NULL;

	return STATUS_OK;
}


/*******************************
 *  find node containing data  *
 *******************************/
statusEnum
rbt_find(keyType key, recType *rec)
{
	nodeType *current = root;

	while(current != NIL) {
		if(compEQ2(key, current->key,current->rec.ipmax)) {
			ll_insert(current);
			(current->rec.hits)++;
			*rec = current->rec;
			lastFind = current;
			return STATUS_OK;
		} else {
			current = compLT(key, current->key) ? current->left : current->right;
		}
	}

	return STATUS_KEY_NOT_FOUND;
}


/*******************************
 *  find node containing data  *
 *******************************/
statusEnum
rbt_find2(keyType key1, keyType key2, recType *rec)
{
	nodeType *current1 = root;
	nodeType *current2 = root;

	while (current1 != NIL || current2 != NIL) {
		if (current1 != NIL) {
			if (compEQ2(key1, current1->key,current1->rec.ipmax)) {
				ll_insert(current1);
				(current1->rec.hits)++;
				*rec = current1->rec;
				lastFind = current1;
				return STATUS_OK;
			} else current1 = compLT (key1, current1->key) ? current1->left : current1->right;
		}
		if (current2 != NIL) {
			if (compEQ2(key2, current2->key,current2->rec.ipmax)) {
				ll_insert(current2);
				(current2->rec.hits)++;
				*rec = current2->rec;
				lastFind = current2;
				return STATUS_OK;
			} else {
				current2 = compLT(key2, current2->key) ? current2->left : current2->right;
			}
		}
	}

    return STATUS_KEY_NOT_FOUND;
}

