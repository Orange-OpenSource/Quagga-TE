/*
 * This is an implementation of BGP Link State as per RFC 7752
 *
 * Copyright (C) 2020 Orange http://www.orange.com
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>

#include "prefix.h"
#include "table.h"
#include "memory.h"
#include "log.h"
#include "vty.h"
#include "stream.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_lsdb.h"
#include "bgpd/bgp_ls.h"

/* Lock LS. */
struct bgp_ls *bgp_ls_lock(struct bgp_ls *ls)
{
	ls->lock++;
	return ls;
}

/* Unlock LS. */
void bgp_ls_unlock(struct bgp_ls **ls)
{
	/* This is sanity check. */
	if (!ls || !*ls)
		return;

	(*ls)->lock--;

	assert((*ls)->lock >= 0);

	if ((*ls)->lock == 0) {
		bgp_ls_free(*ls);
		*ls = NULL;
	}
}

static unsigned int ls_hash_key_make(void *p)
{
	const struct bgp_ls *link_state_attr = p;

	return jhash(link_state_attr, link_state_attr->header.nlri_length, 0);
}


struct bgp_lsdb *bgp_lsdb_new()
{
	struct bgp_lsdb *new;

	new = XCALLOC(MTYPE_BGP_LSDB, sizeof(struct bgp_lsdb));
	bgp_lsdb_init(new);

	return new;
}

void bgp_lsdb_init(struct bgp_lsdb *lsdb)
{
	int i;

	for (i = BGP_LS_MIN_NLRI_TYPE; i < BGP_LS_MIN_NLRI_TYPE; i++)
		lsdb->type[i].db = route_table_init();
}

void bgp_lsdb_free(struct bgp_lsdb *lsdb)
{
	bgp_lsdb_cleanup(lsdb);
	XFREE(MTYPE_BGP_LSDB, lsdb);
}

void bgp_lsdb_cleanup(struct bgp_lsdb *lsdb)
{
	int i;
	assert(lsdb);
	assert(lsdb->total == 0);

	bgp_lsdb_delete_all(lsdb);

	for (i = BGP_LS_MIN_NLRI_TYPE; i < BGP_LS_MIN_NLRI_TYPE; i++)
		route_table_finish(lsdb->type[i].db);
}
/*Add attribute into a buffer*/

struct bgp_ls *ls_attr_node_set(struct attr *attr)
{
	struct bgp_ls *ls;
	if (attr) {
		/*--------mp_bgpls_nlri & mp_bgpls_nlri------------*/
		ls->header = attr->mp_bgpls_nlri->header;
		ls->node->proto_id = attr->mp_bgpls_nlri->ext_hdr.proto_id;
		ls->node->nlri_identifier =
			attr->mp_bgpls_nlri->ext_hdr.nlri_identifier;
		ls->node->local_node = attr->mp_bgpls_nlri->local_node;
		/*---------------link_state-------------------*/
		ls->node->mid = attr->mp_bgpls_nlri->mid;
		ls->node->nfb = attr->link_state_attr->nfb;
		ls->node->onp = attr->link_state_attr->onp;
		ls->node->nn = attr->link_state_attr->nn;
		ls->node->iiai = attr->link_state_attr->iiai;
		ls->node->i4ridofln = attr->link_state_attr->i4ridofln;
		ls->node->i6ridofln = attr->link_state_attr->i6ridofln;
		ls->node->i4ridofrn = attr->link_state_attr->i4ridofrn;
		ls->node->i6ridofrn = attr->link_state_attr->i6ridofrn;
	}
	return ls;
}

struct bgp_ls *ls_attr_link_set(struct attr *attr)
{
	struct bgp_ls *ls;
	if (attr) {
		/*--------mp_bgpls_nlri & mp_bgpls_nlri------------*/
		ls->header = attr->mp_bgpls_nlri->header;
		ls->link->proto_id = attr->mp_bgpls_nlri->ext_hdr.proto_id;
		ls->link->nlri_identifier =
			attr->mp_bgpls_nlri->ext_hdr.nlri_identifier;
		ls->link->local_node = attr->mp_bgpls_nlri->local_node;
		ls->link->remote_node = attr->mp_bgpls_nlri->remote_node;
		ls->link->llri = attr->mp_bgpls_nlri->llri;
		ls->link->i4ia = attr->mp_bgpls_nlri->i4ia;
		ls->link->i4na = attr->mp_bgpls_nlri->i4na;
		ls->link->i6ia = attr->mp_bgpls_nlri->i6ia;
		ls->link->i4na = attr->mp_bgpls_nlri->i6na;
		ls->link->mid = attr->mp_bgpls_nlri->mid;
		/*---------------link_state-------------------*/
		ls->link->i4ridofln = attr->link_state_attr->i4ridofln;
		ls->link->i6ridofln = attr->link_state_attr->i6ridofln;
		ls->link->i4ridofrn = attr->link_state_attr->i4ridofrn;
		ls->link->i6ridofrn = attr->link_state_attr->i6ridofrn;
		ls->link->agc = attr->link_state_attr->agc;
		ls->link->mlb = attr->link_state_attr->mlb;
		ls->link->mrlb = attr->link_state_attr->mrlb;
		ls->link->urb = attr->link_state_attr->urb;
		ls->link->tdm = attr->link_state_attr->tdm;
		ls->link->lpt = attr->link_state_attr->lpt;
		ls->link->mpm = attr->link_state_attr->mpm;
		ls->link->igpm = attr->link_state_attr->igpm;
		ls->link->srlg = attr->link_state_attr->srlg;
		ls->link->ola = attr->link_state_attr->ola;
		ls->link->lna = attr->link_state_attr->lna;
	}
	return ls;
}

struct bgp_ls *ls_attr_ipv4_prefix_set(struct attr *attr)
{
	struct bgp_ls *ls;
	if (attr) {
		/*--------mp_bgpls_nlri & mp_bgpls_nlri------------*/
		ls->ipv4_prefix->header = attr->mp_bgpls_nlri->header;
		ls->ipv4_prefix->proto_id =
			attr->mp_bgpls_nlri->ext_hdr.proto_id;
		ls->node->nlri_identifier =
			attr->mp_bgpls_nlri->ext_hdr.nlri_identifier;
		ls->ipv4_prefix->local_node = attr->mp_bgpls_nlri->local_node;
		ls->ipv4_prefix->mid = attr->mp_bgpls_nlri->mid;
		ls->ipv4_prefix->ort = attr->mp_bgpls_nlri->ort;
		ls->ipv4_prefix->ipreach = attr->mp_bgpls_nlri->ipreach;
		/*---------------link_state-------------------*/
		ls->ipv4_prefix->ifl = attr->link_state_attr->ifl;
		ls->ipv4_prefix->rt = attr->link_state_attr->rt;
		ls->ipv4_prefix->et = attr->link_state_attr->et;
		ls->ipv4_prefix->pm = attr->link_state_attr->pm;
		ls->ipv4_prefix->ofa = attr->link_state_attr->ofa;
		ls->ipv4_prefix->opa = attr->link_state_attr->opa;
	}
	return ls;
}

struct bgp_ls *ls_attr_ipv6_prefix_set(struct attr *attr)
{
	struct bgp_ls *ls;
	if (attr) {
		/*--------mp_bgpls_nlri & mp_bgpls_nlri------------*/
		ls->ipv6_prefix->header = attr->mp_bgpls_nlri->header;
		ls->ipv6_prefix->proto_id =
			attr->mp_bgpls_nlri->ext_hdr.proto_id;
		ls->ipv6_prefix->nlri_identifier =
			attr->mp_bgpls_nlri->ext_hdr.nlri_identifier;
		ls->ipv6_prefix->local_node = attr->mp_bgpls_nlri->local_node;
		ls->ipv6_prefix->mid = attr->mp_bgpls_nlri->mid;
		ls->ipv6_prefix->ort = attr->mp_bgpls_nlri->ort;
		ls->ipv6_prefix->ipreach = attr->mp_bgpls_nlri->ipreach;
		/*--------------------link_state--------------------*/
		ls->ipv6_prefix->ifl = attr->link_state_attr->ifl;
		ls->ipv6_prefix->rt = attr->link_state_attr->rt;
		ls->ipv6_prefix->et = attr->link_state_attr->et;
		ls->ipv6_prefix->pm = attr->link_state_attr->pm;
		ls->ipv6_prefix->ofa = attr->link_state_attr->ofa;
		ls->ipv6_prefix->opa = attr->link_state_attr->opa;
	}
	return ls;
}

struct bgp_ls *ls_attr_set(struct attr *attr)
{
	struct bgp_ls *ls;

	ls_attr_node_set(attr);
	ls_attr_node_set(attr);
	ls_attr_ipv6_prefix_set(attr);
	ls_attr_ipv6_prefix_set(attr);

	return ls;
}

static void bgp_lsdb_delete_entry(struct bgp_lsdb *lsdb, struct route_node *rn)
{

	struct bgp_ls *ls = rn->info;

	if (!ls)
		return;

	assert(rn->table == lsdb->type[ls->header.nlri_type].db);
	lsdb->type[ls->header.nlri_type].count--;
	lsdb->total--;
	rn->info = NULL;
	route_unlock_node(rn);
	bgp_ls_unlock(&ls); /* lsdb */
	return;
}

/* Add new LS to lsdb. */
struct lsdb *bgp_lsdb_add(struct bgp_lsdb *lsdb, struct bgp_ls *ls)
{
	struct route_table *table;
	struct attr attr;
	struct route_node *rn;
	int i;
	for (i = BGP_LS_MIN_NLRI_TYPE; i <= BGP_LS_MAX_NLRI_TYPE; i++) {
		table = lsdb->type[ls->header.nlri_type].db;
		rn = route_node_ls_get(table, (struct bgp_ls *)&ls);

		/* nothing to do? */
		if (rn->info && rn->info == ls) {
			route_unlock_node(rn);
			return lsdb;
		}

		/* purge old entry? */
		if (rn->info)
			bgp_lsdb_delete_entry(lsdb, rn);

		lsdb->type[ls->header.nlri_type].count++;
		lsdb->total++;
		rn->info = bgp_ls_lock(ls); /* lsdb */
	}
	return lsdb;
}

void bgp_lsdb_delete(struct bgp_lsdb *lsdb, struct bgp_ls *ls)
{
	struct route_table *table;
	struct route_node *rn;

	if (!lsdb) {
		zlog_warn("%s: Called with NULL LSDB", __func__);
		if (ls)
			zlog_warn("LSA[Type%d:%s]: LS %p, lsa->lsdb %p", 0, 0,
				  0, 0);

		return;
	}

	if (!ls) {
		zlog_warn("%s: Called with NULL LS", __func__);
		return;
	}

	assert(ls->header.nlri_type < BGP_LS_MAX_NLRI_TYPE);
	table = lsdb->type[ls->header.nlri_type].db;
	// ls_attr_set (&attr, ls);
	if ((rn = route_node_lookup(table, (struct ls *)&ls))) {
		if (rn->info == ls)
			bgp_lsdb_delete_entry(lsdb, rn);
		route_unlock_node(rn); /* route_node_lookup */
	}
}

void bgp_lsdb_delete_all(struct bgp_lsdb *lsdb)
{
	struct route_table *table;
	struct route_node *rn;
	int i;

	for (i = BGP_LS_MIN_NLRI_TYPE; i < BGP_LS_MAX_NLRI_TYPE; i++) {
		table = lsdb->type[i].db;
		for (rn = route_top(table); rn; rn = route_next(rn))
			if (rn->info != NULL)
				bgp_lsdb_delete_entry(lsdb, rn);
	}
}

struct bgp_ls *bgp_lsdb_lookup(struct bgp_lsdb *lsdb, struct bgp_ls *ls)
{
	struct route_table *table;
	struct attr attr;
	struct route_node *rn;
	struct bgp_lsdb *find;

	table = lsdb->type[ls->header.nlri_type].db;
	ls_attr_set(attr);
	rn = route_node_lookup(table, (struct attr *)attr);
	if (rn) {
		find = rn->info;
		route_unlock_node(rn);
		return find;
	}
	return NULL;
}

struct bgp_ls *bgp_lsdb_lookup_by_id(struct bgp_lsdb *lsdb, u_char type,
				     struct in_addr id,
				     struct in_addr adv_router)
{
	struct route_table *table;
	struct attr attr;
	struct route_node *rn;
	struct bgp_ls *find;

	table = lsdb->type[type].db;

	memset(&attr, 0, sizeof(struct attr));
	// attr.family = 0;
	// attr.prefixlen = 64;
	// attr.id = id;
	// attr.adv_router = adv_router;

	rn = route_node_lookup(table, (struct prefix *)&attr);
	if (rn) {
		find = rn->info;
		route_unlock_node(rn);
		return find;
	}

	return NULL;
}

struct bgp_ls *bgp_lsdb_lookup_by_id_next(struct bgp_lsdb *lsdb, u_char type,
					  struct in_addr id,
					  struct in_addr adv_router, int first)
{
	struct route_table *table;
	struct bgp_ls ls;
	struct route_node *rn;
	struct attr *find;

	table = lsdb->type[type].db;

	memset(&ls, 0, sizeof(struct bgp_ls));
	/*
	  attr.family = 0;
	  attr.prefixlen = 64;
	  attr.id = id;
	  attr.adv_router = adv_router;
	 */

	if (first)
		rn = route_top(table);
	else {
		if ((rn = route_node_lookup(table, (struct prefix *)&ls))
		    == NULL)
			return NULL;
		rn = route_next(rn);
	}

	for (; rn; rn = route_next(rn))
		if (rn->info)
			break;

	if (rn && rn->info) {
		find = rn->info;
		route_unlock_node(rn);
		return find;
	}
	return NULL;
}

unsigned long bgp_lsdb_count_all(struct bgp_lsdb *lsdb)
{
	return lsdb->total;
}

unsigned long bgp_lsdb_count(struct bgp_lsdb *lsdb, int type)
{
	return lsdb->type[type].count;
}

void bgp_lsdb_delete_entry(struct bgp_lsdb *lsdb, struct route_node *rn)
{
	struct bgp_ls *ls = rn->info;

	if (!ls)
		return;

	lsdb->total--;
	rn->info = NULL;
	route_unlock_node(rn);

	return;
}

unsigned long bgp_lsdb_count_all(struct bgp_lsdb *lsdb)
{
	return lsdb->total;
}

unsigned long bgp_lsdb_count(struct bgp_lsdb *lsdb, int type)
{
	return lsdb->type[type].count;
}

/*
unsigned long
bgp_lsdb_count_self (struct bgp_lsdb *lsdb, int type)
{
  return lsdb->type[type].count_self;
}
*/

unsigned int bgp_lsdb_checksum(struct bgp_lsdb *lsdb, int type)
{
	return lsdb->type[type].checksum;
}

unsigned long bgp_lsdb_isempty(struct bgp_lsdb *lsdb)
{
	return (lsdb->total == 0);
}
