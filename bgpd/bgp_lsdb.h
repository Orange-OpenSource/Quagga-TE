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

#ifndef _BGP_LS_LSDB_H
#define _BGP_LS_LSDB_H
#define BGP_LS_MIN_NLRI_TYPE 1
#define BGP_LS_MAX_NLRI_TYPE 4

/* BGP LSDB structure. */
struct bgp_lsdb {
	struct {
		unsigned long count;
		unsigned long count_self;
		unsigned int checksum;
		struct route_table *db;
	} type[BGP_LS_MAX_NLRI_TYPE];
	unsigned long total;
};

/* Macros. */
#define LSDB_LOOP(T, N, L)                                                     \
	if ((T) != NULL)                                                       \
		for ((N) = route_top((T)); ((N)); ((N)) = route_next((N)))     \
			if (((L) = (N)->info))

#define NODE_LSDB(A) ((A)->lsdb->type[LINK_STATE_NODE_NLRI].db)
#define LINK_LSDB(A) ((A)->lsdb->type[LINK_STATE_LINK_NLRI].db)
#define IPV4_TOPOLOGY_PREFIX_LSDB(A) ((A)->lsdb->type[LINK_STATE_IPV4_TOPOLOGY_PREFIX_NLRI].db)
#define IPV6_TOPOLOGY_PREFIX_LSDB(A) ((A)->lsdb->type[LINK_STATE_IPV6_TOPOLOGY_PREFIX_NLRI].db)

struct link_state_node_nlri {
	/****MP_REACH_NLRI****/
	struct te_tlv_nlri_header *header;
	u_char proto_id;
	u_int64_t nlri_identifier;
	struct bgp_nlri_tlv_lrnd *local_node;
	/****LINK_STATE****/
	struct bgp_nlri_tlv_mt_id *mid;
	struct bgp_nlri_tlv_nfb *nfb;
	struct bgp_nlri_tlv_onp *onp;
	struct bgp_nlri_tlv_nn *nn;
	struct bgp_nlri_tlv_iiai *iiai;
	struct bgp_nlri_tlv_i4_rid_lrn *i4ridofln;
	struct bgp_nlri_tlv_i6_rid_lrn *i6ridofln;
	struct bgp_nlri_tlv_i4_rid_lrn *i4ridofrn;
	struct bgp_nlri_tlv_i6_rid_lrn *i6ridofrn;
};

struct link_state_link_nlri {
	/****MP_REACH_NLRI****/
	struct te_tlv_nlri_header *header;
	u_char proto_id;
	u_int64_t nlri_identifier;
	struct bgp_nlri_tlv_lrnd *local_node;
	struct bgp_nlri_tlv_lrnd *remote_node;
	struct bgp_nlri_tlv_llri *llri;
	struct bgp_nlri_tlv_i4i_addr *i4ia;
	struct bgp_nlri_tlv_i4n_addr *i4na;
	struct bgp_nlri_tlv_i6i_addr *i6ia;
	struct bgp_nlri_tlv_i6n_addr *i6na;
	struct bgp_nlri_tlv_mt_id *mid;
	/****LINK_STATE****/
	struct bgp_nlri_tlv_i4_rid_lrn *i4ridofln;
	struct bgp_nlri_tlv_i6_rid_lrn *i6ridofln;
	struct bgp_nlri_tlv_i4_rid_lrn *i4ridofrn;
	struct bgp_nlri_tlv_i6_rid_lrn *i6ridofrn;
	struct bgp_nlri_tlv_agc *agc;
	struct bgp_nlri_tlv_max_link_bw *mlb;
	struct bgp_nlri_tlv_max_rsv_link_bw *mrlb;
	struct bgp_nlri_tlv_ursv_bw *urb;
	struct bgp_nlri_tlv_tdm *tdm;
	struct bgp_nlri_tlv_link_pt *lpt;
	struct bgp_nlri_tlv_mpls_pm *mpm;
	struct bgp_nlri_tlv_metric *igpm;
	struct bgp_nlri_tlv_srlg *srlg;
	struct bgp_nlri_tlv_ola *ola;
	struct bgp_nlri_tlv_lna *lna;
};

struct link_state_ipv4_nlri {
	/****MP_REACH_NLRI****/
	struct te_tlv_nlri_header *header;
	u_char proto_id;
	u_int64_t nlri_identifier;
	struct bgp_nlri_tlv_local_rnd *local_node;
	struct bgp_nlri_tlv_mt_id *mid;
	struct bgp_nlri_tlv_ort *ort;
	struct bgp_nlri_tlv_ip_reach *ipreach;
	/****LINK_STATE****/
	struct bgp_nlri_tlv_igp_flags *ifl;
	struct bgp_nlri_tlv_route_tag *rt;
	struct bgp_nlri_tlv_extended_tag *et;
	struct bgp_nlri_tlv_prefix_metric *pm;
	struct bgp_nlri_tlv_ospf_fowarding_adress *ofa;
	struct bgp_nlri_tlv_opa *opa;
};

struct link_state_ipv6_nlri {
	/****MP_REACH_NLRI****/
	struct te_tlv_nlri_header *header;
	u_char proto_id;
	u_int64_t nlri_identifier;
	struct bgp_nlri_tlv_lrnd *local_node;
	struct bgp_nlri_tlv_mt_id *mid;
	struct bgp_nlri_tlv_ort *ort;
	struct bgp_nlri_tlv_ip_reach *ipreach;
	/****LINK_STATE****/
	struct bgp_nlri_tlv_igp_flags *ifl;
	struct bgp_nlri_tlv_route_tag *rt;
	struct bgp_nlri_tlv_extended_tag *et;
	struct bgp_nlri_tlv_prefix_metric *pm;
	struct bgp_nlri_tlv_ospf_fowarding_adress *ofa;
	struct bgp_nlri_tlv_opa *opa;
};

struct bgp_ls {
	struct te_tlv_nlri_header *header;
	struct link_state_node_nlri *node;
	struct link_state_link_nlri *link;
	struct link_state_ipv4_nlri *ipv4_prefix;
	struct link_state_ipv6_nlri *ipv6_prefix;

	/* All of reference count, also lock to remove. */
	int lock;

	/* References to this LSA in neighbor retransmission lists*/
	int retransmit_counter;

	/* Refreshement List or Queue */
	int refresh_list;
};

/* BGP LSDB related functions. */
extern struct bgp_lsdb *bgp_lsdb_new(void);
extern void bgp_lsdb_init(struct bgp_lsdb *);
extern void bgp_lsdb_free(struct bgp_lsdb *);
extern void bgp_lsdb_cleanup(struct bgp_lsdb *);
extern void bgp_ls_prefix_set(struct attr *lp, struct bgp_ls *ls);
extern struct bgp_lsdb *bgp_lsdb_add(struct bgp_lsdb *, struct bgp_ls *);
extern void bgp_lsdb_delete(struct bgp_lsdb *, struct bgp_ls *);
extern void bgp_lsdb_delete_all(struct bgp_lsdb *);

extern struct bgp_ls *ls_attr_node_set(struct attr *attr);
extern struct bgp_ls *ls_attr_link_set(struct attr *attr);
extern struct bgp_ls *ls_attr_ipv4_prefix_set(struct attr *attr);
extern struct bgp_ls *ls_attr_ipv6_prefix_set(struct attr *attr);
extern struct bgp_ls *ls_attr_set(struct attr *attr);

extern void bgp_lsdb_clean_stat(struct bgp_lsdb *lsdb);
extern struct bgp_ls *bgp_lsdb_lookup(struct bgp_lsdb *, struct bgp_ls *);
extern struct bgp_ls *bgp_lsdb_lookup_by_id(struct bgp_lsdb *, u_char,
					    struct in_addr, struct in_addr);
extern struct bgp_ls *bgp_lsdb_lookup_by_id_next(struct bgp_lsdb *, u_char,
						 struct in_addr, struct in_addr,
						 int);
extern unsigned long bgp_lsdb_count_all(struct bgp_lsdb *);
extern unsigned long bgp_lsdb_count(struct bgp_lsdb *, int);
extern unsigned long bgp_lsdb_count_self(struct bgp_lsdb *, int);
extern unsigned int bgp_lsdb_checksum(struct bgp_lsdb *, int);
extern unsigned long bgp_lsdb_isempty(struct bgp_lsdb *);
#endif /* _BGP_LS_LSDB_H */
