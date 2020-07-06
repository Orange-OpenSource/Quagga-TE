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

#ifndef QUAGGA_TE_BGPD_BGP_ZBUSCLIENT_H_
#define QUAGGA_TE_BGPD_BGP_ZBUSCLIENT_H_

#include "privs.h"
#define MTYPE_BGP_APICLIENT 0
/*
 * Opaque LSA's link state ID is redefined as follows.
 *
 *        24       16        8        0
 * +--------+--------+--------+--------+
 * |tttttttt|........|........|........|
 * +--------+--------+--------+--------+
 * |<-Type->|<------- Opaque ID ------>|
 */
#define LSID_OPAQUE_TYPE_MASK	0xff000000	/*  8 bits */
#define LSID_OPAQUE_ID_MASK	0x00ffffff	/* 24 bits */

#define GET_OPAQUE_TYPE(lsid) (((u_int32_t)(lsid)&LSID_OPAQUE_TYPE_MASK) >> 24)

#define GET_OPAQUE_ID(lsid) ((u_int32_t)(lsid)&LSID_OPAQUE_ID_MASK)

#define SET_OPAQUE_LSID(type, id)                                              \
	((((type) << 24) & LSID_OPAQUE_TYPE_MASK) | ((id)&LSID_OPAQUE_ID_MASK))

/*
 * Opaque LSA types will be assigned by IANA.
 * <http://www.iana.org/assignments/ospf-opaque-types>
 */
#define OPAQUE_TYPE_TRAFFIC_ENGINEERING_LSA			   1
#define OPAQUE_TYPE_SYCAMORE_OPTICAL_TOPOLOGY_DESC	   2
#define OPAQUE_TYPE_GRACE_LSA						   3
#define OPAQUE_TYPE_L1VPN_LSA                          5
#define OPAQUE_TYPE_ROUTER_INFORMATION_LSA             4
#define OPAQUE_TYPE_INTER_AS_LSA                       6
#define OPAQUE_TYPE_MAX                                6

#define ASYNCPORT 4000

/* Backlog for listen */
#define BACKLOG 5

/* Structure for the BGP API client */
struct bgp_apiclient {

	/* Sockets for sync requests and async notifications */
	int fd_sync;
	int fd_async;
};

u_int32_t bgp_apiclient_get_seqnr(void);
extern int bgp_apiclient_sync_lsdb(struct bgp_apiclient *oclient);
extern struct bgp_apiclient *bgp_apiclient_connect(char *host, int syncport);
extern int lsa_read(struct thread *thread);
extern int bgp_apiclient_handle_async(struct bgp_apiclient *oclient);
extern void
bgp_zbus_init(struct thread_master *master_thread,
	      struct zebra_privs_t *zprivs); // int argc, char *argv[]

#endif /* QUAGGA_TE_BGPD_BGP_ZBUSCLIENT_H_ */
