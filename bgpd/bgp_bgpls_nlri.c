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

#include "command.h"
#include "linklist.h"
#include "prefix.h"
#include "memory.h"
#include "vector.h"
#include "vty.h"
#include "stream.h"
#include "log.h"
#include "hash.h"
#include "jhash.h"
#include "sockunion.h" /* for inet_aton() */
#include "table.h"
#include "if.h"
#include "thread.h"
#include "checksum.h"
#include "md5.h"

#include "bgpd/bgp_ls.h"
#include "bgpd/bgpd.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_aspath.h"
#include "bgpd/bgp_community.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_packet.h"
#include "bgpd/bgp_ecommunity.h"
#include "isisd/isis_te.h"

static int leftnonzero(struct bgp_attr_parser_args *args);

/* Utilities function to convert float to / from network */
static float htonft(float val)
{
	u_int32_t lu1, lu2;
	float convert;

	memcpy(&lu1, &val, sizeof(u_int32_t));
	lu2 = htonl(lu1);
	memcpy(&convert, &lu2, sizeof(u_int32_t));
	return convert;
}

static float ntohft(float val)
{
	u_int32_t lu1, lu2;
	float convert;

	memcpy(&lu1, &val, sizeof(u_int32_t));
	lu2 = ntohl(lu1);
	memcpy(&convert, &lu2, sizeof(u_int32_t));
	return convert;
}

int leftnonzero(struct bgp_attr_parser_args *args)
{
	size_t start;
	struct stream *s;
	struct peer *const peer = args->peer;
	const bgp_size_t length = args->length;

	/* Set end of packet. */
	s = BGP_INPUT(peer);

	start = stream_get_getp(s);
	/* safe to read statically sized header? */
	//#define LEN_LEFT	(length - (stream_get_getp(s) - start))
	/*
	   if (!LEN_LEFT)
		  {
		    zlog_info ("%s: (%s) Failed to read SNPA and NLRI(s)",
			       __func__, peer->host);
		    return BGP_ATTR_PARSE_ERROR_NOTIFYPLS;
		  }
	*/
	return BGP_ATTR_PARSE_PROCEED;
}

int mp_reach_value(struct bgp_attr_parser_args *args,
		   struct bgp_nlri *mp_update)

{
	size_t start;
	bgp_size_t nlri_len;
	struct stream *s;
	struct peer *const peer = args->peer;
	struct attr *const attr = args->attr;
	const bgp_size_t length = args->length;
	struct attr_extra *attre = bgp_attr_extra_get(attr);

	//  #define LEN_LEFT	(length - (stream_get_getp(s) - start))

	/* Set end of packet. */
	s = BGP_INPUT(peer);

	leftnonzero(args);
	// stream_get(attre->mp_bgpls_nlri->mid,s,length);
	//  nlri_len = LEN_LEFT;
	stream_forward_getp(s, nlri_len);
	return BGP_ATTR_PARSE_PROCEED;
}
/*****************************************************************************************
	   +--------------------+-------------------+----------+
	   | Sub-TLV Code Point | Description       |   Length |
	   +--------------------+-------------------+----------+
	   |        512         | Autonomous System |        4 |
	   |        513         | BGP-LS Identifier |        4 |
	   |        514         | OSPF Area-ID      |        4 |
	   |        515         | IGP Router-ID     | Variable |
	   +--------------------+-------------------+----------+
******************************************************************************************/


int bgp_mp_node_decode(struct bgp_attr_parser_args *args, struct stream *s)
{
	struct peer *const peer = args->peer;
	struct attr *const attr = args->attr;
	u_int16_t type, node_type;
	u_int16_t length, node_length;
	size_t nlri_node_endp;

	attr->mp_bgpls_nlri->ext_hdr.proto_id = stream_getc(s);
	attr->mp_bgpls_nlri->ext_hdr.nlri_identifier = stream_getq(s);
	type = stream_getw(s);   /* Type */
	length = stream_getw(s); /* Length */

	if (type != BGP_NLRI_TLV_LOCAL_NODE_DESCRIPTORS) {
		zlog_info("%s sent invalid Node Descriptor, %lu", peer->host,
			  (unsigned long)length);
	}

	nlri_node_endp = stream_get_getp(s) + length;
	int n, i;
	while (stream_get_getp(s) < nlri_node_endp) {
		node_type = stream_getw(s);
		node_length = stream_getw(s);

		switch (node_type) {

		case BGP_NLRI_TLV_AUTONOMOUS_SYSTEM:

			stream_get(attr->mp_bgpls_nlri->local_node->value, s,
				   BGP_NLRI_TLV_LEN_AUTONOMOUS_SYSTEM);

			break;

		case BGP_NLRI_TLV_BGP_LS_IDENTIFIER:

			stream_get(attr->mp_bgpls_nlri->local_node->value, s,
				   BGP_NLRI_TLV_LEN_BGP_LS_IDENTIFIER);

			break;

		case BGP_NLRI_TLV_AREA_ID:

			stream_get(attr->mp_bgpls_nlri->local_node->value, s,
				   BGP_NLRI_TLV_LEN_AREA_ID);

			break;

		case BGP_NLRI_TLV_IGP_ROUTER_ID:

			switch (node_length) {
			case BGP_NLRI_IS_IS_NON_PSEUDONODE:
				stream_get(
					&attr->mp_bgpls_nlri->local_node->value,
					s, BGP_NLRI_IS_IS_NON_PSEUDONODE);
				break;

			case BGP_NLRI_IS_IS_PSEUDONODE:
				stream_get(
					&attr->mp_bgpls_nlri->local_node->value,
					s, BGP_NLRI_IS_IS_PSEUDONODE);
				break;

			case BGP_NLRI_OSPF_NON_PSEUDONODE:
				stream_get(
					&attr->mp_bgpls_nlri->local_node->value,
					s, BGP_NLRI_OSPF_NON_PSEUDONODE);
				break;

			case BGP_NLRI_OSPF_PSEUDONODE:
				stream_get(
					&attr->mp_bgpls_nlri->local_node->value,
					s, BGP_NLRI_OSPF_PSEUDONODE);
				break;

			default:
				zlog_info("%s sent invalid IGP Router-ID, %lu",
					  peer->host, (unsigned long)length);
				break;
			}

			break;

		default:
			zlog_info("%s sent invalid Node Descriptor, %lu",
				  peer->host, (unsigned long)length);
			break;
		}

		break;
	}
	return BGP_ATTR_PARSE_PROCEED;
}

/********************************************************************************

   +-----------+---------------------+---------------+-----------------+
   |  TLV Code | Description         |   IS-IS TLV   | Value defined   |
   |   Point   |                     |    /Sub-TLV   | in:             |
   +-----------+---------------------+---------------+-----------------+
   |    258    | Link Local/Remote   |      22/4     | [RFC5307]/1.1   |
   |           | Identifiers         |               |                 |
   |    259    | IPv4 interface      |      22/6     | [RFC5305]/3.2   |
   |           | address             |               |                 |
   |    260    | IPv4 neighbor       |      22/8     | [RFC5305]/3.3   |
   |           | address             |               |                 |
   |    261    | IPv6 interface      |     22/12     | [RFC6119]/4.2   |
   |           | address             |               |                 |
   |    262    | IPv6 neighbor       |     22/13     | [RFC6119]/4.3   |
   |           | address             |               |                 |
   |    263    | Multi-Topology      |      ---      | Section 3.2.1.5 |
   |           | Identifier          |               |                 |
   +-----------+---------------------+---------------+-----------------+
*********************************************************************************/
int bgp_mp_link_decode(struct bgp_attr_parser_args *args, struct stream *s)
{
	struct peer *const peer = args->peer;
	struct attr *const attr = args->attr;
	u_int16_t type, node_type;
	u_int16_t length, node_length;
	size_t nlri_node_endp;

	attr->mp_bgpls_nlri->ext_hdr.proto_id = stream_getc(s);
	attr->mp_bgpls_nlri->ext_hdr.nlri_identifier = stream_getq(s);
	type = stream_getw(s);
	length = stream_getw(s);

	nlri_node_endp = stream_get_getp(s) + length;
	int n, i;

	switch (type) {
	case BGP_NLRI_TLV_LOCAL_NODE_DESCRIPTORS:

		while (stream_get_getp(s) < nlri_node_endp) {
			node_type = stream_getw(s);
			node_length = stream_getw(s);

			switch (node_type) {

			case BGP_NLRI_TLV_AUTONOMOUS_SYSTEM:

				stream_get(
					attr->mp_bgpls_nlri->local_node->value,
					s, BGP_NLRI_TLV_LEN_AUTONOMOUS_SYSTEM);

				break;

			case BGP_NLRI_TLV_BGP_LS_IDENTIFIER:

				stream_get(
					attr->mp_bgpls_nlri->local_node->value,
					s, BGP_NLRI_TLV_LEN_BGP_LS_IDENTIFIER);

				break;

			case BGP_NLRI_TLV_AREA_ID:

				stream_get(
					attr->mp_bgpls_nlri->local_node->value,
					s, BGP_NLRI_TLV_LEN_AREA_ID);

				break;

			case BGP_NLRI_TLV_IGP_ROUTER_ID:

				switch (node_length) {
				case BGP_NLRI_IS_IS_NON_PSEUDONODE:

					stream_get(
						&attr->mp_bgpls_nlri->local_node
							 ->value,
						s,
						BGP_NLRI_IS_IS_NON_PSEUDONODE);
					break;

				case BGP_NLRI_IS_IS_PSEUDONODE:
					stream_get(&attr->mp_bgpls_nlri
							    ->local_node->value,
						   s,
						   BGP_NLRI_IS_IS_PSEUDONODE);
					break;

				case BGP_NLRI_OSPF_NON_PSEUDONODE:
					stream_get(
						&attr->mp_bgpls_nlri->local_node
							 ->value,
						s,
						BGP_NLRI_OSPF_NON_PSEUDONODE);
					break;

				case BGP_NLRI_OSPF_PSEUDONODE:
					stream_get(&attr->mp_bgpls_nlri
							    ->local_node->value,
						   s, BGP_NLRI_OSPF_PSEUDONODE);
					break;

				default:
					zlog_info(
						"%s sent invalid IGP Router-ID, %lu",
						peer->host,
						(unsigned long)length);
					break;
				}

				break;

			default:
				zlog_info(
					"%s sent invalid Node Descriptor, %lu",
					peer->host, (unsigned long)length);
				break;
			}
		}
		break;

	case BGP_NLRI_TLV_REMOTE_NODE_DESCRIPTORS:

		while (stream_get_getp(s) < nlri_node_endp) {
			node_type = stream_getw(s);
			node_length = stream_getw(s);

			switch (node_type) {

			case BGP_NLRI_TLV_AUTONOMOUS_SYSTEM:

				stream_get(
					attr->mp_bgpls_nlri->local_node->value,
					s, BGP_NLRI_TLV_LEN_AUTONOMOUS_SYSTEM);

				break;

			case BGP_NLRI_TLV_BGP_LS_IDENTIFIER:

				stream_get(
					attr->mp_bgpls_nlri->local_node->value,
					s, BGP_NLRI_TLV_LEN_BGP_LS_IDENTIFIER);

				break;

			case BGP_NLRI_TLV_AREA_ID:

				stream_get(
					attr->mp_bgpls_nlri->local_node->value,
					s, BGP_NLRI_TLV_LEN_AREA_ID);

				break;

			case BGP_NLRI_TLV_IGP_ROUTER_ID:

				switch (node_length) {
				case BGP_NLRI_IS_IS_NON_PSEUDONODE:
					stream_get(
						&attr->mp_bgpls_nlri
							 ->remote_node->value,
						s,
						BGP_NLRI_IS_IS_NON_PSEUDONODE);
					break;

				case BGP_NLRI_IS_IS_PSEUDONODE:
					stream_get(
						&attr->mp_bgpls_nlri
							 ->remote_node->value,
						s, BGP_NLRI_IS_IS_PSEUDONODE);
					break;

				case BGP_NLRI_OSPF_NON_PSEUDONODE:
					stream_get(
						&attr->mp_bgpls_nlri
							 ->remote_node->value,
						s,
						BGP_NLRI_OSPF_NON_PSEUDONODE);
					break;

				case BGP_NLRI_OSPF_PSEUDONODE:
					stream_get(
						&attr->mp_bgpls_nlri
							 ->remote_node->value,
						s, BGP_NLRI_OSPF_PSEUDONODE);
					break;

				default:
					zlog_info(
						"%s sent invalid IGP Router-ID, %lu",
						peer->host,
						(unsigned long)length);
					break;
				}

				break;

			default:
				zlog_info(
					"%s sent invalid Node Descriptor, %lu",
					peer->host, (unsigned long)length);
				break;
			}
		}
		break;

	case BGP_NLRI_TLV_LINK_LOCAL_REMOTE_IDENTIFIERS:

		node_type = stream_getw(s);
		node_length = stream_getw(s);

		attr->mp_bgpls_nlri->llri.local = stream_getw(s);

		attr->mp_bgpls_nlri->llri.remote = stream_getw(s);

		break;

	case BGP_NLRI_TLV_IPV4_INTERFACE_ADDRESS:

		node_type = stream_getw(s);
		node_length = stream_getw(s);

		attr->mp_bgpls_nlri->i4ia.value.s_addr = stream_get_ipv4(s);

		break;

	case BGP_NLRI_TLV_IPV4_NEIGHBOR_ADDRESS:

		node_type = stream_getw(s);
		node_length = stream_getw(s);

		attr->mp_bgpls_nlri->i4na.value.s_addr = stream_get_ipv4(s);

		break;

	case BGP_NLRI_TLV_IPV6_INTERFACE_ADDRESS:

		node_type = stream_getw(s);
		node_length = stream_getw(s);

#ifdef HAVE_IPV6
		stream_get(&attr->mp_bgpls_nlri->i6ia.value, s,
			   BGP_NLRI_TLV_LEN_IPV6_INTERFACE_ADDRESS);
#endif /* HAVE_IPV6  */

		break;

	case BGP_NLRI_TLV_IPV6_NEIGHBOR_ADDRESS:

		node_type = stream_getw(s);
		node_length = stream_getw(s);

#ifdef HAVE_IPV6
		stream_get(&attr->mp_bgpls_nlri->i6ia.value, s,
			   BGP_NLRI_TLV_LEN_IPV6_NEIGHBOR_ADDRESS);
#endif /* HAVE_IPV6  */

		break;

	case BGP_NLRI_TLV_MULTI_TOPOLOGY_ID:

		node_type = stream_getw(s);
		node_length = stream_getw(s);


		n = (node_length) / 2;
		i = 0;
		for (i = 0; i <= (n - 1); i++) {
			attr->mp_bgpls_nlri->mid->value[i] = stream_getw(s);
		}

		break;

	default:
		break;
	}
	return BGP_ATTR_PARSE_PROCEED;
}

/*********************************************************************************
+---------------+----------------------+----------+-----------------+
   |    TLV Code   | Description          |   Length | Reference       |
   |     Point     |                      |          |                 |
   +---------------+----------------------+----------+-----------------+
   |      1152     | IGP Flags            |        1 | Section 3.3.3.1 |
   |      1153     | Route Tag            |      4*n | Section 3.3.3.2 |
   |      1154     | Extended Tag         |      8*n | Section 3.3.3.3 |
   |      1155     | Prefix Metric        |        4 | Section 3.3.3.4 |
   |      1156     | OSPF Forwarding      |        4 | Section 3.3.3.5 |
   |               | Address              |          |                 |
   |      1157     | Opaque Prefix        | variable | Section 3.3.3.6 |
   |               | Attribute            |          |                 |
   +---------------+----------------------+----------+-----------------+
**********************************************************************************/

int bgp_mp_prefix_decode(struct bgp_attr_parser_args *args, struct stream *s)
{
	struct peer *const peer = args->peer;
	struct attr *const attr = args->attr;
	u_int16_t type, node_type;
	u_int16_t length, node_length;
	size_t nlri_node_endp;

	attr->mp_bgpls_nlri->ext_hdr.proto_id = stream_getc(s);
	attr->mp_bgpls_nlri->ext_hdr.nlri_identifier = stream_getq(s);
	type = stream_getw(s);
	length = stream_getw(s);
	int n, i;
	switch (type) {

	case BGP_NLRI_TLV_LOCAL_NODE_DESCRIPTORS:

		nlri_node_endp = stream_get_getp(s) + length;

		while (stream_get_getp(s) < nlri_node_endp) {

			node_type = stream_getw(s);
			node_length = stream_getw(s);

			switch (node_type) {

			case BGP_NLRI_TLV_AUTONOMOUS_SYSTEM:

				stream_get(
					attr->mp_bgpls_nlri->local_node->value,
					s, BGP_NLRI_TLV_LEN_AUTONOMOUS_SYSTEM);

				break;

			case BGP_NLRI_TLV_BGP_LS_IDENTIFIER:

				stream_get(
					attr->mp_bgpls_nlri->local_node->value,
					s, BGP_NLRI_TLV_LEN_BGP_LS_IDENTIFIER);

				break;

			case BGP_NLRI_TLV_AREA_ID:

				stream_get(
					attr->mp_bgpls_nlri->local_node->value,
					s, BGP_NLRI_TLV_LEN_AREA_ID);

				break;

			case BGP_NLRI_TLV_IGP_ROUTER_ID:

				switch (node_length) {
				case BGP_NLRI_IS_IS_NON_PSEUDONODE:
					stream_get(
						&attr->mp_bgpls_nlri->local_node
							 ->value,
						s,
						BGP_NLRI_IS_IS_NON_PSEUDONODE);
					break;

				case BGP_NLRI_IS_IS_PSEUDONODE:
					stream_get(&attr->mp_bgpls_nlri
							    ->local_node->value,
						   s,
						   BGP_NLRI_IS_IS_PSEUDONODE);
					break;

				case BGP_NLRI_OSPF_NON_PSEUDONODE:
					stream_get(
						&attr->mp_bgpls_nlri->local_node
							 ->value,
						s,
						BGP_NLRI_OSPF_NON_PSEUDONODE);
					break;

				case BGP_NLRI_OSPF_PSEUDONODE:
					stream_get(&attr->mp_bgpls_nlri
							    ->local_node->value,
						   s, BGP_NLRI_OSPF_PSEUDONODE);
					break;

				default:
					zlog_info(
						"%s sent invalid IGP Router-ID, %lu",
						peer->host,
						(unsigned long)length);
					break;
				}

				break;

			default:
				zlog_info(
					"%s sent invalid Node Descriptor, %lu",
					peer->host, (unsigned long)length);
				break;
			}
		}
		break;

	case BGP_NLRI_TLV_MULTI_TOPOLOGY_ID:

		node_type = stream_getw(s);
		node_length = stream_getw(s);

		n = (node_length) / 2;
		i = 0;
		for (i = 0; i <= (n - 1); i++) {
			attr->mp_bgpls_nlri->mid->value[i] = stream_getw(s);
		}

		break;

	case BGP_NLRI_TLV_OSPF_ROUTE_TYPE:

		node_type = stream_getw(s);
		node_length = stream_getw(s);

		attr->mp_bgpls_nlri->ort.value = stream_getc(s);

		break;

	case BGP_NLRI_TLV_IP_REACHABILITY_INFORMATION:

		node_type = stream_getw(s);
		node_length = stream_getw(s);

		attr->mp_bgpls_nlri->ipreach->prefix = stream_getc(s);

		stream_get(&attr->mp_bgpls_nlri->ipreach->value, s,
			   attr->mp_bgpls_nlri->ipreach->prefix);
		break;

	default:
		zlog_info("%s sent invalid Link State IS-IS TLV, %lu",
			  peer->host, (unsigned long)length);
		return BGP_ATTR_PARSE_ERROR_NOTIFYPLS;
		break;
	}
	return BGP_ATTR_PARSE_PROCEED;
}

/*----------------------------------------------------------------------------------------------*
 * 					Followings are vty session control functions.
 **
 *----------------------------------------------------------------------------------------------*/

static u_int16_t
show_vty_multi_topology_identifier(struct vty *vty,
				   struct te_tlv_nlri_header *tlvh)
{
	struct bgp_nlri_tlv_mt_id *top;
	int i, n;

	top = (struct bgp_nlri_tlv_mt_id *)tlvh;
	n = ntohs(top->header.nlri_length) / sizeof(&top->value[0]);
	if (vty != NULL) {
		vty_out(vty, "  Multi Topology ID number: %d%s", n,
			VTY_NEWLINE);
	} else {
		zlog_debug("  Multi Topology ID number: %d", n);
	}
	for (i = 0; i < n; i++) {
		if (vty != NULL) {
			vty_out(vty, " ID   #%d: %d%s", i,
				ntohs(&top->value[i]), VTY_NEWLINE);
		} else {
			zlog_debug("   ID   #%d: %d", i, ntohs(&top->value[i]));
		}
	}
	return BGP_TLV_SIZE(tlvh);
}

static u_int16_t show_vty_node_flag_bits(struct vty *vty,
					 struct te_tlv_nlri_header *tlvh)
{
	struct bgp_nlri_tlv_nfb *top = (struct bgp_nlri_tlv_nfb *)tlvh;

	if (vty != NULL)
		vty_out(vty, "    Node flag bits: %d%s", (u_char)(top->value),
			VTY_NEWLINE);
	else
		zlog_debug("      Node flag bits: %d", (u_char)(top->value));

	return BGP_TLV_SIZE(tlvh);
}

static u_int16_t
show_vty_opaque_node_properties(struct vty *vty,
				struct te_tlv_nlri_header *tlvh)
{
	struct bgp_nlri_tlv_onp *top = (struct bgp_nlri_tlv_onp *)tlvh;
	if (vty != NULL)
		vty_out(vty, "    Opaque Node Properties: %p%s", &top->value,
			VTY_NEWLINE);
	else
		zlog_debug("     Opaque Node Properties: %p", &top->value);
	return BGP_TLV_SIZE(tlvh);
}

static u_int16_t show_vty_node_name(struct vty *vty,
				    struct te_tlv_nlri_header *tlvh)
{
	struct bgp_nlri_tlv_nn *top = (struct bgp_nlri_tlv_nn *)tlvh;
	if (vty != NULL)
		vty_out(vty, "    Node name: %p%s", &top->value, VTY_NEWLINE);
	else
		zlog_debug("     Node name: %p", &top->value);

	return BGP_TLV_SIZE(tlvh);
}

static u_int16_t show_vty_is_is_area_identifier(struct vty *vty,
						struct te_tlv_nlri_header *tlvh)
{
	struct bgp_nlri_tlv_iiai *top = (struct bgp_nlri_tlv_iiai *)tlvh;
	if (vty != NULL)
		vty_out(vty, "    IS-IS Area Identifier: %p%s", &top->value,
			VTY_NEWLINE);
	else
		zlog_debug("     IS-IS Area Identifier: %p", &top->value);

	return BGP_TLV_SIZE(tlvh);
}

static u_int16_t
show_vty_ipv4_router_id_of_local_node(struct vty *vty,
				      struct te_tlv_nlri_header *tlvh)
{
	struct bgp_nlri_tlv_i4_rid_lrn *top =
		(struct bgp_nlri_tlv_i4_rid_lrn *)tlvh;

	if (vty != NULL)
		vty_out(vty, " IPv4 Router ID of local node: %s%s",
			inet_ntoa(top->value), VTY_NEWLINE);
	else
		zlog_debug("   IPv4 Router ID of local node: %s",
			   inet_ntoa(top->value));

	return BGP_TLV_SIZE(tlvh);
}

static u_int16_t
show_vty_ipv6_router_id_of_local_node(struct vty *vty,
				      struct te_tlv_nlri_header *tlvh)
{
	struct bgp_nlri_tlv_i6_rid_lrn *top =
		(struct bgp_nlri_tlv_i6_rid_lrn *)tlvh;
#ifdef HAVE_IPV6
	char straddr[INET6_ADDRSTRLEN];
	if (vty != NULL)

		vty_out(vty, "	 IPv6 Router ID of local node: %s%s",
			inet_ntop(AF_INET6, &top->value, straddr,
				  INET6_ADDRSTRLEN),
			VTY_NEWLINE);
	else
		zlog_debug("   IPv6 Router ID of local node: %s",
			   inet_ntop(AF_INET6, &top->value, straddr,
				     INET6_ADDRSTRLEN));
#endif /*HAVE_IPV6*/
	return BGP_TLV_SIZE(tlvh);
}

static u_int16_t
show_vty_ipv4_router_id_of_remote_node(struct vty *vty,
				       struct te_tlv_nlri_header *tlvh)
{
	struct bgp_nlri_tlv_i4_rid_lrn *top =
		(struct bgp_nlri_tlv_i4_rid_lrn *)tlvh;

	if (vty != NULL)
		vty_out(vty, " IPv4 Router ID of remote node: %s%s",
			inet_ntoa(top->value), VTY_NEWLINE);
	else
		zlog_debug("   IPv4 Router ID of remote node: %s",
			   inet_ntoa(top->value));

	return BGP_TLV_SIZE(tlvh);
}

static u_int16_t
show_vty_ipv6_router_id_of_remote_node(struct vty *vty,
				       struct te_tlv_nlri_header *tlvh)
{
	struct bgp_nlri_tlv_i6_rid_lrn *top =
		(struct bgp_nlri_tlv_i6_rid_lrn *)tlvh;
#ifdef HAVE_IPV6
	char straddr[INET6_ADDRSTRLEN];
	if (vty != NULL)
		vty_out(vty, " IPv6 Router ID of remote node: %s%s",
			inet_ntop(AF_INET6, &top->value, straddr,
				  INET6_ADDRSTRLEN),
			VTY_NEWLINE);
	else
		zlog_debug("   IPv6 Router ID of remote node: %s",
			   inet_ntop(AF_INET6, &top->value, straddr,
				     INET6_ADDRSTRLEN));
#endif /*HAVE_IPV6*/
	return BGP_TLV_SIZE(tlvh);
}

static u_int16_t show_vty_admin_grp_color(struct vty *vty,
					  struct te_tlv_nlri_header *tlvh)
{
	struct bgp_nlri_tlv_agc *top = (struct bgp_nlri_tlv_agc *)tlvh;
	if (vty != NULL)
		vty_out(vty, "    Administrative Group: 0x%x%s",
			(u_int32_t)ntohl(top->value), VTY_NEWLINE);
	else
		zlog_debug("      Administrative Group: 0x%x",
			   (u_int32_t)ntohl(top->value));

	return (BGP_TLV_SIZE(tlvh));
}

static u_int16_t show_vty_max_link_bw(struct vty *vty,
				      struct te_tlv_nlri_header *tlvh)
{
	struct bgp_nlri_tlv_max_link_bw *top =
		(struct bgp_nlri_tlv_max_link_bw *)tlvh;
	float fval;

	fval = ntohft(top->value);

	if (vty != NULL)
		vty_out(vty, "    Maximum Bandwidth: %g (Bytes/sec)%s", fval,
			VTY_NEWLINE);
	else
		zlog_debug("      Maximum Bandwidth: %g (Bytes/sec)", fval);

	return BGP_TLV_SIZE(tlvh);
}

static u_int16_t show_vty_max_rsv_bw(struct vty *vty,
				     struct te_tlv_nlri_header *tlvh)
{
	struct bgp_nlri_tlv_max_rsv_link_bw *top =
		(struct bgp_nlri_tlv_max_rsv_link_bw *)tlvh;

	float fval;

	fval = ntohft(top->value);

	if (vty != NULL)
		vty_out(vty,
			"    Maximum Reservable Bandwidth: %g (Bytes/sec)%s",
			fval, VTY_NEWLINE);
	else
		zlog_debug("      Maximum Reservable Bandwidth: %g (Bytes/sec)",
			   fval);

	return BGP_TLV_SIZE(tlvh);
}

static u_int16_t show_vty_unrsv_bw(struct vty *vty,
				   struct te_tlv_nlri_header *tlvh)
{
	struct bgp_nlri_tlv_ursv_bw *top = (struct bgp_nlri_tlv_ursv_bw *)tlvh;

	float fval1, fval2;
	int i;

	if (vty != NULL)
		vty_out(vty, "    Unreserved Bandwidth:%s", VTY_NEWLINE);
	else
		zlog_debug("      Unreserved Bandwidth:");

	for (i = 0; i < 8; i += 2) //à revenir imperativement
	{
		fval1 = ntohft(top->value[i]);
		fval2 = ntohft(top->value[i + 1]);
		if (vty != NULL)
			vty_out(vty,
				"      [%d]: %g (Bytes/sec),\t[%d]: %g (Bytes/sec)%s",
				i, fval1, i + 1, fval2, VTY_NEWLINE);
		else
			zlog_debug(
				"        [%d]: %g (Bytes/sec),\t[%d]: %g (Bytes/sec)",
				i, fval1, i + 1, fval2);
	}

	return BGP_TLV_SIZE(tlvh);
}

static u_int16_t show_vty_te_metric(struct vty *vty,
				    struct te_tlv_nlri_header *tlvh)
{
	struct bgp_nlri_tlv_tdm *top = (struct bgp_nlri_tlv_tdm *)tlvh;
	// u_int32_t te_metric;

	// te_metric = tlvh->value[2] | tlvh->value[1] << 8 | tlvh->value[0] <<
	// 16;
	if (vty != NULL)
		vty_out(vty, "    Traffic Engineering Metric: %u%s",
			(u_int32_t)ntohl(top->value), VTY_NEWLINE);
	else
		zlog_debug("      Traffic Engineering Metric: %u",
			   (u_int32_t)ntohl(top->value));

	return BGP_TLV_SIZE(tlvh);
}

static u_int16_t show_vty_link_protection_type(struct vty *vty,
					       struct te_tlv_nlri_header *tlvh)
{
	struct bgp_nlri_tlv_link_pt *top = (struct bgp_nlri_tlv_link_pt *)tlvh;

	if (vty != NULL)
		vty_out(vty, "  Link Protection Type: %d%s",
			(u_int16_t)ntohs(top->value), VTY_NEWLINE);
	else
		zlog_debug("    Link Protection Type: %d",
			   (u_int16_t)ntohs(top->value));

	return BGP_TLV_SIZE(tlvh);
}

static u_int16_t show_vty_mpls_protocol_mask(struct vty *vty,
					     struct te_tlv_nlri_header *tlvh)
{
	struct bgp_nlri_tlv_mpls_pm *top = (struct bgp_nlri_tlv_mpls_pm *)tlvh;

	if (vty != NULL)
		vty_out(vty, "    MPLS Protocol Mask: %c%s",
			(u_char)ntohs(top->value), VTY_NEWLINE);
	else
		zlog_debug("      MPLS Protocol Mask: %c",
			   (u_char)ntohs(top->value));

	return BGP_TLV_SIZE(tlvh);
}

static u_int16_t show_vty_igp_metric(struct vty *vty,
				     struct te_tlv_nlri_header *tlvh)
{

	struct bgp_nlri_tlv_metric *top = (struct bgp_nlri_tlv_metric *)tlvh;

	if (vty != NULL)
		vty_out(vty, "    IGP Metric: %u%s",
			(u_int32_t)ntohs(&top->value), VTY_NEWLINE);
	else
		zlog_debug("    IGP Metric: %u", (u_int32_t)ntohs(&top->value));

	return BGP_TLV_SIZE(tlvh);
}

static u_int16_t
show_vty_shared_risk_link_group(struct vty *vty,
				struct te_tlv_nlri_header *tlvh)
{
	struct bgp_nlri_tlv_srlg *top;
	int i, n;

	top = (struct bgp_nlri_tlv_srlg *)tlvh;
	n = ntohs(top->header.nlri_length) / sizeof(&top->value[0]);
	// The size is 4 bytes
	if (vty != NULL)
		vty_out(vty, "  Shared Risk Link Group Number: %d%s", n,
			VTY_NEWLINE);
	else
		zlog_debug("  Shared Risk Link Group Number: %d", n);

	for (i = 0; i < n; i++) {
		if (vty != NULL)
			vty_out(vty, " Value n°   #%d: %d%s", i,
				ntohs(&top->value[i]), VTY_NEWLINE);
		else
			zlog_debug("  Value n°  #%d: %d", i,
				   ntohs(&top->value[i]));
	}

	return BGP_TLV_SIZE(tlvh);
}
static u_int16_t show_vty_opaque_link_attribute(struct vty *vty,
						struct te_tlv_nlri_header *tlvh)
{
	struct bgp_nlri_tlv_ola *top = (struct bgp_nlri_tlv_ola *)tlvh;

	if (vty != NULL) {
		vty_out(vty, "    Opaque Link attributes: %u%s",
			(u_int32_t)ntohs(&top->value), VTY_NEWLINE);
	} else {
		zlog_debug("    Opaque Link attributes: %u",
			   (u_int32_t)ntohs(&top->value));
	}

	return BGP_TLV_SIZE(tlvh);
}

static u_int16_t show_vty_link_name_attribute(struct vty *vty,
					      struct te_tlv_nlri_header *tlvh)
{
	struct bgp_nlri_tlv_lna *top = (struct bgp_nlri_tlv_lna *)tlvh;

	if (vty != NULL) {
		vty_out(vty, "    Link Name: %p%s", top->value, VTY_NEWLINE);
	} else
		zlog_debug("    Link Name: %p", top->value);

	return BGP_TLV_SIZE(tlvh);
}

static u_int16_t
show_vty_bgp_nlri_tlv_igp_flags(struct vty *vty,
				struct te_tlv_nlri_header *tlvh)
{
	struct bgp_nlri_tlv_igp_flags *top =
		(struct bgp_nlri_tlv_igp_flags *)tlvh;

	if (vty != NULL)
		vty_out(vty, "    IGP Flags: %u%s", (u_char)ntohs(top->value),
			VTY_NEWLINE);
	else
		zlog_debug("    IGP Flags: %u", (u_char)ntohs(top->value));

	return BGP_TLV_SIZE(tlvh);
}

static u_int16_t
show_vty_bgp_nlri_tlv_route_tag(struct vty *vty,
				struct te_tlv_nlri_header *tlvh)
{
	struct bgp_nlri_tlv_route_tag *top;
	int i, n;
	top = (struct bgp_nlri_tlv_route_tag *)tlvh;

	n = ntohs(top->header.nlri_length) / sizeof(&top->value[0]);
	// The size is 4 bytes
	if (vty != NULL)
		vty_out(vty, "  Route Tag(s): %d%s", n, VTY_NEWLINE);
	else
		zlog_debug("  Route Tag(s): %d", n);

	for (i = 0; i < n; i++) {
		if (vty != NULL)
			vty_out(vty, " Value n°   #%d: %x%s", i,
				ntohl(top->value[i]), VTY_NEWLINE);
		else
			zlog_debug("  Value n°  #%d: %x", i,
				   ntohl(top->value[i]));
	}

	return BGP_TLV_SIZE(tlvh);
}

static u_int16_t
show_vty_bgp_nlri_tlv_extended_tag(struct vty *vty,
				   struct te_tlv_nlri_header *tlvh)
{
	struct bgp_nlri_tlv_extended_tag *top;
	int i, n;
	top = (struct bgp_nlri_tlv_extended_tag *)tlvh;

	n = ntohs(top->header.nlri_length) / sizeof(&top->value[0]);
	// The size is 8 bytes
	if (vty != NULL)
		vty_out(vty, "  Extended Route Tag(s): %d%s", n, VTY_NEWLINE);
	else
		zlog_debug("  Extended Route Tag(s): %d", n);

	for (i = 0; i < n; i++) {
		if (vty != NULL) {
			vty_out(vty, " Value n°   #%d: %lu%s", i,
				(u_int64_t)ntohl(top->value[i]), VTY_NEWLINE);
		} else
			zlog_debug("  Value n°  #%d: %lu", i,
				   (u_int64_t)ntohl(top->value[i]));
	}

	return BGP_TLV_SIZE(tlvh);
}

static u_int16_t
show_vty_bgp_nlri_tlv_prefix_metric(struct vty *vty,
				    struct te_tlv_nlri_header *tlvh)
{
	struct bgp_nlri_tlv_prefix_metric *top =
		(struct bgp_nlri_tlv_prefix_metric *)tlvh;

	if (vty != NULL)
		vty_out(vty, "    Prefix Metric: %u%s", ntohl(top->value),
			VTY_NEWLINE);
	else
		zlog_debug("    Prefix Metric: %u",
			   (u_int32_t)ntohl(top->value));

	return BGP_TLV_SIZE(tlvh);
}

static u_int16_t
show_bgp_nlri_tlv_ospf_fowarding_adress(struct vty *vty,
					struct te_tlv_nlri_header *tlvh)
{
	struct bgp_nlri_tlv_ospf_fowarding_adress *top =
		(struct bgp_nlri_tlv_ospf_fowarding_adress *)tlvh;
	if (vty != NULL) {
		if (top->header.nlri_length
		    == BGP_NLRI_TLV_LEN_IPV4_FOWARDING_ADDRESS) {
			vty_out(vty, " IPv4 OSPF Fowarding Address: %s%s",
				inet_ntoa(top->value.addr4), VTY_NEWLINE);
		}
		if (top->header.nlri_length
		    == BGP_NLRI_TLV_LEN_IPV6_FOWARDING_ADDRESS) {
#ifdef HAVE_IPV6
			char straddr[INET6_ADDRSTRLEN];
			vty_out(vty, "	 IPv6 OSPF Fowarding Address: %s%s",
				inet_ntop(AF_INET6, &top->value.addr6, straddr,
					  INET6_ADDRSTRLEN),
				VTY_NEWLINE);
#endif /*HAVE_IPV6*/
		}
	} else {
		zlog_debug("   IPv4 OSPF Fowarding Address: %s",
			   inet_ntoa(top->value.addr4));
#ifdef HAVE_IPV6
		char straddr[INET6_ADDRSTRLEN];
		zlog_debug("   IPv6 OSPF Fowarding Address: %s",
			   inet_ntop(AF_INET6, &top->value.addr6, straddr,
				     INET6_ADDRSTRLEN));
#endif /*HAVE_IPV6*/
	}
	return BGP_TLV_SIZE(tlvh);
}

static u_int16_t
show_bgp_nlri_tlv_opaque_prefix_attribute(struct vty *vty,
					  struct te_tlv_nlri_header *tlvh)
{
	struct bgp_nlri_tlv_opa *top = (struct bgp_nlri_tlv_opa *)tlvh;

	if (vty != NULL)

		vty_out(vty, "    Opaque prefix Attribute: %p%s", top->value,
			VTY_NEWLINE);
	else
		zlog_debug("    Opaque prefix Attribute: %p", top->value);

	return BGP_TLV_SIZE(tlvh);
}

static u_int16_t show_vty_unknown_tlv(struct vty *vty,
				      struct te_tlv_nlri_header *tlvh)
{
	int i, rtn = 1;
	u_char *v = (u_char *)tlvh;

	if (vty != NULL) {
		if (tlvh->nlri_length != 0) {
			vty_out(vty,
				"    Unknown TLV: [type(%#.2x), length(%#.2x)]%s",
				tlvh->nlri_type, tlvh->nlri_length,
				VTY_NEWLINE);
			vty_out(vty, "       Dump: [00]");
			rtn = 1; /* initialize end of line counter */
			for (i = 0; i < tlvh->nlri_length; i++) {
				vty_out(vty, " %#.2x", v[i]);
				if (rtn == 8) {
					vty_out(vty, "%s             [%.2x]",
						VTY_NEWLINE, i + 1);
					rtn = 1;
				} else
					rtn++;
			}
			vty_out(vty, "%s", VTY_NEWLINE);
		} else
			vty_out(vty,
				"    Unknown TLV: [type(%#.2x), length(%#.2x)]%s",
				tlvh->nlri_type, tlvh->nlri_length,
				VTY_NEWLINE);
	} else {
		zlog_debug("      Unknown TLV: [type(%#.2x), length(%#.2x)]",
			   tlvh->nlri_type, tlvh->nlri_length);
	}

	return BGP_TLV_HDR_SIZE;
}

/*--------------- ---------Main Show function---------------------------------
 */

int show_bgp_linkstate_print_detail(struct vty *vty, struct ls_bgpls *te)
{
	struct te_tlv_nlri_header *tlvh, *next;
	u_int16_t sum = 0;

	zlog_debug("BGP-LS: Show database TE detail");

	if (te->header.nlri_type == 0) /* En attendant */
		return CMD_WARNING;

	tlvh = &te->header;

	for (; sum < te->header.nlri_length;
	     tlvh = (next ? next : BGP_TLV_HDR_NEXT(tlvh))) {
		next = NULL;
		switch (ntohs(tlvh->nlri_type)) {
		case BGP_NLRI_TLV_MULTI_TOPOLOGY_ID:
			sum += show_vty_multi_topology_identifier(vty, &tlvh);
			break;
		case BGP_NLRI_TLV_NODE_FLAG_BITS:
			sum += show_vty_node_flag_bits(vty, &tlvh);
			break;
		case BGP_NLRI_TLV_OPAQUE_NODE_PROPERTIES:
			sum += show_vty_opaque_node_properties(vty, &tlvh);
			break;
		case BGP_NLRI_TLV_NODE_NAME:
			sum += show_vty_node_name(vty, tlvh);
			break;
		case BGP_NLRI_TLV_IS_IS_AREA_IDENTIFIER:
			sum += show_vty_is_is_area_identifier(vty, tlvh);
			break;
		case BGP_NLRI_TLV_IPV4_ROUTER_ID_OF_LOCAL_NODE:
			sum += show_vty_ipv4_router_id_of_local_node(vty, tlvh);
			break;
		case BGP_NLRI_TLV_IPV6_ROUTER_ID_OF_LOCAL_NODE:
			sum += show_vty_ipv6_router_id_of_local_node(vty, tlvh);
			break;
		case BGP_NLRI_TLV_IPV4_ROUTER_ID_OF_REMOTE_NODE:
			sum += show_vty_ipv4_router_id_of_remote_node(vty,
								      tlvh);
			break;
		case BGP_NLRI_TLV_IPV6_ROUTER_ID_OF_REMOTE_NODE:
			sum += show_vty_ipv6_router_id_of_remote_node(vty,
								      tlvh);
			break;
		case BGP_NLRI_TLV_ADMINISTRATIVE_GROUP_COLOR:
			sum += show_vty_admin_grp_color(vty, tlvh);
			break;
		case BGP_NLRI_TLV_MAX_LINK_BANDWIDTH:
			sum += show_vty_max_link_bw(vty, tlvh);
			break;
		case BGP_NLRI_TLV_MAX_RESERVABLE_LINK_BANDWIDTH:
			sum += show_vty_max_rsv_bw(vty, tlvh);
			break;
		case BGP_NLRI_TLV_UNRESERVED_BANDWIDTH:
			sum += show_vty_unrsv_bw(vty, tlvh);
			break;
		case BGP_NLRI_TLV_TE_DEFAULT_METRIC:
			sum += show_vty_te_metric(vty, tlvh);
			break;
		case BGP_NLRI_TLV_LINK_PROTECTION_TYPE:
			sum += show_vty_link_protection_type(vty, tlvh);
			break;
		case BGP_NLRI_TLV_MPLS_PROTOCOL_MASK:
			sum += show_vty_mpls_protocol_mask(vty, tlvh);
			break;
		case BGP_NLRI_TLV_IGP_METRIC:
			sum += show_vty_igp_metric(vty, tlvh);
			break;
		case BGP_NLRI_TLV_SHARED_RISK_LINK_GROUP:
			sum += show_vty_shared_risk_link_group(vty, tlvh);
			break;
		case BGP_NLRI_TLV_OPAQUE_LINK_ATTRIBUTE:
			sum += show_vty_opaque_link_attribute(vty, tlvh);
			break;
		case BGP_NLRI_TLV_LINK_NAME_ATTRIBUTE:
			sum += show_vty_link_name_attribute(vty, tlvh);
			break;
		case BGP_NLRI_TLV_IGP_FLAGS:
			sum += show_vty_bgp_nlri_tlv_igp_flags(vty, tlvh);
			break;
		case BGP_NLRI_TLV_ROUTE_TAG:
			sum += show_vty_bgp_nlri_tlv_route_tag(vty, tlvh);
			break;
		case BGP_NLRI_TLV_EXTENDED_TAG:
			sum += show_vty_bgp_nlri_tlv_extended_tag(vty, tlvh);
			break;
		case BGP_NLRI_TLV_PREFIX_METRIC:
			sum += show_vty_bgp_nlri_tlv_prefix_metric(vty, tlvh);
			break;
		case BGP_NLRI_TLV_OSPF_FORWARDING_ADDRESS:
			sum += show_bgp_nlri_tlv_ospf_fowarding_adress(vty,
								       tlvh);
			break;
		case BGP_NLRI_TLV_OPAQUE_PREFIX_ATTRIBUTE:
			sum += show_bgp_nlri_tlv_opaque_prefix_attribute(vty,
									 tlvh);
			break;
		default:
			sum += show_vty_unknown_tlv(vty, tlvh);
			break;
		}
	}
	return sum;
}

// static
int show_ls_route(struct vty *vty, struct peer *peer)
{
	struct bgp *bgp;
	struct bgp_table *table;
	struct bgp_node *rn;
	struct bgp_node *rm;
	struct attr *attr;
	int rd_header;
	int header = 1;
	// char v4_header[] = "   Network          Next Hop            Metric
	// LocPrf Weight Path%s";

	bgp = bgp_get_default();
	if (bgp == NULL) {
		vty_out(vty, "No BGP process is configured%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	for (rn = bgp_table_top(bgp->rib[AFI_LINK_STATE][SAFI_LINK_STATE]); rn;
	     rn = bgp_route_next(rn)) {

		if ((table = rn->info) != NULL) {
			rd_header = 1;

			for (rm = bgp_table_top(table); rm;
			     rm = bgp_route_next(rm))
				if ((attr = rm->info) != NULL) {
					if (header) {
						vty_out(vty,
							"BGP table version is 0, local router ID is %s%s",
							inet_ntoa(
								bgp->router_id),
							VTY_NEWLINE);
						vty_out(vty,
							"Status codes: s suppressed, d damped, h history, * valid, > best, i - internal%s",
							VTY_NEWLINE);
						vty_out(vty,
							"Origin codes: i - IGP, e - EGP, ? - incomplete%s%s",
							VTY_NEWLINE,
							VTY_NEWLINE);
						header = 0;
					}

					if (rd_header) {
						show_bgp_linkstate_print_detail(
							vty,
							attr->link_state_attr);
					}
				}
		}
	}

	return CMD_SUCCESS;
}

/*------------------------------------------------------------------------*
 * Followings are vty command functions.
 *------------------------------------------------------------------------*/
DEFUN(show_ip_bgp_linkstate_database, show_ip_bgp_linkstate_database_cmd,
      "show ip bgp ls database",
      SHOW_STR IP_STR BGP_STR
      "Link State Information: BGP-LS Attributes\n"
      "Database of BGP-LS Attributes\n")
{
	return CMD_SUCCESS;
}


DEFUN(show_ip_bgp_linkstate_database_detail,
      show_ip_bgp_linkstate_database_detail_cmd,
      "show ip bgp ls database detail",
      SHOW_STR IP_STR BGP_STR
      "Link State Information: BGP-LS Attributes\n"
      "Database of BGP-LS Attributes\n"
      "Database detail of BGP-LS Attributes\n")
{
	struct bgp *bgp;
	struct peer *peer;
	bgp = bgp_get_default();
	peer = bgp->peer_self;
	show_ls_route(vty, peer);
	return CMD_SUCCESS;
}

void bgp_link_state_init(void)
{
	install_element(VIEW_NODE, &show_ip_bgp_linkstate_database_cmd);
	install_element(VIEW_NODE, &show_ip_bgp_linkstate_database_detail_cmd);
	install_element(ENABLE_NODE, &show_ip_bgp_linkstate_database_cmd);
	install_element(ENABLE_NODE,
			&show_ip_bgp_linkstate_database_detail_cmd);
}
