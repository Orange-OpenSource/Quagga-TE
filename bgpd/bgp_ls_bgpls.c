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

#include "linklist.h"
#include "prefix.h"
#include "memory.h"
#include "vector.h"
#include "vty.h"
#include "stream.h"
#include "log.h"
#include "hash.h"
#include "jhash.h"
#include "command.h"
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
#include "bgpd/bgp_lsdb.h"

/**************************************************************************************

   +--------------+-----------------------+----------+-----------------+
   |   TLV Code   | Description           |   Length | Value defined   |
   |    Point     |                       |          | in:             |
   +--------------+-----------------------+----------+-----------------+
   |     263      | Multi-Topology        | variable | Section 3.2.1.5 |
   |              | Identifier            |          |                 |
   |     1024     | Node Flag Bits        |        1 | Section 3.3.1.1 |
   |     1025     | Opaque Node           | variable | Section 3.3.1.5 |
   |              | Properties            |          |                 |
   |     1026     | Node Name             | variable | Section 3.3.1.3 |
   |     1027     | IS-IS Area Identifier | variable | Section 3.3.1.2 |
   |     1028     | IPv4 Router-ID of     |        4 | [RFC5305]/4.3   |
   |              | Local Node            |          |                 |
   |     1029     | IPv6 Router-ID of     |       16 | [RFC6119]/4.1   |
   |              | Local Node            |          |                 |
   +--------------+-----------------------+----------+-----------------+

   +-----------+---------------------+--------------+------------------+
   |  TLV Code | Description         |  IS-IS TLV   | Defined in:      |
   |   Point   |                     |   /Sub-TLV   |                  |
   +-----------+---------------------+--------------+------------------+
   |    1028   | IPv4 Router-ID of   |   134/---    | [RFC5305]/4.3    |
   |           | Local Node          |              |                  |
   |    1029   | IPv6 Router-ID of   |   140/---    | [RFC6119]/4.1    |
   |           | Local Node          |              |                  |
   |    1030   | IPv4 Router-ID of   |   134/---    | [RFC5305]/4.3    |
   |           | Remote Node         |              |                  |
   |    1031   | IPv6 Router-ID of   |   140/---    | [RFC6119]/4.1    |
   |           | Remote Node         |              |                  |
   |    1088   | Administrative      |     22/3     | [RFC5305]/3.1    |
   |           | group (color)       |              |                  |
   |    1089   | Maximum link        |     22/9     | [RFC5305]/3.3    |
   |           | bandwidth           |              |                  |
   |    1090   | Max. reservable     |    22/10     | [RFC5305]/3.5    |
   |           | link bandwidth      |              |                  |
   |    1091   | Unreserved          |    22/11     | [RFC5305]/3.6    |
   |           | bandwidth           |              |                  |
   |    1092   | TE Default Metric   |    22/18     | Section 3.3.2.3/ |
   |    1093   | Link Protection     |    22/20     | [RFC5307]/1.2    |
   |           | Type                |              |                  |
   |    1094   | MPLS Protocol Mask  |     ---      | Section 3.3.2.2  |
   |    1095   | IGP Metric          |     ---      | Section 3.3.2.4  |
   |    1096   | Shared Risk Link    |     ---      | Section 3.3.2.5  |
   |           | Group               |              |                  |
   |    1097   | Opaque link         |     ---      | Section 3.3.2.6  |
   |           | attribute           |              |                  |
   |    1098   | Link Name attribute |     ---      | Section 3.3.2.7  |
   +-----------+---------------------+--------------+------------------+
****************************************************************************************/
void bgp_link_state_decode(struct bgp_attr_parser_args *args, struct stream *s)
{
	size_t start;
	size_t endp;
	const bgp_size_t length = args->length;
	struct peer *const peer = args->peer;
	struct attr *const attr = args->attr;
	int i, n;
	size_t pos;
	pos = stream_get_getp(s);
	u_int16_t ls_type, mid_type;
	u_int16_t ls_length, mid_length;
	void *value;
	char onp[ls_length], nn[ls_length], i6ridofln[ls_length],
		i6ridofrn[ls_length];
	char igpm[ls_length], iiai[ls_length], opa[ls_length];
	char ofa[ls_length], ola[ls_length], lna[ls_length];

	endp = stream_get_getp(s) + length;

	/* Get link state attributes to the end of attribute length. */
	while (stream_get_getp(s) < endp) {
		ls_type = stream_getw(s);
		ls_length = stream_getw(s);
		/*
			 if (length)
				  {
				    zlog_info ("%s: (%s) Failed to read Link
		   State Value %d : %d ,%d",
					       __func__,
		   peer->host,ls_type,ls_length,length);
				  }
		*/
		switch (ls_type) {
			/********************************************************
					  ---- Node Attribute ----
			 ********************************************************/

		case BGP_NLRI_TLV_MULTI_TOPOLOGY_ID:

			mid_type = stream_getw(s);
			mid_length = stream_getw(s);

			n = (mid_length) / 2;
			i = 0;
			for (i = 0; i <= (n - 1); i++) {
				attr->mp_bgpls_nlri->mid->value[i] =
					stream_getw(s);
			}
			break;

		case BGP_NLRI_TLV_NODE_FLAG_BITS:

			attr->link_state_attr->nfb.value = stream_getc(s);
			break;

		case BGP_NLRI_TLV_OPAQUE_NODE_PROPERTIES:

			//&attr->link_state_attr->onp->value
			stream_get(onp, s, ls_length);
			break;

		case BGP_NLRI_TLV_NODE_NAME:

			//&attr->link_state_attr->nn->value
			stream_get(nn, s, ls_length);
			break;

		case BGP_NLRI_TLV_IS_IS_AREA_IDENTIFIER:

			//&attr->link_state_attr->iiai->value
			stream_get(iiai, s, ls_length);
			break;

		case BGP_NLRI_TLV_IPV4_ROUTER_ID_OF_LOCAL_NODE:

			attr->link_state_attr->i4ridofln.value.s_addr =
				stream_get_ipv4(s);
			break;

		case BGP_NLRI_TLV_IPV6_ROUTER_ID_OF_LOCAL_NODE:

#ifdef HAVE_IPV6
			// value=attr->link_state_attr->i6ridofln.value;
			stream_get(
				i6ridofln, s,
				BGP_NLRI_TLV_LEN_IPV6_ROUTER_ID_OF_LOCAL_NODE);
#endif
			break;

			/********************************************************
						  ---- Link Attribute ----
			 ********************************************************/

		case BGP_NLRI_TLV_IPV4_ROUTER_ID_OF_REMOTE_NODE:

			attr->link_state_attr->i4ridofrn.value.s_addr =
				stream_get_ipv4(s);
			break;

		case BGP_NLRI_TLV_IPV6_ROUTER_ID_OF_REMOTE_NODE:

#ifdef HAVE_IPV6
			// value=&attr->link_state_attr->i6ridofrn.value;
			stream_get(
				i6ridofrn, s,
				BGP_NLRI_TLV_LEN_IPV6_ROUTER_ID_OF_LOCAL_NODE);
#endif
			break;

		case BGP_NLRI_TLV_ADMINISTRATIVE_GROUP_COLOR:

			attr->link_state_attr->agc.value = stream_getl(s);
			break;

		case BGP_NLRI_TLV_MAX_LINK_BANDWIDTH:

			attr->link_state_attr->mlb.value = stream_getl(s);
			break;

		case BGP_NLRI_TLV_MAX_RESERVABLE_LINK_BANDWIDTH:

			attr->link_state_attr->mrlb.value = stream_getl(s);
			break;

		case BGP_NLRI_TLV_UNRESERVED_BANDWIDTH:

			n = attr->link_state_attr->header.nlri_length;
			for (i = 0; i <= (n - 1); i++) {
				attr->link_state_attr->urb.value[i] =
					stream_getl(s);
			}
			break;

		case BGP_NLRI_TLV_TE_DEFAULT_METRIC:

			attr->link_state_attr->tdm.value = stream_getl(s);
			break;

		case BGP_NLRI_TLV_LINK_PROTECTION_TYPE:

			attr->link_state_attr->lpt.value = stream_getw(s);
			break;

		case BGP_NLRI_TLV_MPLS_PROTOCOL_MASK:

			attr->link_state_attr->mpm.value = stream_getc(s);
			break;

		case BGP_NLRI_TLV_IGP_METRIC:

			// value=&attr->link_state_attr->igpm->value;
			stream_get(igpm, s, ls_length);
			break;

		case BGP_NLRI_TLV_SHARED_RISK_LINK_GROUP:

			n = (ls_length) / 4;

			for (i = 0; i <= (n - 1); i++) {
				attr->link_state_attr->srlg->value[i] =
					stream_getl(s);
			}
			break;

		case BGP_NLRI_TLV_OPAQUE_LINK_ATTRIBUTE:
			/*Need to check it*/
			// value=&attr->link_state_attr->ola->value;
			stream_get(ola, s, ls_length);
			break;

		case BGP_NLRI_TLV_LINK_NAME_ATTRIBUTE:

			// value=&attr->link_state_attr->lna->value;
			stream_get(lna, s, ls_length);
			break;

			/********************************************************
					      ---- Prefix Attribute ----
			    ********************************************************/
		case BGP_NLRI_TLV_IGP_FLAGS:

			attr->link_state_attr->ifl.value = stream_getc(s);
			break;

		case BGP_NLRI_TLV_ROUTE_TAG:

			n = (ls_length) / 4;
			i = 0;
			for (i = 0; i <= (n - 1); i++) {
				attr->link_state_attr->rt->value[i] =
					stream_getl(s);
			}
			break;

		case BGP_NLRI_TLV_EXTENDED_TAG:

			n = (ls_length) / 8;
			i = 0;
			for (i = 0; i <= (n - 1); i++) {
				attr->link_state_attr->et->value[i] =
					stream_getq(s);
			}
			break;

		case BGP_NLRI_TLV_PREFIX_METRIC:

			attr->link_state_attr->pm.value = stream_getl(s);
			break;

		case BGP_NLRI_TLV_OSPF_FORWARDING_ADDRESS:

			switch (ls_length) {
			case 4:
				attr->link_state_attr->ofa.value.addr4.s_addr =
					stream_get_ipv4(s);
				break;
			case 16:
#ifdef HAVE_IPV6
				// value=&attr->link_state_attr->ofa.value;
				stream_get(
					ofa, s,
					BGP_NLRI_TLV_LEN_IPV6_FOWARDING_ADDRESS);
#endif /* HAVE_IPV6 */
				break;
			default:
				/*
			      zlog_info ("%s: %s, NLRI length, %s, goes past end
			      of attribute",
								      __func__,
			      peer->host, ls_length);
								      */
				//	return BGP_ATTR_PARSE_ERROR_NOTIFYPLS;
				break;
			}
			break;

		case BGP_NLRI_TLV_OPAQUE_PREFIX_ATTRIBUTE:

			// value=&attr->link_state_attr->opa->value;
			stream_get(opa, s, ls_length);
			break;

		default:
			/*
				      zlog_info ("%s sent invalid Link State
			   TLV, %p", peer->host,value); return
			   BGP_ATTR_PARSE_ERROR_NOTIFYPLS;
		     */
			break;
		}
		//  pos+=stream_get_getp (s);
	}
	//  return BGP_ATTR_PARSE_PROCEED;
}

/*----------------------------------------------------------------------------*
 * 				Followings are vty session control functions.
 **
 *----------------------------------------------------------------------------*/
static u_int16_t
show_vty_local_node_descriptors(struct vty *vty,
				struct te_tlv_nlri_header *tlvh)
{
	struct bgp_nlri_tlv_lrnd *top = (struct bgp_nlri_tlv_lrnd *)tlvh;

	if (vty != NULL)
		vty_out(vty, "  Local Node Descriptors: %u octets of data%s",
			ntohs(&top->value), VTY_NEWLINE);
	else
		zlog_debug("    Local Node Descriptors: %u octets of data",
			   ntohs(&top->value));

	return BGP_TLV_SIZE(tlvh); /* Here is special, not "TLV_SIZE". */
}

static u_int16_t
show_vty_remote_node_descriptors(struct vty *vty,
				 struct te_tlv_nlri_header *tlvh)
{
	struct bgp_nlri_tlv_lrnd *top = (struct bgp_nlri_tlv_lrnd *)tlvh;

	if (vty != NULL)
		vty_out(vty, " Remote Node Descriptors: %u octets of data%s",
			ntohs(&top->value), VTY_NEWLINE);
	else
		zlog_debug(" Remote Node Descriptors: %u octets of data",
			   ntohs(&top->value));

	return BGP_TLV_SIZE(tlvh); /* Here is special, not "TLV_SIZE". */
}

static u_int16_t show_vty_subtlv_llri(struct vty *vty,
				      struct te_tlv_nlri_header *tlvh)
{
	struct bgp_nlri_tlv_llri *top = (struct bgp_nlri_tlv_llri *)tlvh;

	if (vty != NULL) {
		vty_out(vty, "    Link Local  ID: %d%s",
			(u_int32_t)ntohl(top->local), VTY_NEWLINE);
		vty_out(vty, "    Link Remote ID: %d%s",
			(u_int32_t)ntohl(top->remote), VTY_NEWLINE);
	} else {
		zlog_debug("      Link Local  ID: %d",
			   (u_int32_t)ntohl(top->local));
		zlog_debug("      Link Remote ID: %d",
			   (u_int32_t)ntohl(top->remote));
	}

	return BGP_TLV_SIZE(tlvh);
}

static u_int16_t show_vty_ipv4_interface_addr(struct vty *vty,
					      struct te_tlv_nlri_header *tlvh)
{
	struct bgp_nlri_tlv_i4i_addr *top =
		(struct bgp_nlri_tlv_i4i_addr *)tlvh;

	if (vty != NULL)
		vty_out(vty, "  IPv4 interface Address: %s%s",
			inet_ntoa(top->value), VTY_NEWLINE);
	else
		zlog_debug("   IPv4 interface Address: %s",
			   inet_ntoa(top->value));

	return BGP_TLV_SIZE(tlvh);
}

static u_int16_t show_vty_ipv4_neighbor_addr(struct vty *vty,
					     struct te_tlv_nlri_header *tlvh)
{
	struct bgp_nlri_tlv_i4n_addr *top =
		(struct bgp_nlri_tlv_i4n_addr *)tlvh;

	if (vty != NULL)
		vty_out(vty, " IPv4 neighbor Address: %s%s",
			inet_ntoa(top->value), VTY_NEWLINE);
	else
		zlog_debug("   IPv4 neighbor Address: %s",
			   inet_ntoa(top->value));

	return BGP_TLV_SIZE(tlvh);
}

static u_int16_t show_vty_ipv6_interface_addr(struct vty *vty,
					      struct te_tlv_nlri_header *tlvh)
{
	struct bgp_nlri_tlv_i6i_addr *top =
		(struct bgp_nlri_tlv_i6i_addr *)tlvh;
#ifdef HAVE_IPV6
	char straddr[INET6_ADDRSTRLEN];
	if (vty != NULL)
		vty_out(vty, " IPv6 interface Address: %s%s",
			inet_ntop(AF_INET6, &top->value, straddr,
				  INET6_ADDRSTRLEN),
			VTY_NEWLINE);
	else
		zlog_debug("   IPv6 interface Address: %s",
			   inet_ntop(AF_INET6, &top->value, straddr,
				     INET6_ADDRSTRLEN));
#endif /*HAVE_IPV6*/
	return BGP_TLV_SIZE(tlvh);
}


static u_int16_t show_vty_ipv6_neighbor_addr(struct vty *vty,
					     struct te_tlv_nlri_header *tlvh)
{
	struct bgp_nlri_tlv_i6n_addr *top =
		(struct bgp_nlri_tlv_i6n_addr *)tlvh;
#ifdef HAVE_IPV6
	char straddr[INET6_ADDRSTRLEN];
	if (vty != NULL)
		vty_out(vty, "	 IPv6 neighbor Address: %s%s",
			inet_ntop(AF_INET6, &top->value, straddr,
				  INET6_ADDRSTRLEN),
			VTY_NEWLINE);
	else
		zlog_debug("   IPv6 neighbor Address: %s",
			   inet_ntop(AF_INET6, &top->value, straddr,
				     INET6_ADDRSTRLEN));
#endif /*HAVE_IPV6*/
	return BGP_TLV_SIZE(tlvh);
}

static u_int16_t show_vty_multi_topology_id(struct vty *vty,
					    struct te_tlv_nlri_header *tlvh)
{
	struct bgp_nlri_tlv_mt_id *top;
	int i, n;

	top = (struct bgp_nlri_tlv_mt_id *)tlvh;
	n = ntohs(tlvh->nlri_length) / sizeof(&top->value[0]);
	if (vty != NULL)
		vty_out(vty, "  Multi Topology ID number: %d%s", n,
			VTY_NEWLINE);
	else
		zlog_debug("  Multi Topology ID number: %d", n);

	for (i = 0; i < n; i++) {
		if (vty != NULL) {
			vty_out(vty, " ID  #%d: %x%s", i,
				(u_int16_t)ntohs(&top->value[i]), VTY_NEWLINE);
		} else
			zlog_debug(" ID   #%d: %x", i,
				   (u_int16_t)ntohs(&top->value[i]));
	}
	return BGP_TLV_SIZE(tlvh);
}

static u_int16_t show_vty_ospf_type_route(struct vty *vty,
					  struct te_tlv_nlri_header *tlvh)
{
	struct bgp_nlri_tlv_ort *top = (struct bgp_nlri_tlv_ort *)tlvh;

	if (vty != NULL)
		vty_out(vty, " OSPF Type Route: %c%s",
			(u_char)ntohs(top->value), VTY_NEWLINE);
	else
		zlog_debug("OSPF Type Route: %c", (u_char)ntohs(top->value));

	return BGP_TLV_SIZE(tlvh);
}

static u_int16_t show_vty_ip_reachability(struct vty *vty,
					  struct te_tlv_nlri_header *tlvh)
{
	struct bgp_nlri_tlv_ip_reach *top =
		(struct bgp_nlri_tlv_ip_reach *)tlvh;

	if (vty != NULL) {
		vty_out(vty, " IP Reachability: %c%s",
			(u_char)ntohs(top->prefix), VTY_NEWLINE);
		vty_out(vty, " IP Reachability: %p%s", &top->value,
			VTY_NEWLINE);

	} else {
		zlog_debug("   IP Reachability: %c",
			   (u_char)ntohs(top->prefix));
		zlog_debug("   IP Reachability: %p", &top->value);
	}
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

int show_bgp_mpreach_print_detail(struct vty *vty, struct mp_bgpls_nlri *te)
{
	struct te_tlv_nlri_header *tlvh, *next;
	u_int16_t sum = 0;

	zlog_debug("BGP-LS: Show database TE detail");

	if (te->header.nlri_type == 0)
		return CMD_WARNING;

	tlvh->nlri_type = te->header.nlri_type;

	for (; sum < te->header.nlri_length;
	     tlvh = (next ? next : BGP_TLV_HDR_NEXT(tlvh))) {
		next = NULL;
		switch (tlvh->nlri_type) {
		case BGP_NLRI_TLV_LOCAL_NODE_DESCRIPTORS:
			sum += show_vty_local_node_descriptors(vty, tlvh);
			break;
		case BGP_NLRI_TLV_REMOTE_NODE_DESCRIPTORS:
			sum += show_vty_remote_node_descriptors(vty, tlvh);
			break;
		case BGP_NLRI_TLV_LINK_LOCAL_REMOTE_IDENTIFIERS:
			sum += show_vty_subtlv_llri(vty, tlvh);
			break;
		case BGP_NLRI_TLV_IPV4_INTERFACE_ADDRESS:
			sum += show_vty_ipv4_interface_addr(vty, tlvh);
			break;
		case BGP_NLRI_TLV_IPV4_NEIGHBOR_ADDRESS:
			sum += show_vty_ipv4_neighbor_addr(vty, tlvh);
			break;
		case BGP_NLRI_TLV_IPV6_INTERFACE_ADDRESS:
			sum += show_vty_ipv6_interface_addr(vty, tlvh);
			break;
		case BGP_NLRI_TLV_IPV6_NEIGHBOR_ADDRESS:
			sum += show_vty_ipv6_neighbor_addr(vty, tlvh);
			break;
		case BGP_NLRI_TLV_MULTI_TOPOLOGY_ID:
			sum += show_vty_multi_topology_id(vty, tlvh);
			break;
		case BGP_NLRI_TLV_OSPF_ROUTE_TYPE:
			sum += show_vty_ospf_type_route(vty, tlvh);
			break;
		case BGP_NLRI_TLV_IP_REACHABILITY_INFORMATION:
			sum += show_vty_ip_reachability(vty, tlvh);
			break;
		default:
			sum += show_vty_unknown_tlv(vty, tlvh);
			break;
		}
	}
	return CMD_SUCCESS;
}

DEFUN (show_ip_bgp_mpreach_database,
       show_ip_bgp_mpreach_database_cmd,
       "show ip bgp mp_reach database",
       SHOW_STR
       IP_STR
       BGP_STR
       "Link State Information: BGP-LS Attributes\n"
       "Database of BGP-LS Attributes\n")
{
	return 0;
}

DEFUN (show_ip_bgp_mpreach_database_detail,
      show_ip_bgp_mpreach_database_detail_cmd,
      "show ip bgp mp_reach database detail",
      SHOW_STR
      IP_STR
      BGP_STR
      "Link State Information: BGP-LS Attributes\n"
      "Database of BGP-LS Attributes\n"
      "Database detail of BGP-LS Attributes\n")
{
	struct bgp *bgp;
	struct bgp_table *table;
	struct bgp_node *rn;
	struct bgp_node *rm;
	struct attr *attr;
	int rd_header;
	int header = 1;

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
						show_bgp_mpreach_print_detail(
							vty,
							attr->mp_bgpls_nlri);
					}
				}
		}
	}

	return CMD_SUCCESS;
}

void bgp_mp_reach_init(void)
{
	install_element(VIEW_NODE, &show_ip_bgp_mpreach_database_cmd);
	install_element(VIEW_NODE, &show_ip_bgp_mpreach_database_detail_cmd);
	install_element(ENABLE_NODE, &show_ip_bgp_mpreach_database_cmd);
	install_element(ENABLE_NODE, &show_ip_bgp_mpreach_database_detail_cmd);
}
