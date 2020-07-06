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

#ifndef _ZEBRA_BGP_LS_TE_H
#define _ZEBRA_BGP_LS_TE_H

#define BGP_TLV_HDR_SIZE (sizeof(struct te_tlv_nlri_header))

#define BGP_TLV_BODY_SIZE(tlvh)                                                \
	(ROUNDUP(ntohs((tlvh)->nlri_length), sizeof(u_int32_t)))

#define BGP_TLV_SIZE(tlvh) (BGP_TLV_HDR_SIZE + ntohs((tlvh)->nlri_length))

#define BGP_TLV_HDR_NEXT(tlvh) 	(struct te_tlv_nlri_header *)((char *)(tlvh) + BGP_TLV_SIZE(tlvh))

#define BGP_TLV_TYPE(tlvh)     tlvh.header.nlri_type
#define BGP_TLV_LEN(tlvh)      tlvh.header.nlri_length
#define BGP_TLV_HDR(tlvh)      tlvh.header
#define BGP_TLV_VAL(tlvh)      tlvh.value
#define BGP_TLV_DATA(tlvh)     tlvh + BGP_TLV_HDR_SIZE

#ifdef roundup
#  define ROUNDUP(val, gran)	roundup(val, gran)
#else  /* roundup */
#  define ROUNDUP(val, gran)	(((val) - 1 | (gran) - 1) + 1)
#endif /* roundup */


/*  0                   1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |            NLRI Type          |     Total NLRI Length         |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                                                               |
     //                  Link-State NLRI (variable)                 //
     |                                                               |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

struct te_tlv_nlri_header {
	u_int16_t nlri_type;   /* TE_BGP_TLV_XXX (see below) */
	u_int16_t nlri_length; /* Value portion only, in bytes */
};

struct route_distinguisher {
	struct te_tlv_nlri_header header;
	u_int32_t value; /*Value for Route distinguisher*/
};

/*
 ***********************************************************************************
 *				       MP_REACH_NLRI:14	 &
 *MP_UNREACH_NLRI:15		              *
 ***********************************************************************************
 */

/* Link-State NLRI types */

/*  +--------+---------------------------+
    | Type   | NLRI Type                 |
    +--------+---------------------------+
    |  0     | Reserved                  |
    |  1     | Node NLRI                 |
    |  2     | Link NLRI                 |
    |  3     | IPv4 Topology Prefix NLRI |
    |  4     | IPv6 Topology Prefix NLRI |
    |5-65535 | Unassigned                |
    +------+-----------------------------+
  */

#define LINK_STATE_NODE_NLRI                    1
/*
struct link_state_node_nlri
{
 struct te_tlv_nlri_header header;
};
*/
#define LINK_STATE_LINK_NLRI                    2
/*
struct link_state_link_nlri
{
struct te_tlv_nlri_header header;
};
*/
#define LINK_STATE_IPV4_TOPOLOGY_PREFIX_NLRI    3
/*
struct link_state_ipv4_nlri
{
struct te_tlv_nlri_header header;
};
*/
#define LINK_STATE_IPV6_TOPOLOGY_PREFIX_NLRI    4
/*
struct link_state_ipv6_nlri
{
struct te_tlv_nlri_header header;
};
*/

/* Link-State NLRI Protocol-ID values
  +-------------+----------------------------------+
  | Protocol-ID | NLRI information source protocol |
  +-------------+----------------------------------+
  |      0      | Reserved                         |
  |      1      | IS-IS Level 1                    |
  |      2      | IS-IS Level 2                    |
  |      3      | OSPFv2                           |
  |      4      | Direct                           |
  |      5      | Static configuration             |
  |      6      | OSPFv3                           |
  |  7-255      | Unassigned                       |
  +-------------+----------------------------------+
 */

#define BGP_LS_NLRI_PROTO_ID_UNKNOWN       0

#define BGP_LS_NLRI_PROTO_ID_IS_IS_LEVEL_1 1

#define BGP_LS_NLRI_PROTO_ID_IS_IS_LEVEL_2 2

#define BGP_LS_NLRI_PROTO_ID_OSPF          3

#define BGP_LS_NLRI_PROTO_ID_DIRECT        4

#define BGP_LS_NLRI_PROTO_ID_STATIC        5

#define BGP_LS_NLRI_PROTO_ID_OSPFv3        6

struct bgp_ls_nlri_extra_header {
	u_char proto_id;
	u_int64_t nlri_identifier;
};

struct tlv_code_point {
	struct te_tlv_nlri_header header;
};

/* Link-State routing universes */
#define BGP_LS_NLRI_ROUTING_UNIVERSE_LEVEL_3     0
#define BGP_LS_NLRI_ROUTING_UNIVERSE_LEVEL_1     1

/*
 * +-----------+---------------------+---------------+-----------------+
   |  TLV Code | Description         |   IS-IS TLV   | Value defined   |
   |   Point   |                     |    /Sub-TLV   | in:             |
   +-----------+---------------------+---------------+-----------------+
   |   0-255   | Reserved            |      22/4     |    xxxxxxxxxx   |
   |           |                     |               | | |    256    | Local
 node          |      22/6     |    xxxxxxxxxx   | |           | Descriptors |
 |                 | |    257    | Remote node         |      22/8     |
 xxxxxxxxxx   | |           | Descriptors         |               | |
 * +-----------+---------------------+---------------+-----------------+
 */
/* draft-ietf-idr-ls-distribution-10 */
#define BGP_NLRI_TLV_LOCAL_NODE_DESCRIPTORS         256

#define BGP_NLRI_TLV_REMOTE_NODE_DESCRIPTORS        257

#define BGP_NLRI_TLV_AUTONOMOUS_SYSTEM 512

#define BGP_NLRI_TLV_BGP_LS_IDENTIFIER 513

#define BGP_NLRI_TLV_AREA_ID 514

#define BGP_NLRI_TLV_IGP_ROUTER_ID 515

/* bgp_nlri_tlv_local_remote_node_descriptors */
struct bgp_nlri_tlv_lrnd {
	struct te_tlv_nlri_header header;
	void *value;
};


/*
 * +-----------+---------------------+---------------+-----------------+
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

 */
#define BGP_NLRI_TLV_LINK_LOCAL_REMOTE_IDENTIFIERS  258
/* bgp_nlri_tlv_link_local_remote_identifiers  */
struct bgp_nlri_tlv_llri {
	struct te_tlv_nlri_header header; /* Value length is 8 bytes. */
	u_int32_t local;		  /* Link Local Identifier */
	u_int32_t remote;		  /* Link Remote Identifier */
};

#define BGP_NLRI_TLV_IPV4_INTERFACE_ADDRESS         259
/* bgp_nlri_tlv_ipv4_interface_address */
struct bgp_nlri_tlv_i4i_addr {
	struct te_tlv_nlri_header header; /* Value length is 4 x N bytes. */
	struct in_addr value;		  /* Local IPv4 address(es). */
};

#define BGP_NLRI_TLV_IPV4_NEIGHBOR_ADDRESS          260
/* bgp_nlri_tlv_ipv4_neighbor_address */
struct bgp_nlri_tlv_i4n_addr {
	struct te_tlv_nlri_header header; /* Value length is 4 x N bytes. */
	struct in_addr value;		  /* Neighbor's IPv4 address(es). */
};

#define BGP_NLRI_TLV_IPV6_INTERFACE_ADDRESS         261
/* struct bgp_nlri_tlv_ipv6_interface_address */
struct bgp_nlri_tlv_i6i_addr {
	struct te_tlv_nlri_header header; /* Value length is 16 x N bytes. */
#ifdef HAVE_IPV6
	struct in6_addr value; /* Local IPv6 address(es). */
#endif			       /*HAVE_IPV6*/
};

#define BGP_NLRI_TLV_IPV6_NEIGHBOR_ADDRESS          262
/* bgp_nlri_tlv_ipv6_neighbor_address */
struct bgp_nlri_tlv_i6n_addr {
	struct te_tlv_nlri_header header; /* Value length is 16 x N bytes. */
#ifdef HAVE_IPV6
	struct in6_addr value; /* Neighbor's IPv6 address(es). */
#endif			       /*HAVE_IPV6*/
};

/*
 * +--------------+-----------------------+----------+-----------------+
   |   TLV Code   | Description           |  Length  | Value defined   |
   |    Point     |                       |          | in:             |
   +--------------+-----------------------+----------+-----------------+
   |     263      | Multi-Topology        | variable | Section 3.2.1.5 |
   |              | Identifier            |          |                 |
   |     264      | OSPF Route Type       |    1     | Section 3.2.3.1 |
   |     265      | IP Reachability       | variable | Section 3.2.3.2 |
   |              | Information           |          |                 |
   +--------------+-----------------------+----------+-----------------+
 */

#define BGP_NLRI_TLV_MULTI_TOPOLOGY_ID              263
/* bgp_nlri_tlv_multi_topology_id */
struct bgp_nlri_tlv_mt_id {
	struct te_tlv_nlri_header header; /* Value length is 2*n bytes. */
	u_int16_t *value; /* Multi Topology ID: only 12 bits => 0 ... 4096 */
};

#define BGP_NLRI_TLV_OSPF_ROUTE_TYPE                264
/* bgp_nlri_tlv_ospf_route_type */
struct bgp_nlri_tlv_ort {
	struct te_tlv_nlri_header header;
	u_char value; /* Value length is 1 byte */
} __attribute__((__packed__));

#define BGP_LS_PREFIX_OSPF_ROUTE_TYPE_UNKNOWN    0
#define BGP_LS_PREFIX_OSPF_ROUTE_TYPE_INTRA_AREA 1
#define BGP_LS_PREFIX_OSPF_ROUTE_TYPE_INTER_AREA 2
#define BGP_LS_PREFIX_OSPF_ROUTE_TYPE_EXTERNAL_1 3
#define BGP_LS_PREFIX_OSPF_ROUTE_TYPE_EXTERNAL_2 4
#define BGP_LS_PREFIX_OSPF_ROUTE_TYPE_NSSA_1     5
#define BGP_LS_PREFIX_OSPF_ROUTE_TYPE_NSSA_2     6

/*
 * Intra-Area (0x1)

 * Inter-Area (0x2)

 * External 1 (0x3)

 * External 2 (0x4)

 * NSSA 1 (0x5)

 * NSSA 2 (0x6)
 */

#define BGP_NLRI_TLV_IP_REACHABILITY_INFORMATION    265
/* bgp_nlri_tlv_ip_reachability */
struct bgp_nlri_tlv_ip_reach {
	struct te_tlv_nlri_header header;
	u_char prefix; /*lenght*/
	void *value;   /*�� revoir absolument */
} __attribute__((__packed__));

/*
	   +--------------------+-------------------+----------+
	   | Sub-TLV Code Point | Description       |   Length |
	   +--------------------+-------------------+----------+
	   |        512         | Autonomous System |        4 |
	   |        513         | BGP-LS Identifier |        4 |
	   |        514         | OSPF Area-ID      |        4 |
	   |        515         | IGP Router-ID     | Variable |
	   |        516-1023    | Unassigned        |          |
	   +--------------------+-------------------+----------+
*/


/*
 ***********************************************************************************
 *				                LINK_STATE:99
 **
 ***********************************************************************************
 */

/*
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
 */


#define BGP_NLRI_TLV_NODE_FLAG_BITS                 1024
/* struct bgp_nlri_tlv_node_flag_bits */
struct bgp_nlri_tlv_nfb {
	struct te_tlv_nlri_header header; /* Value length is 1 byte */
	u_char value; /* OTEB Reserve only 12 bits => 0 ...256*/
} __attribute__((__packed__));

#define BGP_NLRI_TLV_OPAQUE_NODE_PROPERTIES         1025
/* bgp_nlri_tlv_opaque_node_properties  */
struct bgp_nlri_tlv_onp {
	struct te_tlv_nlri_header header;
	void *value;
};

#define BGP_NLRI_TLV_NODE_NAME                      1026
/* bgp_nlri_tlv_node_name */
struct bgp_nlri_tlv_nn {
	struct te_tlv_nlri_header header;
	void *value;
};

#define BGP_NLRI_TLV_IS_IS_AREA_IDENTIFIER          1027
/* bgp_nlri_tlv_is_is_area_identifier */
struct bgp_nlri_tlv_iiai {
	struct te_tlv_nlri_header header;
	void *value;
};

/* +--------------+-----------------------+----------+-----------------+
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

 */

#define BGP_NLRI_TLV_IPV4_ROUTER_ID_OF_LOCAL_NODE   1028
/* bgp_nlri_tlv_ipv4_router_id_of_local_remote_node */
struct bgp_nlri_tlv_i4_rid_lrn {
	struct te_tlv_nlri_header header; /* Value length is 4 x N bytes. */
	struct in_addr value;		  /* Local IPv4 address(es). */
};

#define BGP_NLRI_TLV_IPV6_ROUTER_ID_OF_LOCAL_NODE   1029
/* bgp_nlri_tlv_ipv6_router_id_of_local_remote_node */
struct bgp_nlri_tlv_i6_rid_lrn {
	struct te_tlv_nlri_header header; /* Value length is 16 x N bytes. */
#ifdef HAVE_IPV6
	struct in6_addr value; /* Local IPv6 address(es). */
#endif			       /*HAVE_IPV6*/
};

/*
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
   | 1099-1151 | Unassigned          |     ---      |                  |
   +-----------+---------------------+--------------+------------------+
*/

#define BGP_NLRI_TLV_IPV4_ROUTER_ID_OF_REMOTE_NODE  1030
/*Same structure than 1028*/

#define BGP_NLRI_TLV_IPV6_ROUTER_ID_OF_REMOTE_NODE  1031
/*Same structure than 1029*/

#define BGP_NLRI_TLV_ADMINISTRATIVE_GROUP_COLOR     1088
/* bgp_nlri_tlv_administrative_group_color */
struct bgp_nlri_tlv_agc {
	struct te_tlv_nlri_header header; /* Value length is 4 bytes. */
	u_int32_t value;		  /* Admin. group membership. */
};

#define BGP_NLRI_TLV_MAX_LINK_BANDWIDTH             1089
/*bgp_nlri_tlv_max_link_bandwith */
struct bgp_nlri_tlv_max_link_bw {
	struct te_tlv_nlri_header header; /* Value length is 4 bytes. */
	float value;			  /* bytes/sec */
};

#define BGP_NLRI_TLV_MAX_RESERVABLE_LINK_BANDWIDTH  1090
/* bgp_nlri_tlv_max_reservable_link_bandwith  */
struct bgp_nlri_tlv_max_rsv_link_bw {
	struct te_tlv_nlri_header header; /* Value length is 4 bytes. */
	float value;			  /* bytes/sec */
};

#define BGP_NLRI_TLV_UNRESERVED_BANDWIDTH           1091
/* bgp_nlri_tlv_unreserved_bandwith  */
struct bgp_nlri_tlv_ursv_bw {
	struct te_tlv_nlri_header header; /* Value length is 32 bytes. */
	float value[8];			  /* One for each priority level. */
};

#define BGP_NLRI_TLV_TE_DEFAULT_METRIC              1092
/* bgp_nlri_tlv_te_default_metric  */
struct bgp_nlri_tlv_tdm {
	struct te_tlv_nlri_header header; /* Value length is 4 bytes. */
	u_int32_t value;		  /* Link metric for TE purpose. */
};

#define BGP_NLRI_TLV_LINK_PROTECTION_TYPE           1093
/* bgp_nlri_tlv_link_protection_type */
struct bgp_nlri_tlv_link_pt {
	struct te_tlv_nlri_header header; /* Value length is xxxx bytes. */
	u_int16_t value;		  /* Only 8 bits : 0.....256*/
};

#define BGP_NLRI_TLV_MPLS_PROTOCOL_MASK             1094
/* bgp_nlri_tlv_mpls_protocol_mask */
struct bgp_nlri_tlv_mpls_pm {
	struct te_tlv_nlri_header header; /* Value length is 2 bytes. */
	u_char value;			  /* Only 6 bits : 0.....64*/
} __attribute__((__packed__));

#define BGP_NLRI_TLV_IGP_METRIC                    1095
/* bgp_nlri_tlv_metric */
struct bgp_nlri_tlv_metric {
	struct te_tlv_nlri_header header; /* Value length is 4 bytes. */
	u_char *value;			  /* max 24 bits : 0.....64*/
} __attribute__((__packed__));

#define BGP_NLRI_TLV_SHARED_RISK_LINK_GROUP         1096
/* bgp_nlri_tlv_shared_risk_link_group */
struct bgp_nlri_tlv_srlg {
	struct te_tlv_nlri_header header; /* Value length is 2*n bytes. */
	u_int32_t *value;		  /* 4*n*/
};					  /* *Check * */

#define BGP_NLRI_TLV_OPAQUE_LINK_ATTRIBUTE          1097
/* bgp_nlri_tlv_opaque_link_attribute */
struct bgp_nlri_tlv_ola {
	struct te_tlv_nlri_header header; /* Value length is variable bytes. */
	void *value;
}; /*Check */

#define BGP_NLRI_TLV_LINK_NAME_ATTRIBUTE            1098
/* bgp_nlri_tlv_link_name_attribute */
struct bgp_nlri_tlv_lna {
	struct te_tlv_nlri_header header; /* Value length max is 255 bytes. */
	void *value;			  /*  2040 bits : 0.....64*/
};					  /*Check */

/*
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
   |   1158-65535  | Unassigned           | variable |                 |
   +---------------+----------------------+----------+-----------------+
*/

#define BGP_NLRI_TLV_IGP_FLAGS                      1152
/* bgp_nlri_tlv_igp_flags */
struct bgp_nlri_tlv_igp_flags {
	struct te_tlv_nlri_header header; /* Value length is 1 bytes. */
	u_char value;			  /*  Only 4 bits is used */
} __attribute__((__packed__));

#define BGP_NLRI_TLV_ROUTE_TAG                      1153
/* bgp_nlri_tlv_route_tag  */
struct bgp_nlri_tlv_route_tag {
	struct te_tlv_nlri_header header; /* Value length is 4*n bytes. */
	u_int32_t *value;		  /*  */
};

#define BGP_NLRI_TLV_EXTENDED_TAG                   1154
/* bgp_nlri_tlv_extended_tag */
struct bgp_nlri_tlv_extended_tag {
	struct te_tlv_nlri_header header; /* Value length is 8*n bytes. */
	u_int64_t *value;		  /*  */
};

#define BGP_NLRI_TLV_PREFIX_METRIC                  1155
/* bgp_nlri_tlv_prefix_metric */
struct bgp_nlri_tlv_prefix_metric {
	struct te_tlv_nlri_header header; /* Value length is 4 bytes. */
	u_int32_t value;
};

#define BGP_NLRI_TLV_OSPF_FORWARDING_ADDRESS        1156
/* bgp_nlri_tlv_ospf_fowarding_adress */
struct bgp_nlri_tlv_ospf_fowarding_adress {
	struct te_tlv_nlri_header header; /* Value length is 4 or 16 bytes. */
	union {
		struct in_addr addr4;
#ifdef HAVE_IPV6
		struct in6_addr addr6;
#endif		 /*HAVE_IPV6*/
	} value; /* IPV4 or IPV6 Prefix Metric*/
};

#define BGP_NLRI_TLV_OPAQUE_PREFIX_ATTRIBUTE        1157
/* bgp_nlri_tlv_opaque_prefix_attribute */
struct bgp_nlri_tlv_opa {
	struct te_tlv_nlri_header header; /* Value length is variable bytes. */
	void *value;			  /*  */
					  /** Check **/
};


/* Link-State NLRI TLV lengths */

#define BGP_NLRI_TLV_LEN_AUTONOMOUS_SYSTEM              4
#define BGP_NLRI_TLV_LEN_BGP_LS_IDENTIFIER              4
#define BGP_NLRI_TLV_LEN_AREA_ID                        4
#define BGP_NLRI_TLV_LEN_IPV4_ROUTER_ID                 4
#define BGP_NLRI_TLV_LEN_IPV6_ROUTER_ID                 16
#define BGP_NLRI_TLV_LEN_IPV4_ROUTER_ID_OF_LOCAL_NODE   BGP_NLRI_TLV_LEN_IPV4_ROUTER_ID
#define BGP_NLRI_TLV_LEN_IPV6_ROUTER_ID_OF_LOCAL_NODE   BGP_NLRI_TLV_LEN_IPV6_ROUTER_ID
#define BGP_NLRI_TLV_LEN_IPV4_ROUTER_ID_OF_REMOTE_NODE  BGP_NLRI_TLV_LEN_IPV4_ROUTER_ID
#define BGP_NLRI_TLV_LEN_IPV6_ROUTER_ID_OF_REMOTE_NODE  BGP_NLRI_TLV_LEN_IPV6_ROUTER_ID
#define BGP_NLRI_TLV_LEN_LINK_LOCAL_REMOTE_IDENTIFIERS  8
#define BGP_NLRI_TLV_LEN_IPV4_INTERFACE_ADDRESS         4
#define BGP_NLRI_TLV_LEN_IPV4_NEIGHBOR_ADDRESS          4
#define BGP_NLRI_TLV_LEN_IPV6_INTERFACE_ADDRESS         16
#define BGP_NLRI_TLV_LEN_IPV6_NEIGHBOR_ADDRESS          16
#define BGP_NLRI_TLV_LEN_MULTI_TOPOLOGY_ID              2
#define BGP_NLRI_TLV_LEN_OSPF_TYPE_ROUTE				1
#define BGP_NLRI_TLV_LEN_ADMINISTRATIVE_GROUP_COLOR     4
#define BGP_NLRI_TLV_LEN_MAX_LINK_BANDWIDTH             4
#define BGP_NLRI_TLV_LEN_MAX_RESERVABLE_LINK_BANDWIDTH  4
#define BGP_NLRI_TLV_LEN_UNRESERVED_BANDWIDTH           32
#define BGP_NLRI_TLV_LEN_TE_DEFAULT_METRIC              4 /* not 3 */
#define BGP_NLRI_TLV_LEN_LINK_PROTECTION_TYPE           2 /* 1 or 2 or 3 */
#define BGP_NLRI_TLV_LEN_MPLS_PROTOCOL_MASK             1
#define BGP_NLRI_TLV_LEN_METRIC                         3 /* prefer to  3 */
#define BGP_NLRI_TLV_LEN_IGP_FLAGS                      1
#define BGP_NLRI_TLV_LEN_PREFIX_METRIC                  4
#define BGP_NLRI_TLV_LEN_AREA_ID                        4
#define BGP_NLRI_TLV_LEN_NODE_FLAG_BITS                 1
#define BGP_NLRI_TLV_LEN_IPV4_FOWARDING_ADDRESS			4
#define BGP_NLRI_TLV_LEN_IPV6_FOWARDING_ADDRESS			16

#define BGP_NLRI_IS_IS_NON_PSEUDONODE                   6
#define BGP_NLRI_IS_IS_PSEUDONODE                       7
#define BGP_NLRI_OSPF_NON_PSEUDONODE                    4
#define BGP_NLRI_OSPF_PSEUDONODE                        8

/* Following declaration concerns the LS-TE and LINk-TE information */

/**Prototype Fonction de parsing des attributs */

/* BGP LS MP_[UN]REACH_NLRI prefix attributes */
struct mp_bgpls_nlri {

	struct te_tlv_nlri_header header;
	/**************************************************************/
	/*struct route_distinguisher rd;*/ /*Prefix RD*/
	struct prefix_rd prd;
	/**************************************************************/
	/*
	struct link_state_node_nlri node_nlri;
	struct link_state_link_nlri link_nlri;
	struct link_state_ipv4_nlri ipv4_nlri;
	struct link_state_ipv6_nlri ipv6_nlri;
	*/
	/***********************************************************/
	struct bgp_ls_nlri_extra_header ext_hdr;
	struct tlv_code_point tlvcp;
	/*************************************************************/

	struct bgp_nlri_tlv_lrnd *local_node;
	struct bgp_nlri_tlv_lrnd *remote_node;
	struct bgp_nlri_tlv_llri llri;
	struct bgp_nlri_tlv_i4i_addr i4ia;
	struct bgp_nlri_tlv_i4n_addr i4na;
	struct bgp_nlri_tlv_i6i_addr i6ia;
	struct bgp_nlri_tlv_i6n_addr i6na;
	struct bgp_nlri_tlv_mt_id *mid;
	struct bgp_nlri_tlv_ort ort;
	struct bgp_nlri_tlv_ip_reach *ipreach;
	/*************************************************************/
};

/* BGP LS LINK_STATE prefix attributes */
struct ls_bgpls {
	struct te_tlv_nlri_header header;

	/*************************************************************/
	struct bgp_nlri_tlv_mt_id *mid;
	struct bgp_nlri_tlv_nfb nfb;
	struct bgp_nlri_tlv_onp *onp;
	struct bgp_nlri_tlv_nn *nn;
	struct bgp_nlri_tlv_iiai *iiai;

	/*************************************************************/
	struct bgp_nlri_tlv_i4_rid_lrn i4ridofln;
	struct bgp_nlri_tlv_i6_rid_lrn i6ridofln;
	struct bgp_nlri_tlv_i4_rid_lrn i4ridofrn;
	struct bgp_nlri_tlv_i6_rid_lrn i6ridofrn;
	struct bgp_nlri_tlv_agc agc;
	struct bgp_nlri_tlv_max_link_bw mlb;
	struct bgp_nlri_tlv_max_rsv_link_bw mrlb;
	struct bgp_nlri_tlv_ursv_bw urb;
	struct bgp_nlri_tlv_tdm tdm;
	struct bgp_nlri_tlv_link_pt lpt;
	struct bgp_nlri_tlv_mpls_pm mpm;
	struct bgp_nlri_tlv_metric *igpm;
	struct bgp_nlri_tlv_srlg *srlg;
	struct bgp_nlri_tlv_ola *ola;
	struct bgp_nlri_tlv_lna *lna;
	/************************************************************/
	struct bgp_nlri_tlv_igp_flags ifl;
	struct bgp_nlri_tlv_route_tag *rt;
	struct bgp_nlri_tlv_extended_tag *et;
	struct bgp_nlri_tlv_prefix_metric pm;
	struct bgp_nlri_tlv_ospf_fowarding_adress ofa;
	struct bgp_nlri_tlv_opa *opa;
};

extern void bgp_link_state_init(void);
extern void bgp_mp_reach_init(void);
extern void htonft(float *src, float *dst);
extern void ntohft(float *src, float *dst);

/*For files bgp_mpreach_nlri.c & bgp_ls_bgpls.c*/
extern int bgp_mp_node_decode(struct bgp_attr_parser_args *args,
			      struct stream *s);
extern int bgp_mp_link_decode(struct bgp_attr_parser_args *args,
			      struct stream *s);
extern int bgp_mp_prefix_decode(struct bgp_attr_parser_args *args,
				struct stream *s);
extern int bgp_link_state_decode(struct bgp_attr_parser_args *args,
				 struct stream *s);
extern int show_bgp_linkstate_print_detail(struct vty *vty,
					   struct ls_bgpls *te);
extern int show_bgp_mpreach_print_detail(struct vty *vty,
					 struct mp_bgpls_nlri *te);

#endif /*_ZEBRA_BGP_LS_TE_H*/
