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

#include "stream.h"
#include "if.h"

/* OSPF LSA Range definition. */
#define OSPF_MIN_LSA		1  /* begin range here */
#if defined(HAVE_OPAQUE_LSA)
#define OSPF_MAX_LSA        12
#else
#define OSPF_MAX_LSA		8
#endif

#define MAX_CLASS_TYPE      8 //to be resolved if.h HAVE_OSPF_TE ISIS_TE

/* OSPF LSA Type definition. */
#define OSPF_UNKNOWN_LSA	          0
#define OSPF_ROUTER_LSA               1
#define OSPF_NETWORK_LSA              2
#define OSPF_SUMMARY_LSA              3
#define OSPF_ASBR_SUMMARY_LSA         4
#define OSPF_AS_EXTERNAL_LSA          5
#define OSPF_GROUP_MEMBER_LSA	      6  /* Not supported. */
#define OSPF_AS_NSSA_LSA	          7
#define OSPF_EXTERNAL_ATTRIBUTES_LSA  8  /* Not supported. */
#define OSPF_OPAQUE_LINK_LSA	      9
#define OSPF_OPAQUE_AREA_LSA	     10
#define OSPF_OPAQUE_AS_LSA	         11

#define OSPF_LSA_HEADER_SIZE	     20U
#define OSPF_ROUTER_LSA_LINK_SIZE    12U
#define OSPF_ROUTER_LSA_TOS_SIZE      4U
#define OSPF_MAX_LSA_SIZE	       1500U

/* AS-external-LSA refresh method. */
#define LSA_REFRESH_IF_CHANGED	0
#define LSA_REFRESH_FORCE	1
