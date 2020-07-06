/* BGP routing table
   Copyright (C) 1998, 2001 Kunihiro Ishiguro

This file is part of GNU Zebra.

GNU Zebra is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 2, or (at your option) any
later version.

GNU Zebra is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
General Public License for more details.

You should have received a copy of the GNU General Public License
along with GNU Zebra; see the file COPYING.  If not, write to the Free
Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
02111-1307, USA.  */

#include <zebra.h>
#include <math.h>

#include "linklist.h"
#include "thread.h"
#include "vty.h"
#include "stream.h"
#include "memory.h"
#include "log.h"
#include "prefix.h"
#include "command.h"
#include "hash.h"
#include "if.h"
#include "checksum.h"
#include "md5.h"
#include "sockunion.h"

/*
#include "isisd/isis_circuit.h"
#include "isisd/isisd.h"
#include "isisd/isis_tlv.h"
#include "isisd/isis_te.h"
#include "ospfd/ospfd.h"
#include "ospfd/ospf_lsa.h"
#include "ospfd/ospf_zebra.h"
#include "ospfd/ospf_te.h"
*/

#include "bgpd/bgpd.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_aspath.h"
#include "bgpd/bgp_community.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_packet.h"
#include "bgpd/bgp_ecommunity.h"
#include "bgpd/bgp_lsdb.h"
//#ifdef HAVE_BGP_LS_TE
#include "bgpd/bgp_ls.h"
//#endif /*  HAVE_BGP_LS_TE  */

/*
* if attributs are OSPF LSA: flag = 1
* if attributs are ISIS LSP: flag = 2
*/

#define OSPF_FLAG 1
#define ISIS_FLAG 2

        /*
	***********************************************************************************
	*				       MP_REACH_NLRI:14	 & 	MP_UNREACH_NLRI:15	TRANSCODE	              *
	***********************************************************************************
	*/



struct attr *bgp_ls_transcode (struct tlvs *isis_tlv ,struct mpls_te_circuit *isis_te ,struct mpls_te_link *ospf_te, struct ospf_lsa *ospf_tlv) {

	struct attr *attr;
	attr->origin = BGP_ORIGIN_IGP;
	attr->aspath = 0 ;
	attr->local_pref=BGP_DEFAULT_LOCAL_PREF;

	/* Make MP_[UN]REACH_NLRI Attribute */

	attr->mp_bgpls_nlri->ext_hdr.proto_id=0;
	attr->mp_bgpls_nlri->ext_hdr.nlri_identifier=0x000000000;

	attr->mp_bgpls_nlri->local_node=NULL;
	attr->mp_bgpls_nlri->remote_node=NULL;
	attr->mp_bgpls_nlri->llri=trans_tlv_llri(isis_te->llri,ospf_te->llri,OSPF_FLAG);

	attr->mp_bgpls_nlri->i4ia=trans_tlv_i4i_addr(isis_te->local_ipaddr,ospf_te->lclif_ipaddr,OSPF_FLAG);
	attr->mp_bgpls_nlri->i4na=trans_tlv_i4n_addr(isis_te->rmt_ipaddr,ospf_te->rmtif_ipaddr,OSPF_FLAG);
	attr->mp_bgpls_nlri->i6ia=trans_tlv_i6i_addr();
	attr->mp_bgpls_nlri->i6na=trans_tlv_i6n_addr();
	attr->mp_bgpls_nlri->mid=NULL;
	attr->mp_bgpls_nlri->ort=trans_tlv_ort(NULL,ospf_te->type,OSPF_FLAG);
    attr->mp_bgpls_nlri->ipreach=NULL;

    /* Make LINK_STATE Attribute */

    attr->link_state_attr->mid=NULL;
    attr->link_state_attr->nfb=NULL;
    attr->link_state_attr->onp=NULL;
    attr->link_state_attr->nn=NULL;
    attr->link_state_attr->iiai=NULL;

    attr->link_state_attr->i4ridofln=trans_tlv_i4ridln(isis_te->local_ipaddr,ospf_te->lclif_ipaddr,OSPF_FLAG);
    attr->link_state_attr->i6ridofln=NULL;
    attr->link_state_attr->i4ridofrn=trans_tlv_i4ridrn(isis_te->rmt_ipaddr,ospf_te->rmtif_ipaddr,OSPF_FLAG);
    attr->link_state_attr->i6ridofrn=NULL;

    attr->link_state_attr->agc=trans_tlv_agc(isis_te->admin_grp,NULL,OSPF_FLAG);
    attr->link_state_attr->mlb=trans_tlv_max_link_bw(isis_te->max_bw,ospf_te->max_bw,OSPF_FLAG);
    attr->link_state_attr->mrlb=trans_tlv_max_rsv_link_bw(isis_te->max_rsv_bw,ospf_te->max_rsv_bw,OSPF_FLAG) ;
    attr->link_state_attr->urb=trans_tlv_max_unrsv_link_bw(isis_te->unrsv_bw,ospf_te->unrsv_bw,OSPF_FLAG);
    attr->link_state_attr->tdm=trans_tlv_tdm(isis_te->te_metric,ospf_te->te_metric);
    attr->link_state_attr->lpt=NULL;
    attr->link_state_attr->mpm=NULL;
    attr->link_state_attr->igpm=trans_tlv_igp_metric(isis_te->te_metric,ospf_te->te_metric);
    attr->link_state_attr->srlg=trans_tlv_srlg();
    attr->link_state_attr->ola=NULL;
    attr->link_state_attr->lna=NULL;

    attr->link_state_attr->ifl=NULL;
    attr->link_state_attr->rt=NULL;
    attr->link_state_attr->et=NULL;
    attr->link_state_attr->pm=NULL;
    attr->link_state_attr->ofa=NULL;
    attr->link_state_attr->opa=NULL;

	return attr;
}
