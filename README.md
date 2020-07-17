# Quagga-BGP-LS

BGP Link State Extension for Quagga

## Disclaimer

This code is published ***AS IS*** more as a proof of concept rather
than a running code.

It is based on a old version of Quagga. I don't know if it compiles, if it runs ...
As the code was unfortunately not versioned, I try to patch what seems
the Quagga version from which the code was based to produce the git commit.
But, I have not the time to check if the result compiles and if it is running.
**And, please, don't ask me for that**

## Target

The goal is to published some code in order to ease the backport to FR-Routing
https://github.com/FRRouting/frr

As an old code, it is using old style. So, only new files are following FRR style.

The implementation is made of new files:

 - BGP-LS TLV definition: bgpd/bgp_ls.h
 - New Link State NLRI: bgpd/bgp_bgpls_nlri.c
 - Parser/Serializer: bgpd/bgp_ls_bgpls.c
 - BGP-LS Database: bgpd/bgp_lsdb.[c,h]
 - BGP API for OSPF-API: bgpd/bgp_api.[c,h], bgpd/bgp_ls_ospf.h
 - BGP Link State transcodage: bgpd/bgp_transcode.c
 - BGP to OSPF-API connection: bgpd/bgp_zbusclient.[c,h]

At least the NLRI, TLV definition, parser / serializer and LSDB could be
re-use easily. Of course all interaction with OSPF through OSPF API must
be replaced by the new ZAPI Opaque message.

And following files have been patched for integration:

 - bgpd/bgp_advertise.c, bgpd/bgp_aspath.c,
   bgpd/bgp_attr.|c,h], bgpd/bgp_btoa.c, bgpd/bgp_clist.c,
   bgpd/bgp_community.[c,h], bgpd/bgp_dump.c, bgpd/bgp_fsm.c, bgpd/bgp_main.c,
   bgpd/bgp_mplsvpn.c, bgpd/bgp_nexthop.c, bgpd/bgp_open.c, bgpd/bgp_packet.c,
   bgpd/bgp_route.c, bgpd/bgp_routemap.c, bgpd/bgp_table.c, bgpd/bgp_vty.c,
   bgpd/bgp_zebra.c, bgpd/bgpd.c, bgpd/bgpd.h

Where takes place the huge part of difficulties in order to merge them into FRR.

