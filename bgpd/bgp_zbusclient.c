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
#include "thread.h"
#include "buffer.h"
#include "stream.h"
#include "command.h"
#include "sockunion.h"
#include "network.h"
#include "memory.h"
#include "filter.h"
#include "routemap.h"
#include "str.h"
#include "log.h"
#include "plist.h"
#include "linklist.h"
#include "memtypes.h"
#include "workqueue.h"
#include "privs.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_table.h"
#include "bgpd/bgp_aspath.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_dump.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_community.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_regex.h"
#include "bgpd/bgp_clist.h"
#include "bgpd/bgp_fsm.h"
#include "bgpd/bgp_packet.h"
#include "bgpd/bgp_zebra.h"
#include "bgpd/bgp_open.h"
#include "bgpd/bgp_filter.h"
#include "bgpd/bgp_nexthop.h"
#include "bgpd/bgp_damp.h"
#include "bgpd/bgp_mplsvpn.h"
#include "bgpd/bgp_advertise.h"
#include "bgpd/bgp_network.h"
#include "bgpd/bgp_vty.h"
#include "bgpd/bgp_api.h"
#include "bgpd/bgp_zbusclient.h"
#include "bgpd/bgp_ls_ospf.h"
#ifdef HAVE_SNMP
#include "bgpd/bgp_snmp.h"
#endif /* HAVE_SNMP */

/*
struct zebra_privs_t *bgpd_privs = NULL;
struct thread_master *master = NULL;


struct bgp_apiclient *oclient;
char **args;
*/
/* ----- wrong usage ----- */
void usage(struct vty *vty)
{
	vty_out(vty, "usage: X Y seed [-ll#i -lm#i -cl#i -p -pl#i -pm#i ...]%s",
		VTY_NEWLINE);
	vty_out(vty, "help: -h or -hh%s", VTY_NEWLINE);

	int np; /* number of parameter parsing now */

	if (np > 0)
		zlog_err("error in parameter # %d\n\n", np);
}

/* Our opaque LSAs have the following format. */
struct my_opaque_lsa {
	struct lsa_header hdr; /* include common LSA header */
	u_char data[4];	/* our own data format then follows here */
};

/*
struct zebra_privs_t bgpd_privs =
{
  .user = NULL,
  .group = NULL,
  .cap_num_p = 0,
  .cap_num_i = 0
};
*/

/* The following includes are specific to this application. For
   example it uses threads from lib zebra, however your application is
   free to use any thread library (like threads). */

#include "bgpd/bgp_dump.h" /* for ospf_lsa_header_dump */
#include "thread.h"
#include "log.h"

/* -----------------------------------------------------------
 * Initialization
 * -----------------------------------------------------------
 */

static unsigned short bgp_apiclient_getport(void)
{
	struct servent *sp = getservbyname("bgpapi", "tcp");

	return sp ? ntohs(sp->s_port) : OSPF_API_SYNC_PORT;
}

/* -----------------------------------------------------------
 * Followings are functions for connection management
 * -----------------------------------------------------------
 */

struct bgp_apiclient *bgp_apiclient_connect(char *host, int syncport)
{
	struct sockaddr_in myaddr_sync;
	struct sockaddr_in myaddr_async;
	struct sockaddr_in peeraddr;
	struct hostent *hp;
	struct bgp_apiclient *new;
	int size = 0;
	unsigned int peeraddrlen;
	int async_server_sock;
	int fd1, fd2;
	int ret;
	int on = 1;

	/* There are two connections between the client and the server.
	   First the client opens a connection for synchronous requests/replies
	   to the server. The server will accept this connection and
	   as a reaction open a reverse connection channel for
	   asynchronous messages. */

	async_server_sock = socket(AF_INET, SOCK_STREAM, 0);
	if (async_server_sock < 0) {
		fprintf(stderr,
			"bgp_apiclient_connect: creating async socket failed\n");
		return NULL;
	}

	/* Prepare socket for asynchronous messages */
	/* Initialize async address structure */
	memset(&myaddr_async, 0, sizeof(struct sockaddr_in));
	myaddr_async.sin_family = AF_INET;
	myaddr_async.sin_addr.s_addr = htonl(INADDR_ANY);
	myaddr_async.sin_port = htons(syncport + 1);
	size = sizeof(struct sockaddr_in);
#ifdef HAVE_STRUCT_SOCKADDR_IN_SIN_LEN
	myaddr_async.sin_len = size;
#endif /* HAVE_STRUCT_SOCKADDR_IN_SIN_LEN */

	/* This is a server socket, reuse addr and port */
	ret = setsockopt(async_server_sock, SOL_SOCKET, SO_REUSEADDR,
			 (void *)&on, sizeof(on));
	if (ret < 0) {
		fprintf(stderr, "bgp_apiclient_connect: SO_REUSEADDR failed\n");
		close(async_server_sock);
		return NULL;
	}

#ifdef SO_REUSEPORT
	ret = setsockopt(async_server_sock, SOL_SOCKET, SO_REUSEPORT,
			 (void *)&on, sizeof(on));
	if (ret < 0) {
		fprintf(stderr, "bgp_apiclient_connect: SO_REUSEPORT failed\n");
		close(async_server_sock);
		return NULL;
	}
#endif /* SO_REUSEPORT */

	/* Bind socket to address structure */
	ret = bind(async_server_sock, (struct sockaddr *)&myaddr_async, size);
	if (ret < 0) {
		fprintf(stderr,
			"bgp_apiclient_connect: bind async socket failed\n");
		close(async_server_sock);
		return NULL;
	}

	/* Wait for reverse channel connection establishment from server */
	ret = listen(async_server_sock, BACKLOG);
	if (ret < 0) {
		fprintf(stderr, "bgp_apiclient_connect: listen: %s\n",
			safe_strerror(errno));
		close(async_server_sock);
		return NULL;
	}

	/* Make connection for synchronous requests and connect to server */
	/* Resolve address of server */
	hp = gethostbyname(host);
	if (!hp) {
		fprintf(stderr, "bgp_apiclient_connect: no such host %s\n",
			host);
		close(async_server_sock);
		return NULL;
	}

	fd1 = socket(AF_INET, SOCK_STREAM, 0);
	if (fd1 < 0) {
		fprintf(stderr,
			"bgp_apiclient_connect: creating sync socket failed\n");
		return NULL;
	}


	/* Reuse addr and port */
	ret = setsockopt(fd1, SOL_SOCKET, SO_REUSEADDR, (void *)&on,
			 sizeof(on));
	if (ret < 0) {
		fprintf(stderr, "bgp_apiclient_connect: SO_REUSEADDR failed\n");
		close(fd1);
		return NULL;
	}

#ifdef SO_REUSEPORT
	ret = setsockopt(fd1, SOL_SOCKET, SO_REUSEPORT, (void *)&on,
			 sizeof(on));
	if (ret < 0) {
		fprintf(stderr, "bgp_apiclient_connect: SO_REUSEPORT failed\n");
		close(fd1);
		return NULL;
	}
#endif /* SO_REUSEPORT */


	/* Bind sync socket to address structure. This is needed since we
	   want the sync port number on a fixed port number. The reverse
	   async channel will be at this port+1 */

	memset(&myaddr_sync, 0, sizeof(struct sockaddr_in));
	myaddr_sync.sin_family = AF_INET;
	myaddr_sync.sin_port = htons(syncport);
#ifdef HAVE_STRUCT_SOCKADDR_IN_SIN_LEN
	myaddr_sync.sin_len = sizeof(struct sockaddr_in);
#endif /* HAVE_STRUCT_SOCKADDR_IN_SIN_LEN */

	ret = bind(fd1, (struct sockaddr *)&myaddr_sync, size);
	if (ret < 0) {
		fprintf(stderr,
			"bgp_apiclient_connect: bind sync socket failed\n");
		close(fd1);
		return NULL;
	}

	/* Prepare address structure for connect */
	memcpy(&myaddr_sync.sin_addr, hp->h_addr,
	       hp->h_length); // h_addr by h_addrtype
	myaddr_sync.sin_family = AF_INET;
	myaddr_sync.sin_port = htons(bgp_apiclient_getport());
#ifdef HAVE_STRUCT_SOCKADDR_IN_SIN_LEN
	myaddr_sync.sin_len = sizeof(struct sockaddr_in);
#endif /* HAVE_STRUCT_SOCKADDR_IN_SIN_LEN */

	/* Now establish synchronous channel with OSPF daemon */
	ret = connect(fd1, (struct sockaddr *)&myaddr_sync,
		      sizeof(struct sockaddr_in));
	if (ret < 0) {
		fprintf(stderr, "bgp_apiclient_connect: sync connect failed\n");
		close(async_server_sock);
		close(fd1);
		return NULL;
	}

	/* Accept reverse connection */
	peeraddrlen = sizeof(struct sockaddr_in);
	memset(&peeraddr, 0, peeraddrlen);

	fd2 = accept(async_server_sock, (struct sockaddr *)&peeraddr,
		     &peeraddrlen);
	if (fd2 < 0) {
		fprintf(stderr, "bgp_apiclient_connect: accept async failed\n");
		close(async_server_sock);
		close(fd1);
		return NULL;
	}

	/* Server socket is not needed anymore since we are not accepting more
	   connections */
	close(async_server_sock);

	/* Create new client-side instance */
	new = XCALLOC(MTYPE_BGP_APICLIENT, sizeof(struct bgp_apiclient));

	/* Initialize socket descriptors for sync and async channels */
	new->fd_sync = fd1;
	new->fd_async = fd2;
	fprintf(stderr, "bgp_apiclient_connect: connection successful\n");
	return new;
}
/* -----------------------------------------------------------
 * Followings are functions to send a request to OSPFd
 * -----------------------------------------------------------
 */

/* Send synchronous request, wait for reply */
static int bgp_apiclient_send_request(struct bgp_apiclient *oclient,
				      struct msg *msg)
{
	u_int32_t reqseq;
	struct msg_reply *msgreply;
	int rc;

	/* NB: Given "msg" is freed inside this function. */

	/* Remember the sequence number of the request */
	reqseq = ntohl(msg->hdr.msgseq);

	/* Write message to OSPFd */
	rc = msg_write(oclient->fd_sync, msg);
	msg_free(msg);

	if (rc < 0) {
		return -1;
	}

	/* Wait for reply */ /* NB: New "msg" is allocated by "msg_read()". */
	msg = msg_read(oclient->fd_sync);
	if (!msg)
		return -1;

	assert(msg->hdr.msgtype == MSG_REPLY);
	assert(ntohl(msg->hdr.msgseq) == reqseq);

	msgreply = (struct msg_reply *)STREAM_DATA(msg->s);
	rc = msgreply->errcode;
	msg_free(msg);

	return rc;
}

/*
 * Synchronous request to synchronize with OSPF's LSDB.
 * Two steps required: register_event in order to get
 * dynamic updates and LSDB_Sync.
 */
int bgp_apiclient_sync_lsdb(struct bgp_apiclient *oclient)
{
	struct msg *msg;
	int rc;
	struct lsa_filter_type filter;

	filter.typemask = 0xFFFF; /* all LSAs */
	filter.origin = ANY_ORIGIN;
	filter.num_areas = 0; /* all Areas. */

	msg = new_msg_register_event(bgp_apiclient_get_seqnr(), &filter);
	if (!msg) {
		fprintf(stderr, "new_msg_register_event failed\n");
		return -1;
	}
	rc = bgp_apiclient_send_request(oclient, msg);

	if (rc != 0)
		goto out;

	msg = new_msg_sync_lsdb(bgp_apiclient_get_seqnr(), &filter);

	if (!msg) {
		fprintf(stderr, "new_msg_sync_lsdb failed\n");
		return -1;
	}
	rc = bgp_apiclient_send_request(oclient, msg);

out:
	return rc;
}

/* -----------------------------------------------------------
 * Helper functions
 * -----------------------------------------------------------
 */

// static
u_int32_t bgp_apiclient_get_seqnr(void)
{
	static u_int32_t seqnr = MIN_SEQ;
	u_int32_t tmp;

	tmp = seqnr;

	/* Increment sequence number */
	if (seqnr < MAX_SEQ) {
		seqnr++;
	} else {
		seqnr = MIN_SEQ;
	}
	return tmp;
}

/* -----------------------------------------------------------
 * API to access OSPF daemon by client applications.
 * -----------------------------------------------------------
 */

static void bgp_apiclient_handle_lsa_update(struct bgp_apiclient *oclient,
					    struct msg *msg)
{
	struct msg_lsa_change_notify *cn;
	struct lsa_header *lsa;
	// struct ospf_lsa *lsas;
	int lsalen;

	printf("bgp_apiclient: handle new LSA update\n");
	cn = (struct msg_lsa_change_notify *)STREAM_DATA(msg->s);

	/* Extract LSA from message */
	lsalen = ntohs(cn->data.length);

	printf("bgp_apiclient: handle new LSA update of size %d\n", lsalen);

	lsa = XMALLOC(MTYPE_BGP_APICLIENT, lsalen);
	// lsa= cn->data;
	if (!lsa) {
		fprintf(stderr, "LSA update: Cannot allocate memory for LSA\n");
		return;
	}


	memcpy(lsa, &(cn->data), lsalen);

	printf("bgp_apiclient: handle new LSA Type %d \n", lsa->type);
	u_char oid;
	oid = GET_OPAQUE_ID(ntohl(lsa->id.s_addr));
	printf("bgp_apiclient: handle oid %d \n", oid);
	struct bgp *bgp;
	struct peer *peer = NULL;
	struct listnode *node, *nnode;
	struct listnode *mnode, *mnnode;

	struct peer *from;
	struct attr *attr;

	for (ALL_LIST_ELEMENTS(bm->bgp, mnode, mnnode, bgp))
		for (ALL_LIST_ELEMENTS(bgp->peer, node, nnode, peer))
			if (peer->status == Established) {
				from = bgp->peer_self;
				// if(peer->bgp->aggregate->afi==AFI_LINK_STATE
				// &&
				// peer->bgp->aggregate->safi==SAFI_LINK_STATE)
				// {

				switch (lsa->type) {
				case OSPF_ROUTER_LSA:
				case OSPF_NETWORK_LSA:
				case OSPF_SUMMARY_LSA:
				case OSPF_ASBR_SUMMARY_LSA:
				case OSPF_GROUP_MEMBER_LSA:
				case OSPF_AS_NSSA_LSA:
				case OSPF_EXTERNAL_ATTRIBUTES_LSA:
				case OSPF_OPAQUE_LINK_LSA:


					switch (oid) {
					case OPAQUE_TYPE_TRAFFIC_ENGINEERING_LSA:
						// bgp_ls_translate_ospf_link(msg,
						// (struct network_lsa *)lsa);

						attr = bgp_ls_transcode(
							NULL, NULL, NULL, lsa);
						break;
					default:
						break;
					}
					break;

				case OSPF_OPAQUE_AREA_LSA:
					oid = GET_OPAQUE_ID(
						ntohl(lsa->id.s_addr));
					switch (oid) {
					case OPAQUE_TYPE_TRAFFIC_ENGINEERING_LSA:

						attr = bgp_ls_transcode(
							NULL, NULL, NULL, lsa);
						break;
					default:
						break;
					}
					attr = bgp_ls_transcode(NULL, NULL,
								NULL, lsa);

					break;

				case OSPF_OPAQUE_AS_LSA:
					oid = GET_OPAQUE_ID(
						ntohl(lsa->id.s_addr));
					switch (oid) {
					case OPAQUE_TYPE_TRAFFIC_ENGINEERING_LSA:

						attr = bgp_ls_transcode(
							NULL, NULL, NULL, lsa);
						break;
					default:
						break;
					}
					break;

				default:
					printf("bgp_apiclient: handle new LSA update C\n");
					break;
					printf("bgp_apiclient: handle new LSA update D\n");
				}

				// attr= bgp_ls_transcode(NULL,NULL,NULL,lsa);
				//  bgp_write(bm->master->write.head);
				bgp_default_update_send(peer, attr,
							AFI_LINK_STATE,
							SAFI_LINK_STATE, from);
				//   }
				/**         Saves attribute in LSDB      **/

				struct bgp *bgp;
				struct bgp_lsdb *bgp_lsdb;
				struct bgp_ls *ls;

				bgp = bgp_get_default();
				bgp_lsdb = bgp->lsdb;
				ls = ls_attr_set(attr);

				if (bgp_lsdb) {
					bgp_lsdb_free(bgp_lsdb);
					bgp_lsdb = bgp_lsdb_new();
					bgp_lsdb_add(bgp_lsdb, ls);
				} else {
					bgp_lsdb = bgp_lsdb_new();
					bgp_lsdb_add(bgp_lsdb, ls);
				}
			}
	/*
	   bgp->rib[AFI_LINK_STATE][SAFI_LINK_STATE]=bgp_table_init(AFI_LINK_STATE,SAFI_LINK_STATE);
	   peer = bgp->aggregate[AFI_LINK_STATE][SAFI_LINK_STATE]->owner;
	   from = NULL;
	    peer->local_id=cn->area_id;
	    from->local_id = peer->remote_id;
	*/

	/* free memory allocated by ospf apiclient library */
	XFREE(MTYPE_BGP_APICLIENT, lsa);
}

static void bgp_apiclient_msghandle(struct bgp_apiclient *oclient,
				    struct msg *msg)
{
	/* Call message handler function. */

	if (msg->hdr.msgtype == MSG_LSA_UPDATE_NOTIFY)

		bgp_apiclient_handle_lsa_update(oclient, msg);

	else
		fprintf(stderr,
			"bgp_apiclient_read: Unknown message type: %d\n",
			msg->hdr.msgtype);
}

/* -----------------------------------------------------------
 * Asynchronous message handling
 * -----------------------------------------------------------
 */

int bgp_apiclient_handle_async(struct bgp_apiclient *oclient)
{
	struct msg *msg;

	/* Get a message */
	msg = msg_read(oclient->fd_async);

	if (!msg) {
		/* Connection broke down */
		return -1;
	}

	/* Handle message */
	bgp_apiclient_msghandle(oclient, msg);

	/* Don't forget to free this message */
	msg_free(msg);

	return 0;
}


/* This thread handles asynchronous messages coming in from the OSPF
   API server */
// static
int lsa_read(struct thread *thread)
{
	struct bgp_apiclient *oclient;
	int fd;
	int ret;

	printf("lsa_read called\n");

	oclient = THREAD_ARG(thread);
	fd = THREAD_FD(thread);

	/* Handle asynchronous message */
	ret = bgp_apiclient_handle_async(oclient);
	if (ret < 0) {
		printf("Connection closed, exiting...");
		exit(0);
	}

	/* Reschedule read thread */
	thread_add_read(master, lsa_read, oclient, fd);

	return 0;
}


void bgp_zbus_init(struct thread_master *master_thread,
		   struct zebra_privs_t *zprivs)
{ // int argc, char *argv[]

	// args = argv;
	struct zebra_privs_t *bgpd_privs;
	bgpd_privs = &zprivs;
	/* ospfclient should be started with the following arguments:
	 *
	 * (1) host (2) lsa_type (3) opaque_type (4) opaque_id (5) if_addr
	 * (6) area_id
	 *
	 * host: name or IP of host where ospfd is running
	 * lsa_type: 9, 10, or 11
	 * opaque_type: 0-255 (e.g., experimental applications use > 128)
	 * opaque_id: arbitrary application instance (24 bits)
	 * if_addr: interface IP address (for type 9) otherwise ignored
	 * area_id: area in IP address format (for type 10) otherwise ignored
	 */

	/* Initialization */
	// zprivs_init (&bgpd_privs);
	// master = thread_master_create ();
	master = master_thread;

	struct bgp_apiclient *oclient;

	/* Open connection to OSPF daemon */
	printf("Try to connect to OSPF API daemon\n");
	oclient = bgp_apiclient_connect("localhost", ASYNCPORT);

	if (!oclient) {
		printf("Connecting to OSPF daemon on localhost failed!\n");
		exit(1);
	}

	/* Synchronize database with BGP daemon. */
	printf("Request LSDB sync to OSPF API daemon\n");
	bgp_apiclient_sync_lsdb(oclient);

	/* Schedule thread that handles asynchronous messages */
	thread_add_read(master, lsa_read, oclient, oclient->fd_async);
}
