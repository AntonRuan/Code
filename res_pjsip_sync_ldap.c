/*
 * Asterisk -- An open source telephony toolkit.
 *
 * Copyright (C) 2013, Digium, Inc.
 *
 * Mark Michelson <mmichelson@digium.com>
 *
 * See http://www.asterisk.org for more information about
 * the Asterisk project. Please do not directly contact
 * any of the maintainers of this project for assistance;
 * the project provides a web site, mailing lists and IRC
 * channels for your use.
 *
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 */
/*!
 * \brief Opaque structure representing an RFC 3265 SIP subscription
 */

/*** MODULEINFO
	<depend>pjproject</depend>
	<depend>res_pjsip</depend>
	<support_level>core</support_level>
 ***/

#ifdef GRANDSTREAM_NETWORKS
#define AST_MODULE_LOG "pjsip"
#endif

#include "asterisk.h"

#ifdef GRANDSTREAM_NETWORKS
ASTERISK_FILE_VERSION(__FILE__, "$Revision: 13.0 $");
#endif

#include <pjsip.h>
#include <pjsip_simple.h>
#include <pjlib.h>

#include "asterisk/res_pjsip_pubsub.h"
#include "asterisk/module.h"
#include "asterisk/linkedlists.h"
#include "asterisk/astobj2.h"
#include "asterisk/datastore.h"
#include "asterisk/uuid.h"
#include "asterisk/taskprocessor.h"
#include "asterisk/sched.h"
#include "asterisk/res_pjsip.h"
#include "asterisk/callerid.h"
#include "asterisk/manager.h"
#include "asterisk/test.h"
#include "res_pjsip/include/res_pjsip_private.h"
#include "asterisk/res_pjsip_presence_xml.h"
#include "asterisk/app.h"

/*! BEGIN: Added by yfyang, for ldap sync */
#define  g_ldap_sync_key   "wohi90237402ns"

static int    g_ldap_changed   = 1;
//static int    g_ldap_request   = 0;

struct st_ldap_server
{
	struct ast_sip_endpoint *endpoint;
	int enabled;
	int local_port;
	int remote_port;
	char *remote_host;
	char *decrypt_key;
	char *extension_prefix;
	char *trunk_name;
	char *trunk_context;
	char *check_sum;/*The MD5 checksum of encrypted file*/
	AST_LIST_ENTRY(st_ldap_server) entry;
};

struct st_ldap_sync_list
{
	int sip_tk_num;
	struct ast_sip_endpoint  *sip_tk_sync_pos;
	AST_LIST_HEAD(, st_ldap_server) ast_ldap_server_list;
};

struct st_ldap_sync_list  g_ldap_sync_list = {0, NULL, };

/*! END: Added by yfyang, for ldap sync */

static const pj_str_t type = { "application", 11 };
static const pj_str_t subtype = { "x-gs-ldap-sync+xml", 18 };
static const pj_str_t ldapSync = { "ldapSync", 8};
static const pj_str_t providerName = { "providerName", 12};
static const pj_str_t providerAddr = { "providerAddr", 12};
static const pj_str_t fileCheckSum = { "fileCheckSum", 12};

static int is_private_network(const char *remote_addr)
{
	char buf1[4] = {0};
	char buf2[4] = {0};
	int ip1 = 0;
	int ip2 = 0;
	int res = -1;

	if ( remote_addr == NULL )
	{
		return -1;
	}

	sscanf(remote_addr, "%3[^.].%3[^.]", buf1, buf2);

	ip1 = atoi(buf1);
	ip2 = atoi(buf2);

	if ( (ip1 == 10) || (ip1 == 192 && ip2 == 168) || (ip1 == 172 && ip2 >= 16 && ip2 <= 31 ) )
	{
		res = 0;
	}
	ast_log(LOG_DEBUG, "is_private_network: host [%s] result [%d]", remote_addr, res);
	return res;
}

/* local_ip : "0" means to return the local ip, others means to return the NAT IP*/
static int getOutgoingIP(char *ipbuf, int local_ip)
{
	struct ifreq ifr_ip;
	struct sockaddr_in  *sin;
	int    fd;
	char buf[64] = { 0 };
	char buffer[128] = { 0 };
	char device[16] = { 0 };
	int  device_mode = 1;

	if (NULL == ipbuf)
	{
		return -1;
	}

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (-1 == fd)
	{
		return -1;
	}
	FILE *fp = NULL;
	fp = popen("nvram get :ext_ip && nvram get 231 && nvram get wan_device && nvram get lan_device && nvram get default_if && nvram get lan1_device && nvram get lan2_device", "r");
	if (fp != NULL)
	{
		while (fp != NULL && (!feof(fp))
			   && (fgets(buf, sizeof(buf) - 1, fp) != NULL))
		{
			ast_log(LOG_DEBUG, "getOutgoingIP Read: %s", buf);
			strcat(buffer, buf);
		}
		pclose(fp);
		fp = NULL;

		if (buffer[0] != '\0')
		{
			/*parsing result*/
			int i = 0;
			char *ptr = buffer;
			char *sub = NULL;
			char value[5][64] = {
				{ 0 }, { 0 }, { 0 }, {0}, {0}
			};
			ast_log(LOG_DEBUG, "getOutgoingIP Reslut: {%s}", buffer);

			while ((sub = strtok(ptr, "\n")) != NULL && i < 5)
			{
				ast_copy_string(value[i], sub, sizeof(value[i]) - 1);
				i++;
				ptr = NULL;
			}

			if ( local_ip != 0 && value[0] != NULL && (strchr(value[0], '.') != NULL || strchr(value[0], ':') != NULL))
			{
				/*Try to support IPv4 and IPv6*/
				ast_log(LOG_DEBUG, "Have the external IP via STUN, use it : {%s}", value[0]);
				strcpy(ipbuf, value[0]);
			}
			else
			{
				int i = 0;
				ast_log(LOG_DEBUG, "Use the local IP");

				if (NULL != strchr(value[0], '.'))
				{
					device_mode = atoi(value[1]);
					i = 1;
				}
				else
				{
					device_mode = atoi(value[0]);
				}

				if (device_mode == 0)
				{
					/*Router mode, using wan_device */
					/*0 ethx ethxx LANx*/
					ast_copy_string(device, value[1+i], sizeof(device) - 1);
				}
				else if (device_mode == 1)
				{
					/*Switch mode, using lan_device */
					/*1 ethx ethx LANX*/
					ast_copy_string(device, value[2+i], sizeof(device) - 1);
				}
				else
				{
					/*Dual mode, using the default interface*/
					/*2 LANX ethx etxx*/
					ast_copy_string(device, value[3+i], sizeof(device) - 1);
				}

				memset(&ifr_ip, 0, sizeof(ifr_ip));
				strncpy(ifr_ip.ifr_ifrn.ifrn_name, device[0] == '\0' ? "eth0" : device, sizeof(ifr_ip.ifr_ifrn.ifrn_name) - 1);

				if (ioctl(fd, SIOCGIFADDR, &ifr_ip) < 0)
				{
					ast_log(LOG_DEBUG, "getOutgoingIP: failed\n");
					close(fd);
					return -1;
				}

				sin = (struct sockaddr_in *)&ifr_ip.ifr_ifru.ifru_addr;
				strcpy(ipbuf, ast_inet_ntoa(sin->sin_addr));

			}
		}

	}
	ast_log(LOG_DEBUG, "getOutgoingIP: [%s]\n", ipbuf);
	close(fd);
	return 0;
}

static int url_to_IP(const char *url, char *ip, int length)
{
	struct addrinfo hints, *res;
	struct in_addr addr;
	int err;

	if (url == NULL || ip == NULL)
	{
		ast_log(LOG_DEBUG, "Enter url_to_IP : Input error");
		return -1;
	}

	ast_log(LOG_DEBUG, "url_to_IP : URL: %s", url);

	memset(&hints, 0, sizeof(hints));
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_family = AF_INET;

	if ((err = getaddrinfo(url, NULL, &hints, &res)) != 0)
	{
		ast_log(LOG_DEBUG, "url_to_IP : error %d", err);
		snprintf(ip, length, "%s", url); /*In case the url is an IP address*/
		return 1;
	}

	addr.s_addr = ((struct sockaddr_in *)(res->ai_addr))->sin_addr.s_addr;
	const char *ptr = ast_inet_ntoa(addr);
	ast_log(LOG_DEBUG, "url_to_IP : IP address: %s", ptr==NULL?"UNKNOW":ptr);

	snprintf(ip, length, "%s", ptr==NULL?url:ptr);

	freeaddrinfo(res);

	return 0;
}

static void sip_ldap_sync_manual(const char *address);
static pj_bool_t optnot_on_rx_request(pjsip_rx_data *rdata);

static struct pjsip_module notify_module = {
	.name = { "NOTIFY Module", 13 },
	.priority = PJSIP_MOD_PRIORITY_APPLICATION - 1,
	.on_rx_request = optnot_on_rx_request,
};

static const pj_str_t str_event_name = { "Event", 5 };

static struct ast_sip_contact_status *find_or_create_contact_status(const struct ast_sip_contact *contact)
{
	struct ast_sip_contact_status *status;

	status = ast_sorcery_retrieve_by_id(ast_sip_get_sorcery(), CONTACT_STATUS,
		ast_sorcery_object_get_id(contact));
	if (status) {
		return status;
	}

	status = ast_sorcery_alloc(ast_sip_get_sorcery(), CONTACT_STATUS,
		ast_sorcery_object_get_id(contact));
	if (!status) {
		ast_log(LOG_ERROR, "Unable to create ast_sip_contact_status for contact %s\n",
			contact->uri);
		return NULL;
	}

	if (ast_sorcery_create(ast_sip_get_sorcery(), status)) {
		ast_log(LOG_ERROR, "Unable to persist ast_sip_contact_status for contact %s\n",
			contact->uri);
		ao2_ref(status, -1);
		return NULL;
	}

	return status;
}

static void update_contact_status(const struct ast_sip_contact *contact,
	enum ast_sip_contact_status_type value)
{
	struct ast_sip_contact_status *status;
	struct ast_sip_contact_status *update;

	status = find_or_create_contact_status(contact);
	if (!status) {
		return;
	}

	update = ast_sorcery_alloc(ast_sip_get_sorcery(), CONTACT_STATUS,
		ast_sorcery_object_get_id(status));
	if (!update) {
		ast_log(LOG_ERROR, "Unable to create update ast_sip_contact_status for contact %s\n",
			contact->uri);
		ao2_ref(status, -1);
		return;
	}

	update->status = value;

	/* if the contact is available calculate the rtt as
	  the diff between the last start time and "now" */
	update->rtt = update->status == AVAILABLE ?
		ast_tvdiff_us(ast_tvnow(), status->rtt_start) : 0;

	update->rtt_start = ast_tv(0, 0);

	if (ast_sorcery_update(ast_sip_get_sorcery(), update)) {
		ast_log(LOG_ERROR, "Unable to update ast_sip_contact_status for contact %s\n",
			contact->uri);
	}

	ao2_ref(update, -1);
	ao2_ref(status, -1);
}

static void qualify_contact_cb(void *token, pjsip_event *e)
{
	struct ast_sip_contact *contact = token;

	switch(e->body.tsx_state.type) {
	default:
		ast_log(LOG_ERROR, "Unexpected PJSIP event %d\n", e->body.tsx_state.type);
		/* Fall through */
	case PJSIP_EVENT_TRANSPORT_ERROR:
	case PJSIP_EVENT_TIMER:
		update_contact_status(contact, UNAVAILABLE);
		break;
	case PJSIP_EVENT_RX_MSG:
		update_contact_status(contact, AVAILABLE);
		break;
	}
	ao2_cleanup(contact);
}


static void init_start_time(const struct ast_sip_contact *contact)
{
	struct ast_sip_contact_status *status;
	struct ast_sip_contact_status *update;

	status = find_or_create_contact_status(contact);
	if (!status) {
		return;
	}

	update = ast_sorcery_alloc(ast_sip_get_sorcery(), CONTACT_STATUS,
		ast_sorcery_object_get_id(status));
	if (!update) {
		ast_log(LOG_ERROR, "Unable to create update ast_sip_contact_status for contact %s\n",
			contact->uri);
		ao2_ref(status, -1);
		return;
	}

	update->rtt_start = ast_tvnow();

	if (ast_sorcery_update(ast_sip_get_sorcery(), update)) {
		ast_log(LOG_ERROR, "Unable to update ast_sip_contact_status for contact %s\n",
			contact->uri);
	}

	ao2_ref(update, -1);
	ao2_ref(status, -1);
}

static void print_tdata_buf(pjsip_tx_data *tdata)
{
	char *buf;

	buf = pj_pool_alloc(tdata->pool, PJSIP_MAX_PKT_LEN);
	pjsip_msg_print(tdata->msg, buf, PJSIP_MAX_PKT_LEN);
	ast_log(LOG_ERROR, "tdata = \n%s",buf);
}

static int get_ldap_checksum(int port, char *checksum, int length)
{
	char cmd[32] = {0};
	char buf[64] = { 0 };
	char buffer[128] = { 0 };

	if (NULL == checksum)
	{
		return -1;
	}

	FILE *fp = NULL;
	snprintf(cmd, sizeof(cmd), "nvram get :ldapsync_%d", port);
	fp = popen(cmd, "r");
	if (fp != NULL)
	{
		while (fp != NULL && (!feof(fp))
			   && (fgets(buf, sizeof(buf) - 1, fp) != NULL))
		{
			ast_log(LOG_DEBUG, "get_ldap_checksum Read: %s", buf);
			strcat(buffer, buf);
		}
		pclose(fp);
		fp = NULL;

		char *ptr = strchr(buffer, '\n');
		if (ptr != NULL)
		{
			*ptr = '\0';
		}
	}
	ast_log(LOG_DEBUG, "get_ldap_checksum: [%s]\n", buffer);
	strncpy(checksum, buffer, length);

	return 0;
}

static int xml_print_body( struct pjsip_msg_body *msg_body,
			  char *buf, pj_size_t size)
{
	return pj_xml_print((const pj_xml_node*)msg_body->data, buf, size,
				PJ_TRUE);
}


/*
 * Function to clone XML document.
 */
static void* xml_clone_data(pj_pool_t *pool, const void *data, unsigned len)
{
	PJ_UNUSED_ARG(len);
	return pj_xml_clone( pool, (const pj_xml_node*)data);
}

static pjsip_msg_body *gs_ldap_sync_build_xml(pj_pool_t *pool, struct ast_sip_endpoint *endpoint)
{
	struct st_ldap_server  *pstLdapServer    = NULL;
	pj_xml_node *doc, *node;
	pjsip_msg_body *body = NULL;
	pj_str_t providerNameVal;
	pj_str_t providerAddrVal;
	pj_str_t fileCheckSumVal;
	char address[256] = {0};
	char checksum[128] = {0};
	const char *name = ast_sorcery_object_get_id(endpoint);

	AST_LIST_TRAVERSE(&(g_ldap_sync_list.ast_ldap_server_list), pstLdapServer, entry)
	{
		ast_log(LOG_ERROR,"pstLdapServer->trunk_name= %s\n",pstLdapServer->trunk_name);
		if ( NULL != pstLdapServer->endpoint&& pstLdapServer->enabled == 1
		  && NULL != pstLdapServer->remote_host && strcasecmp(pstLdapServer->trunk_context, name ) == 0 )
		{
			ast_log(LOG_ERROR,"----------------------------\n");
			doc = pj_xml_node_new(pool, &ldapSync);

			node = pj_xml_node_new(pool, &providerName);
			providerNameVal.ptr = pj_pool_alloc(pool, PJSIP_MAX_URL_SIZE);
			providerNameVal.slen = pj_ansi_snprintf(providerNameVal.ptr, PJSIP_MAX_URL_SIZE,"%s",pstLdapServer->trunk_name);
			node->content = providerNameVal;
			pj_xml_add_node(doc, node);

			node = pj_xml_node_new(pool, &providerAddr);
			memset(address, 0, sizeof(address));
			getOutgoingIP(address, is_private_network( pstLdapServer->remote_host ));
			providerAddrVal.ptr = pj_pool_alloc(pool, PJSIP_MAX_URL_SIZE);
			providerAddrVal.slen = pj_ansi_snprintf(providerAddrVal.ptr, PJSIP_MAX_URL_SIZE,"%s:%d",
				address, pstLdapServer->local_port);
			node->content = providerAddrVal;
			pj_xml_add_node(doc, node);

			node = pj_xml_node_new(pool, &fileCheckSum);
			get_ldap_checksum(pstLdapServer->local_port, checksum, sizeof(checksum));
			fileCheckSumVal.ptr = pj_pool_alloc(pool, PJSIP_MAX_URL_SIZE);
			fileCheckSumVal.slen = pj_ansi_snprintf(fileCheckSumVal.ptr, PJSIP_MAX_URL_SIZE,"%s",checksum);
			node->content = fileCheckSumVal;
			pj_xml_add_node(doc, node);

			body = PJ_POOL_ZALLOC_T(pool, pjsip_msg_body);
			body->content_type.type = type;
			body->content_type.subtype = subtype;

			body->data = doc;
			body->len = 0;

			body->print_body = &xml_print_body;
			body->clone_data = &xml_clone_data;
		}
	 }

	return body;

}

static int send_option(struct ast_sip_endpoint *endpoint, struct ast_sip_contact *contact)
{
	pjsip_tx_data *tdata;

	ast_log(LOG_ERROR," contact = %s\n", contact->uri);

	if (ast_sip_create_request("OPTIONS", NULL, NULL, NULL, contact, &tdata)) {
		ast_log(LOG_ERROR, "Unable to create request to qualify contact %s\n",
			contact->uri);
		return -1;
	}

	/* If an outbound proxy is specified set it on this request */
	if (!ast_strlen_zero(contact->outbound_proxy) &&
		ast_sip_set_outbound_proxy(tdata, contact->outbound_proxy)) {
		pjsip_tx_data_dec_ref(tdata);
		ast_log(LOG_ERROR, "Unable to apply outbound proxy on request to qualify contact %s\n",
			contact->uri);
		return -1;
	}

	init_start_time(contact);

	tdata->msg->body = gs_ldap_sync_build_xml(tdata->pool, endpoint);
	print_tdata_buf(tdata);

	ao2_ref(contact, +1);
	if (ast_sip_send_request(tdata, NULL, endpoint, contact, qualify_contact_cb)
		!= PJ_SUCCESS) {
		ast_log(LOG_ERROR, "Unable to send request to qualify contact %s\n",
			contact->uri);
		update_contact_status(contact, UNAVAILABLE);
		ao2_ref(contact, -1);
		return -1;
	}

	return 0;
}

static int sip_poke_peer(struct ast_sip_endpoint *endpoint)
{
	char *aors;
	char *aor_name;

	ast_log(LOG_ERROR,"sip_poke_peer\n");
	if (!endpoint)
	{
		ast_log(LOG_ERROR,"endpoint->aors\n");
		return -1;
	} else if(!endpoint->aors){
		ast_log(LOG_ERROR,"endpoint->aors\n");
		return -1;
	}
	aors = ast_strdupa(endpoint->aors);
	ast_log(LOG_ERROR, "aors = %s\n",aors);
	while ((aor_name = strsep(&aors, ","))) {
		struct ast_sip_aor *aor;
		struct ast_sip_contact *contact;

		aor = ast_sip_location_retrieve_aor(aor_name);
		if (!aor) {
			continue;
		}

		contact = ast_sip_location_retrieve_first_aor_contact(aor);
		if (contact) {
			send_option(endpoint,contact);
		}

		ao2_ref(aor, -1);
	}
	return PJ_TRUE;
}

static pj_bool_t notify_on_rx_request(pjsip_rx_data *rdata)
{
	ast_log(LOG_ERROR,"notify_on_rx_request\n");
	pjsip_event_hdr *event_header;
	char event[32];
	RAII_VAR(struct ast_sip_endpoint *, endpoint, NULL, ao2_cleanup);

	endpoint = ast_pjsip_rdata_get_endpoint(rdata);
	ast_assert(endpoint != NULL);

	const char *name = ast_sorcery_object_get_id(endpoint);
	ast_log(LOG_ERROR, "name    =   %s\n",name);
	event_header = pjsip_msg_find_hdr_by_name(rdata->msg_info.msg, &str_event_name, rdata->msg_info.msg->hdr.next);
	if (!event_header) {
		ast_log(LOG_ERROR, "Incoming NOTIFY request with no Event header\n");
		return PJ_TRUE;
	}
	ast_copy_pj_str(event, &event_header->event_type, sizeof(event));

	if (strcmp("gs-request-ldap-sync", event)) {
		ast_log(LOG_ERROR, "--------not-----------\n");
		return PJ_FALSE;
	}

	pjsip_endpt_respond_stateless(ast_sip_get_pjsip_endpoint(), rdata, 200, NULL, NULL, NULL);

	ast_log(LOG_ERROR, "---------gs-request-ldap-sync----------\n");
	sip_ldap_sync_manual(name);
	//sip_poke_peer(endpoint);
	return PJ_TRUE;
}

/*LDAP settings on sip_users.conf trunk_xx context*/
#define LDAP_ENABLE        "ldap_sync_enable"
#define LDAP_KEY           "ldap_sync_passwd"
#define LDAP_LOCAL_PORT    "ldap_sync_port"
#define LDAP_OUTGOING_RULE "ldap_default_outrt"
#define LDAP_EXT_PERFIX    "ldap_default_outrt_prefix"
#define LDAP_TRUNK_NAME    "trunk_name"
#define LDAP_TRUNK_HOST    "host"

static void gs_ldap_get_settings_by_trunk_name(struct st_ldap_server  *node, const char *trunk_context)
{
	if ( node == NULL || trunk_context == NULL )
	{
		ast_log(LOG_WARNING, "LDAP get settings: Invalid parameter !");
		return;
	}
	ast_log(LOG_VERBOSE, "Enter gs_ldap_get_settings_by_trunk_name [%s] !!!\n", trunk_context);

	/*Parsing context from users.conf*/
	struct ast_config *cfg = NULL;
	char buffer[256] = {0};
	struct ast_flags config_flags = {0};
	if ((cfg = ast_config_load("sip_users.conf", config_flags)) && cfg != CONFIG_STATUS_FILEINVALID)
	{
		ast_log(LOG_VERBOSE, "sip_users.conf is OK!!!\n");

		ast_copy_string(buffer, S_OR(ast_variable_retrieve(cfg, trunk_context, LDAP_ENABLE), "no"), sizeof(buffer));
		node->trunk_context= ast_strdup(trunk_context);
		if ( strcasecmp(buffer, "yes") == 0 )
		{
			node->enabled = 1;
		}
		memset(buffer, 0, sizeof(buffer));

		ast_copy_string(buffer, S_OR(ast_variable_retrieve(cfg, trunk_context, LDAP_KEY), ""), sizeof(buffer));
		if ( buffer[0] != '\0' )
		{
			if ( node->decrypt_key != NULL )
			{
				ast_free(node->decrypt_key);
				node->decrypt_key = NULL;
			}
			node->decrypt_key = ast_strdup(buffer);
		}
		memset(buffer, 0, sizeof(buffer));

		ast_copy_string(buffer, S_OR(ast_variable_retrieve(cfg, trunk_context, LDAP_LOCAL_PORT), ""), sizeof(buffer));
		if ( buffer[0] != '\0' )
		{
			node->local_port = atoi(buffer);
		}
		memset(buffer, 0, sizeof(buffer));

		ast_copy_string(buffer, S_OR(ast_variable_retrieve(cfg, trunk_context, LDAP_EXT_PERFIX), ""), sizeof(buffer));
		if ( buffer[0] != '\0' )
		{
			if ( node->extension_prefix != NULL )
			{
			  ast_free(node->extension_prefix);
			  node->extension_prefix = NULL;
			}
			node->extension_prefix = ast_strdup(buffer);
		}
		memset(buffer, 0, sizeof(buffer));

		ast_copy_string(buffer, S_OR(ast_variable_retrieve(cfg, trunk_context, LDAP_TRUNK_NAME), ""), sizeof(buffer));
		if ( buffer[0] != '\0' )
		{
			if ( node->trunk_name != NULL )
			{
			  ast_free(node->trunk_name);
			  node->trunk_name = NULL;
			}
			node->trunk_name = ast_strdup(buffer);
		}
		memset(buffer, 0, sizeof(buffer));

		ast_copy_string(buffer, S_OR(ast_variable_retrieve(cfg, trunk_context, LDAP_TRUNK_HOST), ""), sizeof(buffer));
		if ( buffer[0] != '\0' )
		{
			if ( node->remote_host != NULL )
			{
			  ast_free(node->remote_host);
			  node->remote_host = NULL;
			}
			node->remote_host = ast_strdup(buffer);
		}
		memset(buffer, 0, sizeof(buffer));
		ast_config_destroy(cfg);
	}

	ast_log(LOG_DEBUG, "Enabled: (%d)\n", node->enabled);
	ast_log(LOG_DEBUG, "Key    : (%s)\n", node->decrypt_key==NULL?"":node->decrypt_key);
	ast_log(LOG_DEBUG, "Prefix : (%s)\n", node->extension_prefix==NULL?"":node->extension_prefix);
	ast_log(LOG_DEBUG, "Local Port: (%d)\n", node->local_port);
	ast_log(LOG_DEBUG, "Remote Host:(%s)\n", node->remote_host==NULL?"":node->remote_host);
	ast_log(LOG_DEBUG, "Trunk NAME:(%s)\n", node->trunk_name==NULL?"":node->trunk_name);

	ast_log(LOG_ERROR, "Exit gs_ldap_get_settings_by_trunk_name [%s] !!!\n", trunk_context);

}

static void gs_ldap_get_trunk_peer(void)
{
	ast_log(LOG_DEBUG, "Enter gs_ldap_get_trunk_peer !!!\n");

	struct st_ldap_server  *pstLdapServer    = NULL;
	struct st_ldap_server  *pstLdapServerNew = NULL;
	struct ast_sip_endpoint *pstPeer          = NULL;
	struct ao2_iterator     i;

	//AST_LIST_LOCK(&g_ldap_sync_list.ast_ldap_server_list);
	/* remove old list member */
	while ((pstLdapServer = AST_LIST_REMOVE_HEAD(&g_ldap_sync_list.ast_ldap_server_list, entry)))
	{
		if (pstLdapServer->decrypt_key != NULL)
		{
			ast_free(pstLdapServer->decrypt_key);
			pstLdapServer->decrypt_key = NULL;
		}

		if (pstLdapServer->extension_prefix != NULL)
		{
			ast_free(pstLdapServer->extension_prefix);
			pstLdapServer->extension_prefix = NULL;
		}

		if (pstLdapServer->remote_host != NULL)
		{
			ast_free(pstLdapServer->remote_host);
			pstLdapServer->remote_host = NULL;
		}

		if (pstLdapServer->trunk_name != NULL)
		{
			ast_free(pstLdapServer->trunk_name);
			pstLdapServer->trunk_name = NULL;
		}

		if (pstLdapServer->trunk_context!= NULL)
		{
			ast_free(pstLdapServer->trunk_context);
			pstLdapServer->trunk_context = NULL;
		}
		ast_free(pstLdapServer);
	}

	g_ldap_sync_list.sip_tk_num = 0;

	/* inset new list member */
	RAII_VAR(struct ao2_container *, endpoints, ast_sip_get_endpoints(), ao2_cleanup);
	i = ao2_iterator_init(endpoints, 0);
	while ((pstPeer = ao2_t_iterator_next(&i, "iterate thruk peers table")))
	{
		ao2_lock(pstPeer);
		const char *name = ast_sorcery_object_get_id(pstPeer);

		if (0 == strstr(name, "trunk_"))
		{
			ao2_unlock(pstPeer);
			continue;
		}

		pstLdapServerNew = ast_calloc(1, sizeof(struct st_ldap_server));
		if (NULL == pstLdapServerNew)
		{
			ao2_unlock(pstPeer);
			continue;
		}

		pstLdapServerNew->decrypt_key = NULL;
		pstLdapServerNew->extension_prefix = NULL;
		pstLdapServerNew->remote_host = NULL;
		pstLdapServerNew->trunk_name = NULL;
		pstLdapServerNew->trunk_context = NULL;
		pstLdapServerNew->enabled     = 0;
		pstLdapServerNew->local_port  = 0;
		pstLdapServerNew->remote_port = 0;
		pstLdapServerNew->endpoint= pstPeer;
		gs_ldap_get_settings_by_trunk_name(pstLdapServerNew, name);

		AST_LIST_INSERT_TAIL(&g_ldap_sync_list.ast_ldap_server_list, pstLdapServerNew, entry);
		g_ldap_sync_list.sip_tk_num++;

		ao2_unlock(pstPeer);
		ao2_cleanup(pstPeer);
	}
	ao2_iterator_destroy(&i);

	//AST_LIST_UNLOCK(&g_ldap_sync_list.ast_ldap_server_list);

	ast_log(LOG_DEBUG, "gs_ldap_get_trunk_peer, has [%d] sip trunk", g_ldap_sync_list.sip_tk_num);
	ast_log(LOG_DEBUG, "Exit gs_ldap_get_trunk_peer !!!\n");

}

/*! \brief Send a ldap sync optons to all sip trunk peers */
static void sip_ldap_sync_manual(const char *context)
{
	ast_log(LOG_ERROR, "Enter sip_ldap_sync_manual !!!");

	struct st_ldap_server  *pstLdapServer = NULL;
	char   command[512] = {0};
	char   host_address[512] = {0};

	if ( context == NULL)
	{
		ast_log(LOG_ERROR, "sip_ldap_sync_manual, input error!");
		return;
	}

	ast_log(LOG_ERROR, "sip_ldap_sync_manual host: [%s]!!!", context);


	if (0 == g_ldap_sync_list.sip_tk_num)
	{
		ast_log(LOG_ERROR, "sip_ldap_sync_msnual, no sip trunk");
		return;
	}

	AST_LIST_LOCK(&(g_ldap_sync_list.ast_ldap_server_list));
	AST_LIST_TRAVERSE(&(g_ldap_sync_list.ast_ldap_server_list), pstLdapServer, entry)
	{
		//ast_log(LOG_DEBUG, "pstLdapServer->sip_tk_peer == NULL? : %s", NULL != pstLdapServer->sip_tk_peer?"yes":"no");
		//ast_log(LOG_DEBUG, "pstLdapServer->enabled == 1? : %s", pstLdapServer->enabled == 1?"yes":"no");
		#if 0
		snprintf(host_address, sizeof(host_address), "%s:%d", pstLdapServer->remote_host, pstLdapServer->remote_port);
		#else
		url_to_IP(pstLdapServer->remote_host, host_address, sizeof(host_address));
		#endif

		ast_log(LOG_ERROR, "host_addr is (%s), address is (%s)", host_address, context);

		if ( NULL != pstLdapServer->endpoint && pstLdapServer->enabled == 1
			&& strcasecmp(pstLdapServer->trunk_context, context) == 0 )
		{
			ast_log(LOG_ERROR, "prepareLDAPSync for trunk [%s] ~", pstLdapServer->trunk_name);
			ast_log(LOG_ERROR, "prepareLDAPSync for <%s> (%d)", pstLdapServer->decrypt_key==NULL?"NULL":pstLdapServer->decrypt_key, pstLdapServer->local_port);
			snprintf(command, sizeof(command), "prepareLDAPFile.sh %s %d", pstLdapServer->decrypt_key==NULL?g_ldap_sync_key:pstLdapServer->decrypt_key
			  , pstLdapServer->local_port);
			ast_safe_system(command);

			snprintf(command, sizeof(command), "prepareLDAPSync.sh %d &", pstLdapServer->local_port);
			ast_safe_system(command);

			sip_poke_peer(pstLdapServer->endpoint);
		}
	}
	AST_LIST_UNLOCK(&(g_ldap_sync_list.ast_ldap_server_list));

	ast_log(LOG_ERROR, "Exit sip_ldap_sync_manual !!!");

	//g_ldap_request--;

	return;
}

static void sip_ldap_sync_all(void)
{
	ast_log(LOG_ERROR, "Enter sip_ldap_sync_all !!!\n");

	struct st_ldap_server  *pstLdapServer = NULL;
	char   command[512] = {0};

	if ( 0 == g_ldap_changed)
	{
		ast_log(LOG_ERROR, "sip_ldap_sync_all, no change");
		return;
	}

	if (0 == g_ldap_sync_list.sip_tk_num)
	{
		ast_log(LOG_ERROR, "sip_ldap_sync_all, no sip trunk");
		return;
	}

	AST_LIST_LOCK(&(g_ldap_sync_list.ast_ldap_server_list));
	AST_LIST_TRAVERSE(&(g_ldap_sync_list.ast_ldap_server_list), pstLdapServer, entry)
	{
		if ( NULL != pstLdapServer->endpoint && pstLdapServer->enabled == 1 )
		{
			ast_log(LOG_ERROR, "prepareLDAPSync for trunk [%s] ~", pstLdapServer->trunk_name);
			ast_log(LOG_ERROR, "prepareLDAPSync for <%s> (%d)", pstLdapServer->decrypt_key==NULL?"NULL":pstLdapServer->decrypt_key, pstLdapServer->local_port);
			snprintf(command, sizeof(command), "prepareLDAPFile.sh %s %d", pstLdapServer->decrypt_key==NULL?g_ldap_sync_key:pstLdapServer->decrypt_key, pstLdapServer->local_port);
			ast_safe_system(command);

			snprintf(command, sizeof(command), "prepareLDAPSync.sh %d &", pstLdapServer->local_port);
			ast_safe_system(command);
			ast_log(LOG_ERROR, "sip_poke_peer for\n");
			sip_poke_peer(pstLdapServer->endpoint);
		}
	}
	AST_LIST_UNLOCK(&(g_ldap_sync_list.ast_ldap_server_list));

	g_ldap_changed = 0;

	ast_log(LOG_ERROR, "Exit sip_ldap_sync_all !!!\n");


	return;
}

static pj_status_t sip_get_ldap_sync_info_from_msg( pj_pool_t *pool, char *msg, pj_size_t len,
	pj_str_t **pName, pj_str_t **pIPAddr, pj_str_t **pChecksum)
{
	pj_xml_node *doc, *node;

	doc = pj_xml_parse( pool, msg, len);
	if (!doc)
	{
		return -1;
	}

	if (pj_stricmp(&doc->name, &ldapSync) != 0)
	{
		return -1;
	}

	node = pj_xml_find_node(doc, &providerName);
	if (node == NULL)
	{
		return -1;
	}
	*pName = &node->content;

	node = pj_xml_find_node(doc, &providerAddr);
	if (node == NULL)
	{
		return -1;
	}
	*pIPAddr = &node->content;

	node = pj_xml_find_node(doc, &fileCheckSum);
	if (node == NULL)
	{
		return -1;
	}
	*pChecksum = &node->content;

	return PJ_SUCCESS;
}

static pj_bool_t options_on_rx_request(pjsip_rx_data *rdata)
{
	ast_log(LOG_ERROR,"options_on_rx_request\n");
	pjsip_ctype_hdr *ctype_header;
	pjsip_msg_body *body = rdata->msg_info.msg->body;
	RAII_VAR(struct ast_sip_endpoint *, endpoint, NULL, ao2_cleanup);

	endpoint = ast_pjsip_rdata_get_endpoint(rdata);

	ast_assert(endpoint != NULL);

	ctype_header = pjsip_msg_find_hdr(rdata->msg_info.msg, PJSIP_H_CONTENT_TYPE, NULL);
	if (!ctype_header) {
		ast_log(LOG_ERROR, "Incoming OPTIONS request with no CONTENT TYPE header\n");
		return PJ_FALSE;
	}

	if (pj_stricmp(&ctype_header->media.type, &type)) {
		ast_log(LOG_ERROR, "type not application\n");
		return PJ_FALSE;
	}
	if (pj_stricmp(&ctype_header->media.subtype, &subtype)) {
		ast_log(LOG_ERROR, "content not gs-request-ldap-sync\n");
		return PJ_FALSE;
	}

	pjsip_endpt_respond_stateless(ast_sip_get_pjsip_endpoint(), rdata, 200, NULL, NULL, NULL);
	pj_status_t status;
	pj_str_t *pj_name= NULL;
	pj_str_t *pj_ip = NULL;
	pj_str_t *pj_checksum = NULL;
	char prd_name[80] = {0};
	char prd_ip[32] = {0};
	char prd_checksum[128] = {0};
	int  prd_port   = 0;
	char command[512] = {0};
	char host_address[256] = {0};

	status = sip_get_ldap_sync_info_from_msg(rdata->tp_info.pool, (char*)body->data, body->len,
		&pj_name, &pj_ip, &pj_checksum);
	snprintf(prd_name, sizeof(prd_name), "%.*s", (int)pj_name->slen, pj_name->ptr);
	snprintf(prd_ip, sizeof(prd_ip), "%.*s", (int)pj_ip->slen, pj_ip->ptr);
	char *pPort = NULL; 
	pPort = strchr(prd_ip, ':');
	sscanf(prd_ip, "%[^:]", prd_ip);
	++pPort;
	prd_port = atoi(pPort);
	snprintf(prd_checksum, sizeof(prd_checksum), "%.*s", (int)pj_checksum->slen, pj_checksum->ptr);
	ast_log(LOG_ERROR, "prd_name = %s, prd_addr = %s:%d,  prd_checksum = %s\n", prd_name, prd_ip, prd_port, prd_checksum); 
	{
		/*UPdate list*/
		struct st_ldap_server *pstLdapServer = NULL;
		//AST_LIST_LOCK(&(g_ldap_sync_list.ast_ldap_server_list));
		AST_LIST_TRAVERSE(&(g_ldap_sync_list.ast_ldap_server_list), pstLdapServer, entry)
		{
			if ( pstLdapServer->remote_host != NULL )
			{
				url_to_IP(pstLdapServer->remote_host, host_address, sizeof(host_address));
				ast_log(LOG_ERROR, "Remote host is:[%s], toIP[%s], PRD_IP is [%s]", pstLdapServer->remote_host, host_address, prd_ip);
				if ( strcasecmp(host_address, prd_ip) == 0 )
				{
					pstLdapServer->remote_port = prd_port;

					snprintf(command, sizeof(command), "syncRemoteLDAP.sh %s %d %s %s %s %s&",
							prd_ip, prd_port, pstLdapServer->trunk_name, pstLdapServer->decrypt_key, prd_checksum,
							pstLdapServer->extension_prefix==NULL?"":pstLdapServer->extension_prefix);
					break;
				}
			}
		}
		//AST_LIST_UNLOCK(&(g_ldap_sync_list.ast_ldap_server_list));

		if ( command[0] == '\0' )
		{
				snprintf(command, sizeof(command), "syncRemoteLDAP.sh %s %d %s %s &",
						prd_ip, prd_port, prd_name, g_ldap_sync_key);
		}

		ast_log(LOG_ERROR, "command is : %s\n", command);
		ast_safe_system(command);
	}
	if (status != PJ_SUCCESS)
	{
		return PJ_FALSE;
	}
	ast_log(LOG_ERROR, "---------gs-request-ldap-sync----------\n");

	return PJ_TRUE;
}
static pj_bool_t optnot_on_rx_request(pjsip_rx_data *rdata)
{
	if (!pjsip_method_cmp(&rdata->msg_info.msg->line.req.method, &pjsip_notify_method)) {
		return notify_on_rx_request(rdata);
	} else if (!pjsip_method_cmp(&rdata->msg_info.msg->line.req.method, &pjsip_options_method)) {
		return options_on_rx_request(rdata);
	}

	return PJ_FALSE;
}


static int load_module(void)
{
	CHECK_PJSIP_MODULE_LOADED();

	if (ast_sip_register_service(&notify_module)) {
		ast_log(LOG_ERROR, "Could not register notify service\n");
		return AST_MODULE_LOAD_FAILURE;
	}

	/* Added by yfyang, for ldap sync feature */
	ast_log(LOG_DEBUG, "ldap sync feature PROCESS START\n");
	gs_ldap_get_trunk_peer();
	//sip_ldap_sync_all();
	ast_log(LOG_DEBUG, "ldap sync feature PROCESS END\n");

	return AST_MODULE_LOAD_SUCCESS;
}

static int unload_module(void)
{
	ast_sip_unregister_service(&notify_module);
	return 0;
}

AST_MODULE_INFO(ASTERISK_GPL_KEY, AST_MODFLAG_LOAD_ORDER, "PJSIP sync LDAP",
		.support_level = AST_MODULE_SUPPORT_CORE,
		.load = load_module,
		.unload = unload_module,
		.load_pri = AST_MODPRI_APP_DEPEND,
);