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

static pj_bool_t notify_on_rx_request(pjsip_rx_data *rdata);

static struct pjsip_module notify_module = {
	.name = { "NOTIFY Module", 13 },
	.priority = PJSIP_MOD_PRIORITY_APPLICATION,
	.on_rx_request = notify_on_rx_request,
};

static const pj_str_t str_event_name = { "Event", 5 };

static struct ast_sched_context *sched;

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

static int sip_dialog_create_from(pj_pool_t *pool, pj_str_t *from, const char *user, const char *domain, const pj_str_t *target, pjsip_tpselector *selector)
{
	pj_str_t tmp, local_addr;
	pjsip_uri *uri;
	pjsip_sip_uri *sip_uri;
	pjsip_transport_type_e type = PJSIP_TRANSPORT_UNSPECIFIED;
	int local_port;
	char uuid_str[AST_UUID_STR_LEN];

	if (ast_strlen_zero(user)) {
		user = ast_uuid_generate_str(uuid_str, sizeof(uuid_str));
	}

	/* Parse the provided target URI so we can determine what transport it will end up using */
	pj_strdup_with_null(pool, &tmp, target);

	if (!(uri = pjsip_parse_uri(pool, tmp.ptr, tmp.slen, 0)) ||
	    (!PJSIP_URI_SCHEME_IS_SIP(uri) && !PJSIP_URI_SCHEME_IS_SIPS(uri))) {
		return -1;
	}

	sip_uri = pjsip_uri_get_uri(uri);

	/* Determine the transport type to use */
	if (PJSIP_URI_SCHEME_IS_SIPS(sip_uri)) {
		type = PJSIP_TRANSPORT_TLS;
	} else if (!sip_uri->transport_param.slen) {
		type = PJSIP_TRANSPORT_UDP;
	} else {
		type = pjsip_transport_get_type_from_name(&sip_uri->transport_param);
	}

	if (type == PJSIP_TRANSPORT_UNSPECIFIED) {
		return -1;
	}

	/* If the host is IPv6 turn the transport into an IPv6 version */
	if (pj_strchr(&sip_uri->host, ':') && type < PJSIP_TRANSPORT_START_OTHER) {
		type = (pjsip_transport_type_e)(((int)type) + PJSIP_TRANSPORT_IPV6);
	}

	if (!ast_strlen_zero(domain)) {
		from->ptr = pj_pool_alloc(pool, PJSIP_MAX_URL_SIZE);
		from->slen = pj_ansi_snprintf(from->ptr, PJSIP_MAX_URL_SIZE,
				"<sip:%s@%s%s%s>",
				user,
				domain,
				(type != PJSIP_TRANSPORT_UDP && type != PJSIP_TRANSPORT_UDP6) ? ";transport=" : "",
				(type != PJSIP_TRANSPORT_UDP && type != PJSIP_TRANSPORT_UDP6) ? pjsip_transport_get_type_name(type) : "");
		return 0;
	}

	/* Get the local bound address for the transport that will be used when communicating with the provided URI */
	if (pjsip_tpmgr_find_local_addr(pjsip_endpt_get_tpmgr(ast_sip_get_pjsip_endpoint()), pool, type, selector,
							      &local_addr, &local_port) != PJ_SUCCESS) {

		/* If no local address can be retrieved using the transport manager use the host one */
		pj_strdup(pool, &local_addr, pj_gethostname());
		local_port = pjsip_transport_get_default_port_for_type(PJSIP_TRANSPORT_UDP);
	}

	/* If IPv6 was specified in the transport, set the proper type */
	if (pj_strchr(&local_addr, ':') && type < PJSIP_TRANSPORT_START_OTHER) {
		type = (pjsip_transport_type_e)(((int)type) + PJSIP_TRANSPORT_IPV6);
	}

	from->ptr = pj_pool_alloc(pool, PJSIP_MAX_URL_SIZE);
	from->slen = pj_ansi_snprintf(from->ptr, PJSIP_MAX_URL_SIZE,
				      "<sip:%s@%s%.*s%s:%d%s%s>",
				      user,
				      (type & PJSIP_TRANSPORT_IPV6) ? "[" : "",
				      (int)local_addr.slen,
				      local_addr.ptr,
				      (type & PJSIP_TRANSPORT_IPV6) ? "]" : "",
				      local_port,
				      (type != PJSIP_TRANSPORT_UDP && type != PJSIP_TRANSPORT_UDP6) ? ";transport=" : "",
				      (type != PJSIP_TRANSPORT_UDP && type != PJSIP_TRANSPORT_UDP6) ? pjsip_transport_get_type_name(type) : "");

	return 0;
}

static int sip_get_tpselector_from_endpoint(const struct ast_sip_endpoint *endpoint, pjsip_tpselector *selector)
{
	RAII_VAR(struct ast_sip_transport *, transport, NULL, ao2_cleanup);
	const char *transport_name = endpoint->transport;

	if (ast_strlen_zero(transport_name)) {
		return 0;
	}

	transport = ast_sorcery_retrieve_by_id(ast_sip_get_sorcery(), "transport", transport_name);

	if (!transport || !transport->state) {
		ast_log(LOG_ERROR, "Unable to retrieve PJSIP transport '%s' for endpoint '%s'\n",
			transport_name, ast_sorcery_object_get_id(endpoint));
		return -1;
	}

	if (transport->state->transport) {
		selector->type = PJSIP_TPSELECTOR_TRANSPORT;
		selector->u.transport = transport->state->transport;
	} else if (transport->state->factory) {
		selector->type = PJSIP_TPSELECTOR_LISTENER;
		selector->u.listener = transport->state->factory;
	} else if (transport->type == AST_TRANSPORT_WS || transport->type == AST_TRANSPORT_WSS) {
		/* The WebSocket transport has no factory as it can not create outgoing connections, so
		 * even if an endpoint is locked to a WebSocket transport we let the PJSIP logic
		 * find the existing connection if available and use it.
		 */
		return 0;
	} else {
		return -1;
	}

	return 0;
}

static void print_tdata_buf(pjsip_tx_data *tdata)
{
	char *buf;

	buf = pj_pool_alloc(tdata->pool, PJSIP_MAX_PKT_LEN);
	pjsip_msg_print(tdata->msg, buf, PJSIP_MAX_PKT_LEN);
	ast_log(LOG_ERROR, "tdata = \n%s",buf);
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

static pjsip_msg_body *gs_ldap_sync_build_xml(pj_pool_t *pool)
{
    pj_xml_node *doc, *node;
    pjsip_msg_body *body;
	pj_str_t type = { "application", 11 };
	pj_str_t subtype = { "x-gs-ldap-sync+xml", 18 };
	pj_str_t ldapSync = { "ldapSync", 8}; 
	pj_str_t providerName = { "providerName", 12};
	pj_str_t providerNameVal;
	pj_str_t providerAddr = { "providerAddr", 12};
	pj_str_t providerAddrVal;
	pj_str_t fileCheckSum = { "fileCheckSum", 12};
	pj_str_t fileCheckSumVal;	

	doc = pj_xml_node_new(pool, &ldapSync);
	
	node = pj_xml_node_new(pool, &providerName);
	providerNameVal.ptr = pj_pool_alloc(pool, PJSIP_MAX_URL_SIZE);
	providerNameVal.slen = pj_ansi_snprintf(providerNameVal.ptr, PJSIP_MAX_URL_SIZE,"%s","160");
	node->content = providerNameVal;
	pj_xml_add_node(doc, node);

	node = pj_xml_node_new(pool, &providerAddr);
	providerAddrVal.ptr = pj_pool_alloc(pool, PJSIP_MAX_URL_SIZE);
	providerAddrVal.slen = pj_ansi_snprintf(providerAddrVal.ptr, PJSIP_MAX_URL_SIZE,"%s:%d","192.168.124.108",999);
	node->content = providerAddrVal;
	pj_xml_add_node(doc, node);

	node = pj_xml_node_new(pool, &fileCheckSum);
	fileCheckSumVal.ptr = pj_pool_alloc(pool, PJSIP_MAX_URL_SIZE);
	fileCheckSumVal.slen = pj_ansi_snprintf(fileCheckSumVal.ptr, PJSIP_MAX_URL_SIZE,"%s","d939e809868cd4e768d1581c0b2f42a8");
	node->content = fileCheckSumVal;
	pj_xml_add_node(doc, node);
	
    body = PJ_POOL_ZALLOC_T(pool, pjsip_msg_body);
    body->content_type.type = type;
    body->content_type.subtype = subtype;

    body->data = doc;
    body->len = 0;

    body->print_body = &xml_print_body;
    body->clone_data = &xml_clone_data;

    return body;

}

static int send_test_request(struct ast_sip_endpoint *endpoint, struct ast_sip_contact *contact)
{
	const pjsip_method *method = &pjsip_options_method;
	struct ast_sip_endpoint *endpoint_local = NULL;
	pjsip_tx_data *tdata;
	pj_str_t remote_uri;
	pj_str_t from;
	//pj_str_t text;
	pj_pool_t *pool;
	pjsip_tpselector selector = { .type = PJSIP_TPSELECTOR_NONE, };

	if (!endpoint_local && (!contact || ast_strlen_zero(contact->uri))) {
		ast_log(LOG_ERROR, "An endpoint and/or uri must be specified\n");
		return -1;
	}

	if (!contact) {
		contact = ast_sip_location_retrieve_contact_from_aor_list(endpoint_local->aors);
	}
	if (!contact || ast_strlen_zero(contact->uri)) {
		ast_log(LOG_ERROR, "Unable to retrieve contact for endpoint %s\n",
				ast_sorcery_object_get_id(endpoint_local));
		return -1;
	}

	pj_cstr(&remote_uri, contact->uri);

	if (endpoint_local) {
		if (sip_get_tpselector_from_endpoint(endpoint_local, &selector)) {
			ast_log(LOG_ERROR, "Unable to retrieve PJSIP transport selector for endpoint %s\n",
				ast_sorcery_object_get_id(endpoint_local));
			return -1;
		}
	}

	pool = pjsip_endpt_create_pool(ast_sip_get_pjsip_endpoint(), "Outbound request", 256, 256);

	if (!pool) {
		ast_log(LOG_ERROR, "Unable to create PJLIB memory pool\n");
		return -1;
	}

	if (sip_dialog_create_from(pool, &from, endpoint_local ? endpoint_local->fromuser : NULL,
				endpoint_local ? endpoint_local->fromdomain : NULL, &remote_uri, &selector)) {
		ast_log(LOG_ERROR, "Unable to create From header for %.*s request to endpoint %s\n",
				(int) pj_strlen(&method->name), pj_strbuf(&method->name), ast_sorcery_object_get_id(endpoint_local));
		pjsip_endpt_release_pool(ast_sip_get_pjsip_endpoint(), pool);
		return -1;
	}

	if (pjsip_endpt_create_request(ast_sip_get_pjsip_endpoint(), method, &remote_uri,
			&from, &remote_uri, &from, NULL, -1, NULL, &tdata) != PJ_SUCCESS) {
		ast_log(LOG_ERROR, "Unable to create outbound %.*s request to endpoint %s\n",
				(int) pj_strlen(&method->name), pj_strbuf(&method->name), ast_sorcery_object_get_id(endpoint_local));
		pjsip_endpt_release_pool(ast_sip_get_pjsip_endpoint(), pool);
		return -1;
	}

	//tdata->msg->body->content_type.type = STR_MIME_TYPE;
    //tdata->msg->body->content_type.subtype = STR_MIME_SUBTYPE;
    tdata->msg->body = gs_ldap_sync_build_xml(tdata->pool);
	print_tdata_buf(tdata);
	/* If an outbound proxy is specified on the endpoint apply it to this request */
	if (endpoint_local && !ast_strlen_zero(endpoint_local->outbound_proxy) &&
		ast_sip_set_outbound_proxy(tdata, endpoint_local->outbound_proxy)) {
		ast_log(LOG_ERROR, "Unable to apply outbound proxy on request %.*s to endpoint %s\n",
			(int) pj_strlen(&method->name), pj_strbuf(&method->name), ast_sorcery_object_get_id(endpoint_local));
		pjsip_endpt_release_pool(ast_sip_get_pjsip_endpoint(), pool);
		return -1;
	}

	ast_sip_mod_data_set(tdata->pool, tdata->mod_data, notify_module.id, "contact", ao2_bump(contact));

	/* We can release this pool since request creation copied all the necessary
	 * data into the outbound request's pool
	 */
	pjsip_endpt_release_pool(ast_sip_get_pjsip_endpoint(), pool);

	/* If an outbound proxy is specified set it on this request */
	// if (!ast_strlen_zero(contact->outbound_proxy) &&
	// 	ast_sip_set_outbound_proxy(tdata, contact->outbound_proxy)) {
	// 	pjsip_tx_data_dec_ref(tdata);
	// 	ast_log(LOG_ERROR, "Unable to apply outbound proxy on request to qualify contact %s\n",
	// 		contact->uri);
	// 	return -1;
	// }

	init_start_time(contact);

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

    tdata->msg->body = gs_ldap_sync_build_xml(tdata->pool);
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

static pj_bool_t notify_on_rx_request(pjsip_rx_data *rdata)
{
	ast_log(LOG_ERROR,"notify_on_rx_request\n");
	pjsip_event_hdr *event_header;
	char event[32];
	RAII_VAR(struct ast_sip_endpoint *, endpoint, NULL, ao2_cleanup);

	if (pjsip_method_cmp(&rdata->msg_info.msg->line.req.method, &pjsip_notify_method)) {
		return PJ_FALSE;
	}

	endpoint = ast_pjsip_rdata_get_endpoint(rdata);
	ast_assert(endpoint != NULL);

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

	char *aors;
	char *aor_name;

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
			//send_test_request(endpoint, contact);
			send_option(endpoint,contact);
		}

		ao2_ref(aor, -1);
	}

	return PJ_TRUE;
}

static int load_module(void)
{
	ast_log(LOG_ERROR, "1");
	CHECK_PJSIP_MODULE_LOADED();
	if (!(sched = ast_sched_context_create())) {
		ast_log(LOG_ERROR, "Could not create scheduler for publication expiration\n");
		return AST_MODULE_LOAD_FAILURE;
	}
	ast_log(LOG_ERROR, "2");
	if (ast_sched_start_thread(sched)) {
		ast_log(LOG_ERROR, "Could not start scheduler thread for publication expiration\n");
		ast_sched_context_destroy(sched);
		return AST_MODULE_LOAD_FAILURE;
	}
	ast_log(LOG_ERROR, "3");
	if (ast_sip_register_service(&notify_module)) {
		ast_log(LOG_ERROR, "Could not register notify service\n");
		ast_sched_context_destroy(sched);
		return AST_MODULE_LOAD_FAILURE;
	}
	ast_log(LOG_ERROR, "4");
	return AST_MODULE_LOAD_SUCCESS;
}

static int unload_module(void)
{
	if (sched) {
		ast_sched_context_destroy(sched);
	}

	return 0;
}

AST_MODULE_INFO(ASTERISK_GPL_KEY, AST_MODFLAG_LOAD_ORDER, "PJSIP sync LDAP",
		.load = load_module,
		.unload = unload_module,
		.load_pri = AST_MODPRI_APP_DEPEND,
);