/* Behavioral spec for NanoMQ MQTT SUBSCRIBE parsing.
 *
 * A SUBSCRIBE entry that omits its final options byte must be rejected, and
 * the topic must not be recorded. These checks fail on the broker declared
 * by ../build/Dockerfile until that parser is fixed.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <nng/nng.h>
#include <nng/mqtt/mqtt_client.h>
#include <nng/protocol/mqtt/mqtt_parser.h>

#include "core/list.h"

#include "include/broker.h"
#include "include/sub_handler.h"

/* Same layout as struct subinfo in NanoNNG src/core/sockimpl.h.
 * The list offset has to match the object nmq_subinfo_decode appends. */
struct subinfo {
	uint8_t       qos : 2;
	uint8_t       no_local : 1;
	uint8_t       rap : 1;
	uint8_t       retain_handling : 2;
	char         *topic;
	int           subid;
	nni_list_node node;
};

static int
subinfo_has(nni_list *subs, const char *topic)
{
	struct subinfo *sn;

	NNI_LIST_FOREACH (subs, sn) {
		if (sn->topic != NULL && strcmp(sn->topic, topic) == 0) {
			return 1;
		}
	}
	return 0;
}

static void
fill_body(uint8_t *body, size_t body_len, int version, const char *topic,
    int with_options)
{
	size_t topic_len = strlen(topic);
	size_t need;

	memset(body, 0, body_len);
	body[0] = 0x00;
	body[1] = 0x01;
	if (version == MQTT_PROTOCOL_VERSION_v5) {
		body[2] = 0x00;
		body[3] = (uint8_t) ((topic_len >> 8) & 0xff);
		body[4] = (uint8_t) (topic_len & 0xff);
		memcpy(body + 5, topic, topic_len);
		need = 5 + topic_len + (with_options ? 1 : 0);
	} else {
		body[2] = (uint8_t) ((topic_len >> 8) & 0xff);
		body[3] = (uint8_t) (topic_len & 0xff);
		memcpy(body + 4, topic, topic_len);
		need = 4 + topic_len + (with_options ? 1 : 0);
	}
	if (need != body_len) {
		fprintf(stderr, "body length %zu does not match constructed %zu\n",
		    body_len, need);
		exit(2);
	}
	if (with_options) {
		body[body_len - 1] = 0x00;
	}
}

static nng_msg *
message_with_body(size_t body_len, int version, const char *topic, int with_options)
{
	nng_msg *msg = NULL;
	uint8_t *body;

	if (nng_msg_alloc(&msg, body_len) != 0) {
		fprintf(stderr, "nng_msg_alloc failed\n");
		exit(2);
	}
	body = nng_msg_body(msg);
	fill_body(body, body_len, version, topic, with_options);
	nng_msg_set_remaining_len(msg, body_len);
	nng_msg_set_cmd_type(msg, 0x80);
	return msg;
}

static int
run_subinfo(size_t body_len, int version, const char *topic, int with_options,
    int expect_accept)
{
	nng_msg *msg = message_with_body(body_len, version, topic, with_options);
	nni_list subs;
	int      rv;
	int      installed;

	NNI_LIST_INIT(&subs, struct subinfo, node);
	rv        = nmq_subinfo_decode(msg, &subs, (uint8_t) version);
	installed = subinfo_has(&subs, topic);
	fprintf(stderr, "nmq_subinfo_decode rv=%d installed=%d accept_expected=%d\n",
	    rv, installed, expect_accept);
	if (expect_accept) {
		return (rv >= 0 && installed) ? 0 : 1;
	}
	/* Rejected means a negative result and no recorded topic.
	 * Recording the topic and then returning an error is still a failure. */
	return (rv < 0 && !installed) ? 0 : 1;
}

static int
run_decode_sub(size_t body_len, int version, const char *topic, int with_options,
    int expect_accept)
{
	nng_msg  *msg = message_with_body(body_len, version, topic, with_options);
	nano_work work;
	uint8_t  *body = nng_msg_body(msg);
	int       rv;
	int       recorded;

	memset(&work, 0, sizeof(work));
	work.proto_ver = (uint8_t) version;
	work.msg       = msg;
	work.sub_pkt   = calloc(1, sizeof(packet_subscribe));
	if (work.sub_pkt == NULL) {
		return 2;
	}
	if (version == MQTT_PROTOCOL_VERSION_v5) {
		nng_msg_set_payload_ptr(msg, body + 3);
	} else {
		nng_msg_set_payload_ptr(msg, body + 2);
	}
	rv = decode_sub_msg(&work);
	recorded =
	    work.sub_pkt->node != NULL && work.sub_pkt->node->topic.body != NULL;
	fprintf(stderr, "decode_sub_msg rv=%d recorded=%d accept_expected=%d\n",
	    rv, recorded, expect_accept);
	if (expect_accept) {
		return (rv == 0 && recorded) ? 0 : 1;
	}
	return (rv != 0 && !recorded) ? 0 : 1;
}

int
main(int argc, char **argv)
{
	const char *mode;
	size_t      exact = 1024;
	size_t      v5_topic_len;
	size_t      v3_topic_len;

	if (argc != 2) {
		fprintf(stderr, "usage: %s <mode>\n", argv[0]);
		return 2;
	}
	mode = argv[1];

	/* v5 body: packet id, property length, topic length, topic, optional byte. */
	v5_topic_len = exact - 5;
	v3_topic_len = exact - 4;

	if (strcmp(mode, "subinfo-v5-valid") == 0) {
		return run_subinfo(2 + 1 + 2 + 1 + 1, MQTT_PROTOCOL_VERSION_v5, "t",
		    1, 1);
	}
	if (strcmp(mode, "subinfo-v5-missing") == 0) {
		return run_subinfo(2 + 1 + 2 + 1, MQTT_PROTOCOL_VERSION_v5, "t", 0,
		    0);
	}
	if (strcmp(mode, "subinfo-v311-missing") == 0) {
		return run_subinfo(2 + 2 + 1, MQTT_PROTOCOL_VERSION_v311, "t", 0, 0);
	}
	if (strcmp(mode, "subinfo-v5-exact") == 0) {
		char *long_topic = malloc(v5_topic_len + 1);
		int   rc;
		if (long_topic == NULL) {
			return 2;
		}
		memset(long_topic, 'a', v5_topic_len);
		long_topic[v5_topic_len] = '\0';
		rc = run_subinfo(exact, MQTT_PROTOCOL_VERSION_v5, long_topic, 0, 0);
		free(long_topic);
		return rc;
	}
	if (strcmp(mode, "decode-v5-valid") == 0) {
		return run_decode_sub(2 + 1 + 2 + 1 + 1, MQTT_PROTOCOL_VERSION_v5,
		    "t", 1, 1);
	}
	if (strcmp(mode, "decode-v5-missing") == 0) {
		return run_decode_sub(
		    2 + 1 + 2 + 1, MQTT_PROTOCOL_VERSION_v5, "t", 0, 0);
	}
	if (strcmp(mode, "decode-v311-missing") == 0) {
		return run_decode_sub(
		    2 + 2 + 1, MQTT_PROTOCOL_VERSION_v311, "t", 0, 0);
	}
	if (strcmp(mode, "decode-v5-exact") == 0) {
		char *long_topic = malloc(v5_topic_len + 1);
		int   rc;
		if (long_topic == NULL) {
			return 2;
		}
		memset(long_topic, 'b', v5_topic_len);
		long_topic[v5_topic_len] = '\0';
		rc = run_decode_sub(
		    exact, MQTT_PROTOCOL_VERSION_v5, long_topic, 0, 0);
		free(long_topic);
		return rc;
	}
	if (strcmp(mode, "subinfo-v311-exact") == 0) {
		char *long_topic = malloc(v3_topic_len + 1);
		int   rc;
		if (long_topic == NULL) {
			return 2;
		}
		memset(long_topic, 'c', v3_topic_len);
		long_topic[v3_topic_len] = '\0';
		rc = run_subinfo(
		    exact, MQTT_PROTOCOL_VERSION_v311, long_topic, 0, 0);
		free(long_topic);
		return rc;
	}

	fprintf(stderr, "unknown mode %s\n", mode);
	return 2;
}
