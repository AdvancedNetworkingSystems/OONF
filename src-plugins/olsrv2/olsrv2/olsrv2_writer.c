
/*
 * The olsr.org Optimized Link-State Routing daemon version 2 (olsrd2)
 * Copyright (c) 2004-2015, the olsr.org team - see HISTORY file
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * * Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 * * Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in
 *   the documentation and/or other materials provided with the
 *   distribution.
 * * Neither the name of olsr.org, olsrd nor the names of its
 *   contributors may be used to endorse or promote products derived
 *   from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * Visit http://www.olsr.org for more information.
 *
 * If you find this software useful feel free to make a donation
 * to the project. For more information see the website or contact
 * the copyright holders.
 *
 */

/**
 * @file
 */

#include "common/avl.h"
#include "common/common_types.h"
#include "common/list.h"
#include "common/netaddr.h"
#include "core/oonf_logging.h"
#include "subsystems/oonf_class.h"
#include "subsystems/oonf_rfc5444.h"

#include "nhdp/nhdp_interfaces.h"
#include "nhdp/nhdp_db.h"
#include "nhdp/nhdp_domain.h"

#include "olsrv2/olsrv2.h"
#include "olsrv2/olsrv2_internal.h"
#include "olsrv2/olsrv2_lan.h"
#include "olsrv2/olsrv2_originator.h"
#include "olsrv2/olsrv2_routing.h"
#include "olsrv2/olsrv2_writer.h"

/* constants */

/**
 * olsrv2 index values for address tlvs
 */
enum olsrv2_addrtlv_idx {
  /*! index of neighbor address tlv */
  IDX_ADDRTLV_NBR_ADDR_TYPE,

  /*! index of destination specific gateway tlv */
  IDX_ADDRTLV_GATEWAY_DSTSPEC,

  /*! index of source specific gateway tlv */
  IDX_ADDRTLV_GATEWAY_SRCSPEC,

  /*! index of source specific default gateway tlv */
  IDX_ADDRTLV_GATEWAY_SRCSPEC_DEF,

  /*! index of source prefix tlv */
  IDX_ADDRTLV_GATEWAY_SRC_PREFIX,
};

/* Prototypes */
static void _send_tc(int af_type);
#if 0
static bool _cb_tc_interface_selector(struct rfc5444_writer *,
    struct rfc5444_writer_target *rfc5444_target, void *ptr);
#endif

static int _cb_addMessageHeader(
    struct rfc5444_writer *, struct rfc5444_writer_message *);
static void _cb_finishMessageHeader(struct rfc5444_writer *, struct rfc5444_writer_message *,
    struct rfc5444_writer_address *, struct rfc5444_writer_address *, bool);

static void _cb_addMessageTLVs(struct rfc5444_writer *);
static void _cb_addAddresses(struct rfc5444_writer *);
static void _cb_finishMessageTLVs(struct rfc5444_writer *,
  struct rfc5444_writer_address *start,
  struct rfc5444_writer_address *end, bool complete);

/* definition of NHDP writer */
static struct rfc5444_writer_message *_olsrv2_message = NULL;

static struct rfc5444_writer_content_provider _olsrv2_msgcontent_provider = {
  .msg_type = RFC7181_MSGTYPE_TC,
  .addMessageTLVs = _cb_addMessageTLVs,
  .addAddresses = _cb_addAddresses,
  .finishMessageTLVs = _cb_finishMessageTLVs,
};

static struct rfc5444_writer_tlvtype _olsrv2_addrtlvs[] = {
  [IDX_ADDRTLV_NBR_ADDR_TYPE]       = { .type = RFC7181_ADDRTLV_NBR_ADDR_TYPE },
  [IDX_ADDRTLV_GATEWAY_DSTSPEC]     = {
      .type = RFC7181_ADDRTLV_GATEWAY, .exttype = RFC7181_DSTSPEC_GATEWAY },
  [IDX_ADDRTLV_GATEWAY_SRCSPEC]     = {
      .type = RFC7181_ADDRTLV_GATEWAY, .exttype = RFC7181_SRCSPEC_GATEWAY },
  [IDX_ADDRTLV_GATEWAY_SRCSPEC_DEF] = {
      .type = RFC7181_ADDRTLV_GATEWAY, .exttype = RFC7181_SRCSPEC_DEF_GATEWAY },
  [IDX_ADDRTLV_GATEWAY_SRC_PREFIX] = {
      .type = SRCSPEC_GW_ADDRTLV_SRC_PREFIX },
};

static struct oonf_rfc5444_protocol *_protocol;

static bool _cleanedup = false;
static size_t _mprtypes_size;

/**
 * initialize olsrv2 writer
 * @param protocol rfc5444 protocol
 * @return -1 if an error happened, 0 otherwise
 */
int
olsrv2_writer_init(struct oonf_rfc5444_protocol *protocol) {
  _protocol = protocol;

  _olsrv2_message = rfc5444_writer_register_message(
      &_protocol->writer, RFC7181_MSGTYPE_TC, false);
  if (_olsrv2_message == NULL) {
    OONF_WARN(LOG_OLSRV2, "Could not register OLSRV2 TC message");
    return -1;
  }

  _olsrv2_message->addMessageHeader = _cb_addMessageHeader;
  _olsrv2_message->finishMessageHeader = _cb_finishMessageHeader;
  _olsrv2_message->forward_target_selector = nhdp_forwarding_selector;

  if (rfc5444_writer_register_msgcontentprovider(
      &_protocol->writer, &_olsrv2_msgcontent_provider,
      _olsrv2_addrtlvs, ARRAYSIZE(_olsrv2_addrtlvs))) {

    OONF_WARN(LOG_OLSRV2, "Count not register OLSRV2 msg contentprovider");
    rfc5444_writer_unregister_message(&_protocol->writer, _olsrv2_message);
    return -1;
  }

  return 0;
}

/**
 * Cleanup olsrv2 writer
 */
void
olsrv2_writer_cleanup(void) {
  _cleanedup = true;

  /* remove pbb writer */
  rfc5444_writer_unregister_content_provider(
      &_protocol->writer, &_olsrv2_msgcontent_provider,
      _olsrv2_addrtlvs, ARRAYSIZE(_olsrv2_addrtlvs));
  rfc5444_writer_unregister_message(&_protocol->writer, _olsrv2_message);
}

/**
 * Send a new TC message over all relevant interfaces
 */
void
olsrv2_writer_send_tc(void) {
  if (_cleanedup) {
    /* do not send more TCs during shutdown */
    return;
  }

  _send_tc(AF_INET);
  _send_tc(AF_INET6);
}

/**
 * Set a new forwarding selector for OLSRv2 TC messages
 * @param forward_target_selector pointer to forwarding selector
 *   callback, NULL for NHDP dualstack forwarding selector
 */
void
olsrv2_writer_set_forwarding_selector(
    bool (*forward_target_selector)(struct rfc5444_writer_target *,
      struct rfc5444_reader_tlvblock_context *context)) {
  if (forward_target_selector) {
    _olsrv2_message->forward_target_selector = forward_target_selector;
  }
  else {
    _olsrv2_message->forward_target_selector = nhdp_forwarding_selector;
  }
}

/**
 * Send a TC for a specified address family if the originator is set
 * @param af_type address family type
 */
static void
_send_tc(int af_type) {
  const struct netaddr *originator;

  originator = olsrv2_originator_get(af_type);
  if (netaddr_get_address_family(originator) == af_type) {
    OONF_INFO(LOG_OLSRV2_W, "Emit IPv%d TC message.", af_type == AF_INET ? 4 : 6);
    oonf_rfc5444_send_all(_protocol, RFC7181_MSGTYPE_TC,
        af_type == AF_INET ? 4 : 16, nhdp_flooding_selector);
  }
}

/**
 * Callback for rfc5444 writer to add message header for tc
 * @param writer RFC5444 writer instance
 * @param message RFC5444 message that is generated
 */
static int
_cb_addMessageHeader(struct rfc5444_writer *writer,
    struct rfc5444_writer_message *message) {
  const struct netaddr *orig;

  if (writer->msg_addr_len == 4) {
    orig = olsrv2_originator_get(AF_INET);
  }
  else {
    orig = olsrv2_originator_get(AF_INET6);
  }

  /* initialize message header */
  rfc5444_writer_set_msg_header(writer, message, true, true, true, true);
  rfc5444_writer_set_msg_originator(writer, message, netaddr_get_binptr(orig));
  rfc5444_writer_set_msg_hopcount(writer, message, 0);
  rfc5444_writer_set_msg_hoplimit(writer, message, 255);

  OONF_DEBUG(LOG_OLSRV2_W, "Generate TC");
  return RFC5444_OKAY;
}

static void
_cb_finishMessageHeader(struct rfc5444_writer *writer,
    struct rfc5444_writer_message *message,
    struct rfc5444_writer_address *first __attribute__((unused)),
    struct rfc5444_writer_address *last __attribute__((unused)),
    bool fragented __attribute__((unused))) {
  uint16_t seqno;

  seqno = oonf_rfc5444_get_next_message_seqno(_protocol);
  OONF_DEBUG(LOG_OLSRV2_W, "Set message sequence number to %u", seqno);
  rfc5444_writer_set_msg_seqno(writer, message, seqno);
}

/**
 * Callback for rfc5444 writer to add message tlvs to tc
 * @param writer RFC5444 writer instance
 */
static void
_cb_addMessageTLVs(struct rfc5444_writer *writer) {
  uint8_t vtime_encoded, itime_encoded;
  uint8_t mprtypes[NHDP_MAXIMUM_DOMAINS];

  /* generate validity time and interval time */
  itime_encoded = rfc5497_timetlv_encode(olsrv2_get_tc_interval());
  vtime_encoded = rfc5497_timetlv_encode(olsrv2_get_tc_validity());

  /* allocate space for ANSN tlv */
  rfc5444_writer_allocate_messagetlv(writer, true, 2);

  /* add validity and interval time TLV */
  rfc5444_writer_add_messagetlv(writer, RFC5497_MSGTLV_VALIDITY_TIME, 0,
      &vtime_encoded, sizeof(vtime_encoded));
  rfc5444_writer_add_messagetlv(writer, RFC5497_MSGTLV_INTERVAL_TIME, 0,
      &itime_encoded, sizeof(itime_encoded));

  /* generate mprtypes */
  _mprtypes_size = 0;
  if (nhdp_domain_get_count() > 1) {
    _mprtypes_size = nhdp_domain_encode_mprtypes_tlvvalue(mprtypes, sizeof(mprtypes));

    rfc5444_writer_add_messagetlv(writer,
        DRAFT_MT_MSGTLV_MPR_TYPES, DRAFT_MT_MSGTLV_MPR_TYPES_EXT,
        mprtypes, _mprtypes_size);
  }

  /* generate source-specific routing flag */
  if (os_routing_supports_source_specific(
      writer->msg_addr_len == 16 ? AF_INET6 : AF_INET)) {
    rfc5444_writer_add_messagetlv(writer,
        DRAFT_SSR_MSGTLV_CAPABILITY, DRAFT_SSR_MSGTLV_CAPABILITY_EXT,
        NULL, 0);
  }
}

static void
_generate_neighbor_metric_tlvs(struct rfc5444_writer *writer,
    struct rfc5444_writer_address *addr, struct nhdp_neighbor *neigh) {
  struct nhdp_neighbor_domaindata *neigh_domain;
  struct nhdp_domain *domain;
  uint32_t metric_in, metric_out;
  struct rfc7181_metric_field metric_in_encoded, metric_out_encoded;
  bool second_tlv;

  list_for_each_element(nhdp_domain_get_list(), domain, _node) {
    neigh_domain = nhdp_domain_get_neighbordata(domain, neigh);

    /* erase metric values */
    memset(&metric_in_encoded, 0, sizeof(metric_in_encoded));
    memset(&metric_out_encoded, 0, sizeof(metric_out_encoded));
    second_tlv = false;

    if (!nhdp_domain_get_neighbordata(domain, neigh)->local_is_mpr) {
      /* not an MPR, do not mention it in the TC */
      continue;
    }

    /* neighbor has selected us as an MPR */
    OONF_DEBUG(LOG_OLSRV2_W, "Neighbor is chosen by domain %u as MPR", domain->index);

    metric_in = neigh_domain->metric.in;
    if (metric_in > RFC7181_METRIC_MAX) {
      /* Metric value does not make sense */
      continue;
    }
    if (rfc7181_metric_encode(&metric_in_encoded, metric_in)) {
      OONF_DEBUG(LOG_OLSRV2_W, "Encoding of metric %u failed", metric_in);
      /* invalid incoming metric, do not mention it in the TC */
      continue;
    }

    /* set flag for incoming metric */
    rfc7181_metric_set_flag(&metric_in_encoded, RFC7181_LINKMETRIC_INCOMING_NEIGH);

    metric_out = neigh_domain->metric.out;
    if (rfc7181_metric_encode(&metric_out_encoded, metric_out)) {
      OONF_DEBUG(LOG_OLSRV2_W, "Encoding of metric %u failed", metric_in);
    }
    else if (memcmp(&metric_in_encoded, &metric_out_encoded, sizeof(metric_in_encoded)) == 0) {
      /* incoming and outgoing metric are the same */
      rfc7181_metric_set_flag(&metric_in_encoded, RFC7181_LINKMETRIC_OUTGOING_NEIGH);
    }
    else if (metric_out <= RFC7181_METRIC_MAX){
      /* two different link metrics */
      rfc7181_metric_set_flag(&metric_out_encoded, RFC7181_LINKMETRIC_OUTGOING_NEIGH);
      second_tlv = true;
    }

    OONF_DEBUG(LOG_OLSRV2_W, "Add Linkmetric (ext %u) TLV with value 0x%02x%02x",
        domain->ext, metric_in_encoded.b[0], metric_in_encoded.b[1]);
    rfc5444_writer_add_addrtlv(writer, addr, &domain->_metric_addrtlvs[0],
        &metric_in_encoded, sizeof(metric_in_encoded), true);

    if (second_tlv) {
      OONF_DEBUG(LOG_OLSRV2_W, "Add Linkmetric (ext %u) TLV with value 0x%02x%02x",
          domain->ext, metric_out_encoded.b[0], metric_out_encoded.b[1]);
      rfc5444_writer_add_addrtlv(writer, addr, &domain->_metric_addrtlvs[1],
          &metric_out_encoded, sizeof(metric_out_encoded), true);
    }
  }
}

/**
 * Callback for rfc5444 writer to add addresses and addresstlvs to tc
 * @param writer RFC5444 writer instance
 */
static void
_cb_addAddresses(struct rfc5444_writer *writer) {
  struct rfc5444_writer_address *addr;
  struct nhdp_neighbor *neigh;
  struct nhdp_naddr *naddr;
  struct nhdp_domain *domain;
  struct olsrv2_lan_entry *lan;
  struct olsrv2_lan_domaindata *lan_data;
  bool any_advertised;
  uint8_t nbr_addrtype_value;
  uint32_t metric_out;
  struct rfc7181_metric_field metric_out_encoded;
  uint8_t distance_vector[NHDP_MAXIMUM_DOMAINS];
  int af_type;
  enum olsrv2_addrtlv_idx gateway_idx;
  uint8_t srcprefix[17];
#ifdef OONF_LOG_DEBUG_INFO
  struct netaddr_str nbuf1, nbuf2;
#endif

  af_type = writer->msg_addr_len == 4 ? AF_INET : AF_INET6;

  /* iterate over neighbors */
  list_for_each_element(nhdp_db_get_neigh_list(), neigh, _global_node) {
    any_advertised = false;

    if (!neigh->symmetric) {
      /* do not announce non-symmetric neighbors */
      continue;
    }

    /* see if we have been selected as a MPR by this neighbor */
    list_for_each_element(nhdp_domain_get_list(), domain, _node) {
      if (nhdp_domain_get_neighbordata(domain, neigh)->local_is_mpr) {
        /* found one */
        any_advertised = true;
        break;
      }
    }

    if (!any_advertised) {
      /* we are not a MPR for this neighbor, so we don't advertise the neighbor */
      continue;
    }

    /* iterate over neighbors addresses */
    avl_for_each_element(&neigh->_neigh_addresses, naddr, _neigh_node) {
      if (netaddr_get_address_family(&naddr->neigh_addr) != af_type) {
        /* wrong address family, skip this one */
        continue;
      }

      if (!olsrv2_is_nhdp_routable(&naddr->neigh_addr)
          && netaddr_cmp(&neigh->originator, &naddr->neigh_addr) != 0) {
        /* do not propagate unroutable addresses in TCs */
        continue;
      }

      nbr_addrtype_value = 0;

      if (olsrv2_is_routable(&naddr->neigh_addr)) {
        nbr_addrtype_value |= RFC7181_NBR_ADDR_TYPE_ROUTABLE;
      }
      if (netaddr_cmp(&neigh->originator, &naddr->neigh_addr) == 0) {
        nbr_addrtype_value |= RFC7181_NBR_ADDR_TYPE_ORIGINATOR;
      }

      if (nbr_addrtype_value == 0) {
        /* skip this address */
        OONF_DEBUG(LOG_OLSRV2_W, "Address %s is neither routable"
            " nor an originator", netaddr_to_string(&nbuf1, &naddr->neigh_addr));
        continue;
      }

      OONF_DEBUG(LOG_OLSRV2_W, "Add address %s to TC",
          netaddr_to_string(&nbuf1, &naddr->neigh_addr));
      addr = rfc5444_writer_add_address(writer, _olsrv2_msgcontent_provider.creator,
          &naddr->neigh_addr, false);
      if (addr == NULL) {
        OONF_WARN(LOG_OLSRV2_W, "Out of memory error for olsrv2 address");
        return;
      }

      /* add neighbor type TLV */
      OONF_DEBUG(LOG_OLSRV2_W, "Add NBRAddrType TLV with value %u", nbr_addrtype_value);
      rfc5444_writer_add_addrtlv(writer, addr, &_olsrv2_addrtlvs[IDX_ADDRTLV_NBR_ADDR_TYPE],
          &nbr_addrtype_value, sizeof(nbr_addrtype_value), false);

      /* add linkmetric TLVs */
      _generate_neighbor_metric_tlvs(writer, addr, neigh);
    }
  }

  /* Iterate over locally attached networks */
  avl_for_each_element(olsrv2_lan_get_tree(), lan, _node) {
    if (netaddr_get_address_family(&lan->prefix.dst) != af_type) {
      /* wrong address family */
      continue;
    }

    OONF_DEBUG(LOG_OLSRV2_W, "Add address %s [%s] to TC",
        netaddr_to_string(&nbuf1, &lan->prefix.dst),
        netaddr_to_string(&nbuf2, &lan->prefix.src));

    if (netaddr_get_prefix_length(&lan->prefix.dst) > 0
        || netaddr_get_prefix_length(&lan->prefix.src) == 0) {
      addr = rfc5444_writer_add_address(writer, _olsrv2_msgcontent_provider.creator,
          &lan->prefix.dst, false);

      if (netaddr_get_prefix_length(&lan->prefix.src) == 0) {
        gateway_idx = IDX_ADDRTLV_GATEWAY_DSTSPEC;
      }
      else {
        gateway_idx = IDX_ADDRTLV_GATEWAY_SRCSPEC;
      }
    }
    else {
      addr = rfc5444_writer_add_address(writer, _olsrv2_msgcontent_provider.creator,
          &lan->prefix.src, false);
      gateway_idx = IDX_ADDRTLV_GATEWAY_SRCSPEC_DEF;
    }
    if (addr == NULL) {
      OONF_WARN(LOG_OLSRV2_W, "Out of memory error for olsrv2 address");
      return;
    }

    /* add Gateway TLV and Metric TLV */
    memset(distance_vector, 0, sizeof(distance_vector));

    list_for_each_element(nhdp_domain_get_list(), domain, _node) {
      lan_data = olsrv2_lan_get_domaindata(domain, lan);
      metric_out = lan_data->outgoing_metric;
      if (metric_out > RFC7181_METRIC_MAX) {
        /* metric value does not make sense */
        continue;
      }

      if (rfc7181_metric_encode(&metric_out_encoded, metric_out)) {
        OONF_WARN(LOG_OLSRV2_W, "Encoding of metric %u failed", metric_out);
        continue;
      }
      rfc7181_metric_set_flag(&metric_out_encoded, RFC7181_LINKMETRIC_OUTGOING_NEIGH);

      /* add Metric TLV */
      OONF_DEBUG(LOG_OLSRV2_W, "Add Linkmetric (ext %u) TLV with value 0x%02x%02x (%u)",
          domain->ext, metric_out_encoded.b[0], metric_out_encoded.b[1], metric_out);
      rfc5444_writer_add_addrtlv(writer, addr, &domain->_metric_addrtlvs[0],
          &metric_out_encoded, sizeof(metric_out_encoded), false);

      OONF_DEBUG(LOG_OLSRV2_W, "Gateway (ext %u) has hopcount cost %u",
          domain->ext, lan_data->distance);
      distance_vector[domain->index] = lan_data->distance;
    }

    /* add Gateway TLV */
    if (!lan->same_distance) {
      rfc5444_writer_add_addrtlv(writer, addr, &_olsrv2_addrtlvs[gateway_idx],
          distance_vector, _mprtypes_size, false);
    }
    else {
      rfc5444_writer_add_addrtlv(writer, addr, &_olsrv2_addrtlvs[gateway_idx],
          distance_vector, 1, false);
    }

    if (gateway_idx == IDX_ADDRTLV_GATEWAY_SRCSPEC) {
      /* add Src Prefix TLV */
      srcprefix[0] = netaddr_get_prefix_length(&lan->prefix.src);
      memcpy(&srcprefix[1], netaddr_get_binptr(&lan->prefix.src),
          netaddr_get_binlength(&lan->prefix.src));

      rfc5444_writer_add_addrtlv(writer, addr,
          &_olsrv2_addrtlvs[IDX_ADDRTLV_GATEWAY_SRC_PREFIX],
          srcprefix, 1 + (netaddr_get_prefix_length(&lan->prefix.src) + 7)/8, false);
    }
  }
}

/**
 * Callback triggered when tc is finished.
 * @param writer RFC5444 writer instance
 * @param start first address contained in generated message
 * @param end last address contained in generated message
 * @param complete true if all addresses are in message, false otherwise
 */
static void
_cb_finishMessageTLVs(struct rfc5444_writer *writer,
    struct rfc5444_writer_address *start __attribute__((unused)),
    struct rfc5444_writer_address *end __attribute__((unused)),
    bool complete) {
  uint16_t ansn;

  /* get ANSN */
  ansn = htons(olsrv2_routing_get_ansn());

  rfc5444_writer_set_messagetlv(writer, RFC7181_MSGTLV_CONT_SEQ_NUM,
      complete ? RFC7181_CONT_SEQ_NUM_COMPLETE : RFC7181_CONT_SEQ_NUM_INCOMPLETE,
      &ansn, sizeof(ansn));
}
