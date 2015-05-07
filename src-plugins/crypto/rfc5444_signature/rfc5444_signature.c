
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

#include "common/common_types.h"
#include "common/avl.h"
#include "common/avl_comp.h"
#include "core/oonf_subsystem.h"
#include "subsystems/oonf_rfc5444.h"
#include "subsystems/rfc5444/rfc5444_reader.h"
#include "subsystems/rfc5444/rfc5444_writer.h"

#include "rfc5444_signature/rfc5444_signature.h"

#define LOG_RFC5444_SIG _rfc5444_sig_subsystem.logging

/* prototypes */
static int _init(void);
static void _cleanup(void);
static enum rfc5444_result _cb_signature_tlv(struct rfc5444_reader_tlvblock_context *context);
static int _cb_add_signature(struct rfc5444_writer_postprocessor *processor,
    struct rfc5444_writer_target *target, struct rfc5444_writer_message *msg,
    uint8_t *data, size_t *data_size);

static size_t _remove_signature_data(uint8_t *dst,
    const struct rfc5444_reader_tlvblock_context *context);
static void _handle_postprocessors(void);

static int _avl_cmp_signatures(const void *, const void *);
static const void *_cb_get_empty_keyid(
    struct rfc5444_signature *sig, size_t *len);
static enum rfc5444_sigid_check _cb_sigid_okay(
    struct rfc5444_signature *sig, const void *id, size_t len);

static bool _cb_is_matching_signature(
    struct rfc5444_writer_postprocessor *processor, int msg_type);
static int _cb_identity_hash(struct rfc5444_signature *sigdata,
    void *dst, size_t *dst_len, const void *src, size_t src_len);
static int _cb_identity_crypt(struct rfc5444_signature *sigdata,
    void *dst, size_t *dst_len, const void *src, size_t src_len);
static bool _cb_check_by_crypt(struct rfc5444_signature *sigdata,
    const void *encrypted, size_t encrypted_length,
    const void *hash, size_t hash_len);

/* plugin declaration */
static const char *_dependencies[] = {
  OONF_RFC5444_SUBSYSTEM,
};
static struct oonf_subsystem _rfc5444_sig_subsystem = {
  .name = OONF_RFC5444_SIG_SUBSYSTEM,
  .dependencies = _dependencies,
  .dependencies_count = ARRAYSIZE(_dependencies),
  .descr = "OONF rfc5444 signature plugin",
  .author = "Henning Rogge",

  .init = _init,
  .cleanup = _cleanup,
};
DECLARE_OONF_PLUGIN(_rfc5444_sig_subsystem);

/* tlvblock consumer for signature TLVs */
static struct rfc5444_reader_tlvblock_consumer _signature_msg_consumer = {
  .order = RFC5444_VALIDATOR_PRIORITY,
  .default_msg_consumer = true,

  .block_callback = _cb_signature_tlv,
};

static struct rfc5444_reader_tlvblock_consumer _signature_pkt_consumer = {
  .order = RFC5444_VALIDATOR_PRIORITY,
  .block_callback = _cb_signature_tlv,
};

static struct rfc5444_reader_tlvblock_consumer_entry _pkt_signature_tlv = {
  .type = RFC7182_PKTTLV_ICV,
};

static struct rfc5444_reader_tlvblock_consumer_entry _msg_signature_tlv = {
  .type = RFC7182_MSGTLV_ICV,
};

static struct oonf_rfc5444_protocol *_protocol;

/* identity hash/crypt function */
struct rfc5444_sig_hash _identity_hash = {
  .type = RFC7182_ICV_HASH_IDENTITY,
  .hash = _cb_identity_hash,
};

struct rfc5444_sig_crypt _identity_crypt = {
  .type = RFC7182_ICV_CRYPT_IDENTITY,
  .crypt = _cb_identity_crypt,
};

/* tree of hash/crypt functions */
static struct avl_tree _crypt_functions;
static struct avl_tree _hash_functions;

/* tree of registered signatures */
static struct avl_tree _sig_tree;

/* static buffer for signature calculation */
static uint8_t _static_message_buffer[RFC5444_MAX_PACKET_SIZE];
static uint8_t _crypt_buffer[RFC5444_MAX_PACKET_SIZE];

/**
 * Constructor of subsystem
 * @return -1 if rfc5444 protocol was not available, 0 otherwise
 */
static int
_init(void) {
   _protocol = oonf_rfc5444_add_protocol(RFC5444_PROTOCOL, true);
  if (_protocol == NULL) {
    return -1;
  }

  rfc5444_reader_add_message_consumer(&_protocol->reader,
      &_signature_msg_consumer, &_msg_signature_tlv, 1);
  rfc5444_reader_add_packet_consumer(&_protocol->reader,
      &_signature_pkt_consumer, &_pkt_signature_tlv, 1);
  avl_init(&_crypt_functions, avl_comp_uint8, false);
  avl_init(&_hash_functions, avl_comp_uint8, false);
  avl_init(&_sig_tree, _avl_cmp_signatures, true);

  rfc5444_sig_add_hash(&_identity_hash);
  rfc5444_sig_add_crypt(&_identity_crypt);

  // install();
  return 0;
}

/**
 * Destructor of subsystem
 */
static void
_cleanup(void) {
  struct rfc5444_sig_hash *hash, *hash_it;
  struct rfc5444_sig_crypt *crypt, *crypt_it;
  struct rfc5444_signature *sig, *sig_it;

  avl_for_each_element_safe(&_hash_functions, hash, _node, hash_it) {
    rfc5444_sig_remove_hash(hash);
  }
  avl_for_each_element_safe(&_crypt_functions, crypt, _node, crypt_it) {
    rfc5444_sig_remove_crypt(crypt);
  }
  avl_for_each_element_safe(&_sig_tree, sig, _node, sig_it) {
    rfc5444_sig_remove(sig);
  }

  rfc5444_reader_remove_message_consumer(
      &_protocol->reader, &_signature_msg_consumer);
  rfc5444_reader_remove_packet_consumer(
      &_protocol->reader, &_signature_pkt_consumer);
  oonf_rfc5444_remove_protocol(_protocol);
}

/**
 * Register a hash function to the signature API
 * @param hash pointer to hash definition
 */
void
rfc5444_sig_add_hash(struct rfc5444_sig_hash *hash) {
  /* hook key into avl node */
  hash->_node.key = &hash->type;

  /* hook hash into hash tree */
  avl_insert(&_hash_functions, &hash->_node);

  /* see if someone needs this hash-function */
  _handle_postprocessors();
}

/**
 * Remove hash function from signature API
 * @param hash pointer to hash definition
 */
void
rfc5444_sig_remove_hash(struct rfc5444_sig_hash *hash) {
  avl_remove(&_hash_functions, &hash->_node);
  _handle_postprocessors();
}

/**
 * Add a crypto function to the signature API
 * @param crypt pointer to signature definition
 */
void
rfc5444_sig_add_crypt(struct rfc5444_sig_crypt *crypt) {
  /* hook key into avl node */
  crypt->_node.key = &crypt->type;

  /* use default checker if necessary */
  if (!crypt->check) {
    crypt->check = _cb_check_by_crypt;
  }

  /* hook crypt function into crypt tree */
  avl_insert(&_crypt_functions, &crypt->_node);

  /* see if someone needs this crypto-function */
  _handle_postprocessors();
}

/**
 * Remove a crypto function from the signature API
 * @param crypt pointer to signature definition
 */
void
rfc5444_sig_remove_crypt(struct rfc5444_sig_crypt *crypt) {
  avl_remove(&_crypt_functions, &crypt->_node);
  _handle_postprocessors();
}

/**
 * Add a message signature
 * @param sig pointer to signature definition
 */
void
rfc5444_sig_add(struct rfc5444_signature *sig) {
  sig->_node.key = &sig->key;

  if (sig->verify_id == NULL) {
    sig->verify_id = _cb_sigid_okay;
  }
  if (sig->getKeyId == NULL) {
    sig->getKeyId = _cb_get_empty_keyid;
  }

  avl_insert(&_sig_tree, &sig->_node);

  /* initialize postprocessor */
  sig->_postprocessor.priority = 0;
  sig->_postprocessor.process = _cb_add_signature;
  sig->_postprocessor.is_matching_signature = _cb_is_matching_signature;

  _handle_postprocessors();
}

/**
 * Remove a signature
 * @param sig pointer to signature definition
 */
void
rfc5444_sig_remove(struct rfc5444_signature *sig) {
  rfc5444_writer_unregister_postprocessor(
      &_protocol->writer, &sig->_postprocessor);
  avl_remove(&_sig_tree, &sig->_node);
}

/**
 * Callback for checking both message and packet signature TLVs
 * @param context rfc5444 TLV context
 * @return okay or drop
 */
static enum rfc5444_result
_cb_signature_tlv(struct rfc5444_reader_tlvblock_context *context) {
  struct rfc5444_reader_tlvblock_consumer_entry *sig_tlv;
  struct rfc5444_reader_tlvblock_entry *tlv;
  struct rfc5444_signature *sig, *sigstart;
  struct rfc5444_signature_key sigkey;
  enum rfc5444_sigid_check check;
  enum rfc5444_result drop_value;
  int msg_type;
  uint8_t key_id_len;
  uint8_t *static_data;
  size_t static_length;
  bool sig_to_verify;

  if (context->type == RFC5444_CONTEXT_PACKET) {
    msg_type = RFC5444_WRITER_PKT_POSTPROCESSOR;
    drop_value = RFC5444_DROP_PACKET;
    sig_tlv = &_pkt_signature_tlv;
  }
  else {
    msg_type = context->msg_type;
    drop_value = RFC5444_DROP_MESSAGE;
    sig_tlv = &_msg_signature_tlv;
  }

  /* initialize verification fields */
  sig_to_verify = false;
  avl_for_each_element(&_sig_tree, sig, _node) {
    bool match = sig->is_matching_signature(sig, msg_type);

    sig->_must_be_verified = sig->drop_if_invalid && match;
    sig->verified = false;

    sig_to_verify |= match;
  }

  if (!sig_to_verify) {
    /* nothing to do, no matching signature */
    return RFC5444_OKAY;
  }

  OONF_DEBUG(LOG_RFC5444_SIG,
      "Start checking signature for message type %d", msg_type);

  for (tlv = sig_tlv->tlv; tlv; tlv = tlv->next_entry) {
    if (tlv->type_ext != RFC7182_ICV_EXT_CRYPTHASH
        && tlv->type_ext != RFC7182_ICV_EXT_SRCSPEC_CRYPTHASH) {
      /* unknown subtype, just ignore */
      OONF_INFO(LOG_RFC5444_SIG, "Signature with unknown ext-type: %u",
          tlv->type_ext);
      continue;
    }
    if (tlv->length < 4) {
      /* not enough bytes for valid signature */
      OONF_INFO(LOG_RFC5444_SIG, "Signature tlv too short: %u bytes",
          tlv->length);
      continue;
    }

    sigkey.hash_function = tlv->single_value[0];
    sigkey.crypt_function = tlv->single_value[1];
    key_id_len = tlv->single_value[2];

    if (tlv->length <= 3 + key_id_len) {
      /* not enough bytes for valid signature */
      OONF_INFO_HEX(LOG_RFC5444_SIG, tlv->single_value, tlv->length,
          "Signature tlv %u/%u too short: %u bytes",
          tlv->single_value[0], tlv->single_value[1], tlv->length);
      continue;
    }

    /* assemble static message buffer */
    if (tlv->type_ext == RFC7182_ICV_EXT_SRCSPEC_CRYPTHASH) {
      struct netaddr_str nbuf;
      OONF_DEBUG(LOG_RFC5444_SIG, "incoming src IP: %s",
          netaddr_to_string(&nbuf, _protocol->input_address));

      /* copy source address into buffer */
      netaddr_to_binary(_static_message_buffer, _protocol->input_address,
          sizeof(_static_message_buffer));
      static_length = netaddr_get_binlength(_protocol->input_address);
    }
    else {
      static_length = 0;
    }
    memcpy(&_static_message_buffer[static_length], tlv->single_value,
        3 + key_id_len);
    static_length += 3 + key_id_len;

    static_data = &_static_message_buffer[static_length];
    static_length += _remove_signature_data(static_data, context);

    /* loop over all possible signatures */
    avl_for_each_elements_with_key(&_sig_tree, sig, _node, sigstart, &sigkey) {
      if (!sig->is_matching_signature(sig, msg_type)) {
        /* signature doesn't apply to this message type */
        continue;
      }

      if ((tlv->type_ext == RFC7182_ICV_EXT_SRCSPEC_CRYPTHASH) != sig->source_specific) {
        OONF_INFO(LOG_RFC5444_SIG, "Signature extension %u does not match", tlv->type_ext);
        continue;
      }

      /* see how signature want to handle the incoming key id */
      check = sig->verify_id(sig, &tlv->single_value[3], key_id_len);
      if (check == RFC5444_SIGID_IGNORE) {
        /* signature wants to ignore this TLV */
        continue;
       }
      if (check == RFC5444_SIGID_DROP) {
        /* signature wants us to drop this context */
        OONF_INFO(LOG_RFC5444_SIG, "Dropped message because of wrong key-id");
        return drop_value;
      }

      /* remember source IP */
      sig->source = _protocol->input_address;

      /* check signature */
      sig->verified = sig->crypt->check(sig, &tlv->single_value[3+key_id_len],
            tlv->length - 3 - key_id_len, _static_message_buffer, static_length);

      OONF_DEBUG(LOG_RFC5444_SIG, "Checked signature hash=%d/crypt=%d: %s",
          sig->key.hash_function, sig->key.crypt_function, sig->verified ? "check" : "bad");
    }
  }

  /* check if mandatory signatures are missing or failed*/
  avl_for_each_element(&_sig_tree, sig, _node) {
    if (!sig->verified && sig->_must_be_verified) {
      OONF_INFO(LOG_RFC5444_SIG, "Dropped %s because bad/missing signature",
          msg_type == RFC5444_WRITER_PKT_POSTPROCESSOR ? "packet" : "message");
      return drop_value;
    }
  }

  if (sig_to_verify) {
    OONF_INFO(LOG_RFC5444_SIG, "%s signature valid!",
        msg_type == RFC5444_WRITER_PKT_POSTPROCESSOR ? "packet" : "message");
  }
  return RFC5444_OKAY;
}

/**
 * Post processor to add a packet signature
 * @param processor rfc5444 post-processor
 * @param target rfc5444 target
 * @param msg rfc5444 message, NULL for packet signature
 * @param data pointer to binary data
 * @param length pointer to length of binary data, will be overwritten by function
 * @return -1 if an error happened, 0 otherwise
 */
static int
_cb_add_signature(struct rfc5444_writer_postprocessor *processor,
    struct rfc5444_writer_target *target, struct rfc5444_writer_message *msg,
    uint8_t *data, size_t *data_size) {
  struct rfc5444_signature *sig;
  struct oonf_rfc5444_target *oonf_target;
  const union netaddr_socket *local_socket;
  struct netaddr srcaddr;

  int hash_buffer_size, sig_size, sig_tlv_size, tlvblock_size;
  uint8_t *tlvblock;
  int idx;

  size_t crypt_len;

  const void *key_id;
  size_t key_id_length;

  sig = container_of(processor, struct rfc5444_signature, _postprocessor);

  if (!msg) {
    OONF_INFO(LOG_RFC5444_SIG, "Add signature data to packet");
  }
  else {
    OONF_INFO(LOG_RFC5444_SIG, "Add signature data to message %u",
        msg->type);
  }
  oonf_target = oonf_rfc5444_get_target_from_rfc5444_target(target);

  /*
   * copy data into static buffer, leave space in front
   * for source address and signature data
   */
  if (sig->source_specific) {
    struct netaddr_str nbuf;
    local_socket = oonf_rfc5444_target_get_local_socket(oonf_target);
    if (netaddr_from_socket(&srcaddr, local_socket)) {
      return -1;
    }
    OONF_DEBUG(LOG_RFC5444_SIG, "outgoing src IP: %s",
        netaddr_to_string(&nbuf, &srcaddr));

    netaddr_to_binary(_static_message_buffer, &srcaddr, sizeof(_static_message_buffer));
    idx = netaddr_get_binlength(&srcaddr);
  }
  else {
    idx = 0;
  }

  key_id_length = 0;
  key_id = sig->getKeyId(sig, &key_id_length);

  _static_message_buffer[idx++] = sig->key.hash_function;
  _static_message_buffer[idx++] = sig->key.crypt_function;
  _static_message_buffer[idx++] = key_id_length;
  memcpy(&_static_message_buffer[idx], key_id, key_id_length);
  idx += key_id_length;
  hash_buffer_size = idx + *data_size;

  if (msg) {
    /* just copy message data, it always has a TLV block */
    memcpy(&_static_message_buffer[idx], data, *data_size);

    /*
     * get pointer to message tlvblock
     * zero hoplimit/hopcount in static buffer
     */
    idx += 4;
    tlvblock = &data[4];
    if (msg->has_origaddr) {
      idx += msg->addr_len;
      tlvblock += msg->addr_len;
    }
    if (msg->has_hoplimit) {
      _static_message_buffer[idx++] = 0;
      tlvblock++;
    }
    if (msg->has_hopcount) {
      _static_message_buffer[idx++] = 0;
      tlvblock++;
    }
    if (msg->has_seqno) {
      idx+=2;
      tlvblock+=2;
    }
  }
  else {
    /* just copy packet for hashing */
    memcpy(&_static_message_buffer[idx], data, *data_size);

    if (data[0] & RFC5444_PKT_FLAG_SEQNO) {
      tlvblock = &data[3];
    }
    else {
      tlvblock = &data[1];
    }
  }

  /* calculate encrypted hash value */
  crypt_len = sizeof(_crypt_buffer);
  if (sig->crypt->crypt(sig, _crypt_buffer, &crypt_len, _static_message_buffer, hash_buffer_size)) {
    OONF_WARN(LOG_RFC5444_SIG, "Signature generation failed");
    return -1;
  }

  if (crypt_len > sig->crypt->getSize(sig)) {
    OONF_WARN(LOG_RFC5444_SIG, "Signature too long: "
        "%"PRINTF_SIZE_T_SPECIFIER" > %"PRINTF_SIZE_T_SPECIFIER,
        crypt_len, sig->crypt->getSize(sig));
    return -1;
  }

  /* calulate signature size */
  sig_size = 3 + key_id_length + crypt_len;

  /* tlv with type extension and (extended) value */
  sig_tlv_size = 4 + sig_size;
  if (sig_size > 255) {
    sig_tlv_size ++;
  }

  if (msg == NULL && (data[0] & RFC5444_PKT_FLAG_TLV) == 0) {
    /* mark packet as "has tlv" */
    data[0] |= RFC5444_PKT_FLAG_TLV;

    /* add space for signature tlv and tlv block */
    memmove(tlvblock + 2 + sig_tlv_size,
        tlvblock, *data_size - (tlvblock - data));

    /* add two bytes for new tlv-block header */
    *data_size += 2;

    /* clear new packet tlvblock length */
    tlvblock[0] = 0;
    tlvblock[1] = 0;
  }
  else {
    /* add space for signature tlv */
    memmove(tlvblock + 2 + sig_tlv_size,
        tlvblock + 2, *data_size - (tlvblock + 2 - data));
  }
  /* write new tlvblock size */
  tlvblock_size = (256 * tlvblock[0] + tlvblock[1]);
  tlvblock_size += sig_tlv_size;
  *tlvblock++ = tlvblock_size / 256;
  *tlvblock++ = tlvblock_size & 255;

  /* write signature TLV header */
  *tlvblock++ = RFC7182_MSGTLV_ICV;
  if (sig_size > 255) {
    *tlvblock++ = RFC5444_TLV_FLAG_TYPEEXT |
        RFC5444_TLV_FLAG_VALUE | RFC5444_TLV_FLAG_EXTVALUE;
  }
  else {
    *tlvblock++ = RFC5444_TLV_FLAG_TYPEEXT | RFC5444_TLV_FLAG_VALUE;
  }

  if (sig->source_specific) {
    *tlvblock++ = RFC7182_ICV_EXT_SRCSPEC_CRYPTHASH;
  }
  else {
    *tlvblock++ = RFC7182_ICV_EXT_CRYPTHASH;
  }

  if (sig_size > 255) {
    *tlvblock++ = sig_size / 256;
    *tlvblock++ = sig_size & 255;
  }
  else {
    *tlvblock++ = sig_size;
  }

  /* write signature tlv value */
  *tlvblock++ = sig->key.hash_function;
  *tlvblock++ = sig->key.crypt_function;
  *tlvblock++ = key_id_length;
  memcpy(tlvblock, key_id, key_id_length);
  memcpy(tlvblock + key_id_length, _crypt_buffer, crypt_len);

  /* fix data size */
  *data_size += sig_tlv_size;

  if (msg) {
    /* fix message size field */
    data[2] = *data_size / 256;
    data[3] = *data_size & 255;
  }

  /* return new message size */
  OONF_DEBUG_HEX(LOG_RFC5444_SIG, data, *data_size, "Signed data:");

  return 0;
}

/**
 * Remove signature TLVs from a message/packet
 * @param dst pointer to destination buffer for unsigned message/packet
 * @param context rfc5444 context
 * @return size of unsigned data
 */
static size_t
_remove_signature_data(uint8_t *dst, const struct rfc5444_reader_tlvblock_context *context) {
  const uint8_t *src_ptr, *src_end;
  uint8_t *dst_ptr, *tlvblock;
  uint16_t len, hoplimit, hopcount;
  uint16_t blocklen, tlvlen;

  hoplimit = 0;
  hopcount = 0;

  /* initialize pointers to src/dst */
  if (context->type == RFC5444_CONTEXT_PACKET) {
    src_ptr = context->pkt_buffer;
    src_end = context->pkt_buffer + context->pkt_size;

    /* calculate message header length */
    if (context->has_pktseqno) {
      len = 3;
    }
    else {
      len = 1;
    }
  }
  else {
    src_ptr = context->msg_buffer;
    src_end = context->msg_buffer + context->msg_size;

    /* calculate message header length */
    len = 4;
    if (context->has_origaddr) {
      len += context->addr_len;
    }
    if (context->has_hoplimit) {
      hoplimit = len;
      len++;
    }
    if (context->has_hopcount) {
      hopcount = len;
      len++;
    }
    if (context->has_seqno) {
      len += 2;
    }
  }
  dst_ptr = dst;


  /* copy pakcet/message header */
  memcpy(dst_ptr, src_ptr, len);

  /* clear hoplimit/hopcount */
  if (hoplimit) {
    dst_ptr[hoplimit] = 0;
  }
  if (hopcount) {
    dst_ptr[hopcount] = 0;
  }

  /* advance to end of header */
  src_ptr += len;
  dst_ptr += len;
  tlvblock = dst_ptr;

  /* copy all message tlvs except for signature tlvs */
  blocklen = 256 * src_ptr[0] + src_ptr[1];

  /* skip over message tlv block header, we write the number later */
  src_ptr +=2;
  dst_ptr +=2;

  /* loop over message tlvs */
  len = blocklen;
  while (len > 0) {
    /* calculate length of TLV */
    tlvlen = 2;
    if (src_ptr[1] & RFC5444_TLV_FLAG_TYPEEXT) {
      /* extended type, one extra byte */
      tlvlen++;
    }
    if (src_ptr[1] & RFC5444_TLV_FLAG_VALUE) {
      /* TLV has a value field */
      if (src_ptr[1] & RFC5444_TLV_FLAG_EXTVALUE) {
        /* 2-byte value */
        tlvlen += (256 * src_ptr[tlvlen]) + src_ptr[tlvlen+1] + 2;
      }
      else {
        /* 1-byte value */
        tlvlen += src_ptr[tlvlen] + 1;
      }
    }

    if (src_ptr[0] != RFC7182_MSGTLV_ICV) {
      /* copy TLV if not signature TLV */
      memcpy(dst_ptr, src_ptr, tlvlen);
      dst_ptr += tlvlen;
    }
    else {
      /* reduce blocklength */
      blocklen -= tlvlen;
    }
    len -= tlvlen;
    src_ptr += tlvlen;
  }

  if (blocklen > 0 || context->type == RFC5444_CONTEXT_MESSAGE) {
    /* overwrite message tlvblock length */
    tlvblock[0] = blocklen / 256;
    tlvblock[1] = blocklen & 255;
  }
  else {
    /* remove empty packet tlvblock and fix flags */
    dst_ptr -= 2;
    dst[0] &= ~ RFC5444_PKT_FLAG_TLV;
  }

  /* copy rest of data */
  len = src_end - src_ptr;
  memcpy(dst_ptr, src_ptr, len);

  /* calculate data length */
  len =  dst_ptr - dst + len;
  if (context->type == RFC5444_CONTEXT_MESSAGE) {
    /* overwrite message length */
    dst[2] = len / 256;
    dst[3] = len & 255;
  }
  return len;
}

/**
 * Helper function that registers the packet post-processors
 * for signature schemes that referred to an unregistered
 * hash/crypto-function
 */
static void
_handle_postprocessors(void) {
  struct rfc5444_signature *sig;
  bool registered;

  avl_for_each_element(&_sig_tree, sig, _node) {
    registered = avl_is_node_added(&sig->_postprocessor._node);

    /* test if hash/crypt-function is available */
    sig->hash = avl_find_element(&_hash_functions, &sig->key.hash_function,
        sig->hash, _node);
    sig->crypt = avl_find_element(&_crypt_functions,
        &sig->key.crypt_function, sig->crypt, _node);

    if (!registered && sig->hash != NULL && sig->crypt != NULL) {
      sig->_postprocessor.allocate_space = sig->crypt->getSize(sig);
      rfc5444_writer_register_postprocessor(
          &_protocol->writer, &sig->_postprocessor);
    }
    else if (registered && (sig->hash == NULL || sig->crypt == NULL)) {
      rfc5444_writer_unregister_postprocessor(
                &_protocol->writer, &sig->_postprocessor);
    }
  }
}

/**
 * AVL comparator for two signature keys
 * @param k1
 * @param k2
 * @return
 */
static int
_avl_cmp_signatures(const void *k1, const void *k2) {
  return memcmp(k1, k2, sizeof(struct rfc5444_signature_key));
}

/**
 * Callback to query the key-id including length
 * @param sig this rfc5444 signature
 * @param len pointer to length, will set by this function
 * @return pointer to key-id
 */
static const void *
_cb_get_empty_keyid(
    struct rfc5444_signature *sig __attribute__((unused)), size_t *len) {
  static const char *id = "";

  *len = 0;
  return id;
}

/**
 * Callback to checks if the key-id is valid for a signature before
 * checking the signature itself. This can also be used to store the key-id
 * before 'crypt' callback is called.
 * @param sig this rfc5444 signature
 * @param id pointer to key-id
 * @param len length of key id
 * @return okay, ignore or drop
 */
static enum rfc5444_sigid_check
_cb_sigid_okay(struct rfc5444_signature *sig __attribute__((unused)),
    const void *id __attribute((unused)), size_t len __attribute((unused))) {
  return RFC5444_SIGID_OKAY;
}

static bool
_cb_is_matching_signature(
    struct rfc5444_writer_postprocessor *processor, int msg_type) {
  struct rfc5444_signature *sig;

  sig = container_of(processor, struct rfc5444_signature, _postprocessor);

  return sig->is_matching_signature(sig, msg_type);
}

/**
 * 'Identity' hash function as defined in RFC7182
 * @param sig rfc5444 signature
 * @param dst output buffer for signature
 * @param dst_len pointer to length of output buffer,
 *   will be set to signature length afterwards
 * @param src unsigned original data
 * @param src_len length of original data
 * @return -1 if an error happened, 0 otherwise
 */
static int
_cb_identity_hash(struct rfc5444_signature *sig __attribute__((unused)),
    void *dst, size_t *dst_len, const void *src, size_t src_len) {
  *dst_len = src_len;
  memcpy(dst, src, src_len);
  return 0;
}

/**
 * 'Identity' crypto function as defined in RFC7182
 * @param sig rfc5444 signature
 * @param dst output buffer for cryptographic signature
 * @param dst_len pointer to length of output buffer, will be set to
 *   length of signature afterwards
 * @param src unsigned original data
 * @param src_len length of original data
 * @return -1 if an error happened, 0 otherwise
 */
static int
_cb_identity_crypt(struct rfc5444_signature *sig,
    void *dst, size_t *dst_len, const void *src, size_t src_len) {
  /* just hash */
  if (sig->hash->hash(sig, dst, dst_len, src, src_len)) {
    OONF_INFO(LOG_RFC5444_SIG, "Hash-error when checking signature");
    return -1;
  }
  return 0;
}

/**
 * Callback to check a signature by generating a local signature
 * with the 'crypto' callback and then comparing both.
 * @param sig rfc5444 signature
 * @param encrypted pointer to encrypted signature
 * @param encrypted_length length of encrypted signature
 * @param src unsigned original data
 * @param src_len length of original data
 * @return true if signature matches, false otherwise
 */
static bool
_cb_check_by_crypt(struct rfc5444_signature *sig,
    const void *encrypted, size_t encrypted_length,
    const void *src, size_t src_len) {
  size_t crypt_length;
  int result;

  /* run encryption function */
  crypt_length = sizeof(_crypt_buffer);
  if (sig->crypt->crypt(sig, _crypt_buffer, &crypt_length, src, src_len)) {
    OONF_INFO(LOG_RFC5444_SIG, "Crypto-error when checking signature");
    return -1;
  }

  /* compare length of both signatures */
  if (crypt_length != encrypted_length) {
    OONF_INFO(LOG_RFC5444_SIG, "signature has wrong length: "
        "%"PRINTF_SIZE_T_SPECIFIER" != %"PRINTF_SIZE_T_SPECIFIER,
        crypt_length, encrypted_length);
    return -1;
  }

  /* binary compare both signatures */
  result = memcmp(encrypted, _crypt_buffer, crypt_length);
  if (result) {
    OONF_INFO_HEX(LOG_RFC5444_SIG, encrypted, crypt_length, "Received signature:");
    OONF_INFO_HEX(LOG_RFC5444_SIG, _crypt_buffer, crypt_length, "Expected signature:");
  }
  return result == 0;
}
