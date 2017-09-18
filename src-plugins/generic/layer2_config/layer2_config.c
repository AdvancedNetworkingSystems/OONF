
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
#include "common/avl_comp.h"
#include "common/common_types.h"
#include "config/cfg_schema.h"
#include "config/cfg_validate.h"
#include "core/oonf_logging.h"
#include "core/oonf_subsystem.h"
#include "subsystems/oonf_class.h"
#include "subsystems/oonf_layer2.h"
#include "subsystems/oonf_timer.h"

#include "layer2_config/layer2_config.h"

/* definitions and constants */
#define LOG_LAYER2_CONFIG _oonf_layer2_config_subsystem.logging

enum l2_data_type {
  L2_NET,
  L2_DEF,
  L2_NEIGH,
};

struct l2_config_data {
  enum l2_data_type type;
  struct netaddr mac;

  int data_idx;
  int64_t data;
};

struct l2_config_if_data {
  char interf[IF_NAMESIZE];

  struct oonf_timer_instance _reconfigure_timer;
  struct avl_node _node;

  size_t count;
  struct l2_config_data d[0];
};

/* Prototypes */
static int _init(void);
static void _cleanup(void);

static struct l2_config_if_data *_add_if_data(
    const char *ifname, size_t data_count);
static void _remove_if_data(struct l2_config_if_data *);

static void _cb_update_l2net(void *);
static void _cb_update_l2neigh(void *);
static void _cb_reconfigure(struct oonf_timer_instance *);

static int _parse_l2net_config(
    struct l2_config_data *storage, const char *value);
static int _parse_l2neigh_config(
    struct l2_config_data *storage, const char *value);
static void _configure_if_data(struct l2_config_if_data *if_data);

static int _cb_validate_l2netdata(const struct cfg_schema_entry *entry,
    const char *section_name, const char *value, struct autobuf *out);
static int _cb_validate_l2defdata(const struct cfg_schema_entry *entry,
    const char *section_name, const char *value, struct autobuf *out);
static int _cb_validate_l2neighdata(const struct cfg_schema_entry *entry,
    const char *section_name, const char *value, struct autobuf *out);

static void _cb_valhelp_l2net(
    const struct cfg_schema_entry *entry, struct autobuf *out);
static void _cb_valhelp_l2def(
    const struct cfg_schema_entry *entry, struct autobuf *out);
static void _cb_valhelp_l2neigh(
    const struct cfg_schema_entry *entry, struct autobuf *out);
static void _create_neigh_help(struct autobuf *out, bool mac);

static void _cb_config_changed(void);

/* define configuration entries */

/*! configuration validator for linkdata */
#define CFG_VALIDATE_L2NETDATA(p_name, p_def, p_help, args...)         _CFG_VALIDATE(p_name, p_def, p_help, .cb_validate = _cb_validate_l2netdata, .cb_valhelp = _cb_valhelp_l2net, .list = true, ##args )
#define CFG_VALIDATE_L2DEFDATA(p_name, p_def, p_help, args...)         _CFG_VALIDATE(p_name, p_def, p_help, .cb_validate = _cb_validate_l2defdata, .cb_valhelp = _cb_valhelp_l2def, .list = true, ##args )
#define CFG_VALIDATE_L2NEIGHDATA(p_name, p_def, p_help, args...)         _CFG_VALIDATE(p_name, p_def, p_help, .cb_validate = _cb_validate_l2neighdata, .cb_valhelp = _cb_valhelp_l2neigh, .list = true, ##args )

static struct cfg_schema_entry _l2_config_if_entries[] = {
  [L2_NET] = CFG_VALIDATE_L2NETDATA("l2net", "",
    "Sets an interface wide layer2 entry into the database."
    " Parameters are the key of the interface data followed by the data."),
  [L2_DEF] = CFG_VALIDATE_L2DEFDATA("l2default", "",
    "Sets an interface wide default neighbor layer2 entry into the database."
    " Parameters are the key of the neighbor data followed by the data."),
  [L2_NEIGH] = CFG_VALIDATE_L2NEIGHDATA("l2neighbor", "",
    "Sets an neighbor specific layer2 entry into the database."
    " Parameters are the key of the neighbor data followed by the mac address and then the data."),
};

static struct cfg_schema_section _l2_config_section = {
  .type = CFG_INTERFACE_SECTION,
  .mode = CFG_INTERFACE_SECTION_MODE,
  .cb_delta_handler = _cb_config_changed,
  .entries = _l2_config_if_entries,
  .entry_count = ARRAYSIZE(_l2_config_if_entries),
};

/* declare subsystem */
static const char *_dependencies[] = {
  OONF_LAYER2_SUBSYSTEM,
  OONF_TIMER_SUBSYSTEM,
};
static struct oonf_subsystem _oonf_layer2_config_subsystem = {
  .name = OONF_LAYER2_CONFIG_SUBSYSTEM,
  .dependencies = _dependencies,
  .dependencies_count = ARRAYSIZE(_dependencies),
  .init = _init,
  .cleanup = _cleanup,

  .cfg_section = &_l2_config_section,
};
DECLARE_OONF_PLUGIN(_oonf_layer2_config_subsystem);

/* originator for smooth set/remove of configured layer2 values */
static struct oonf_layer2_origin _l2_origin_current = {
  .name = "layer2 config",
  .priority = OONF_LAYER2_ORIGIN_CONFIGURED,
};
static struct oonf_layer2_origin _l2_origin_old = {
  .name = "layer2 config old",
  .priority = OONF_LAYER2_ORIGIN_CONFIGURED,
};

/* listener for removal of layer2 data */
static struct oonf_class_extension _l2net_listener = {
  .ext_name = "link config listener",
  .class_name = LAYER2_CLASS_NETWORK,

  .cb_remove = _cb_update_l2net,
  .cb_change = _cb_update_l2net,
};
static struct oonf_class_extension _l2neigh_listener = {
  .ext_name = "link config listener",
  .class_name = LAYER2_CLASS_NEIGHBOR,

  .cb_remove = _cb_update_l2neigh,
  .cb_change = _cb_update_l2neigh,
};

/* interface data */
static struct avl_tree _if_data_tree;

/* interface reconfiguration timer */
static struct oonf_timer_class _reconfigure_timer = {
  .name = "layer2 reconfiguration",
  .callback = _cb_reconfigure,
};

/**
 * Subsystem constructor
 * @return always returns 0
 */
static int
_init(void) {
  oonf_layer2_add_origin(&_l2_origin_current);
  oonf_layer2_add_origin(&_l2_origin_old);

  oonf_class_extension_add(&_l2net_listener);
  oonf_class_extension_add(&_l2neigh_listener);

  oonf_timer_add(&_reconfigure_timer);

  avl_init(&_if_data_tree, avl_comp_strcasecmp, false);
  return 0;
}

/**
 * Subsystem destructor
 */
static void
_cleanup(void) {
  struct l2_config_if_data *if_data, *if_data_it;

  avl_for_each_element_safe(&_if_data_tree, if_data, _node, if_data_it) {
    _remove_if_data(if_data);
  }
  oonf_timer_remove(&_reconfigure_timer);

  oonf_class_extension_remove(&_l2net_listener);
  oonf_class_extension_remove(&_l2neigh_listener);

  oonf_layer2_remove_origin(&_l2_origin_current);
  oonf_layer2_remove_origin(&_l2_origin_old);
}

/**
 * Add a new layer2 config interface data
 * @param ifname name of interface
 * @param data_count number of data entries
 * @return interface entry, NULL if out of memory
 */
static struct l2_config_if_data *
_add_if_data(const char *ifname, size_t data_count) {
  struct l2_config_if_data *if_data;

  if_data = avl_find_element(&_if_data_tree, ifname, if_data, _node);
  if (if_data) {
    _remove_if_data(if_data);
  }

  if_data = calloc(1, sizeof(struct l2_config_if_data)
      + data_count * sizeof(struct l2_config_data));
  if (!if_data) {
    OONF_WARN(LOG_LAYER2_CONFIG, "Out of memory for %"PRINTF_SIZE_T_SPECIFIER
        " ifdata entries for interface %s", data_count, _l2_config_section.section_name);
    return NULL;
  }

  /* hook into tree */
  strscpy(if_data->interf, ifname, IF_NAMESIZE);
  if_data->_node.key = if_data->interf;

  avl_insert(&_if_data_tree, &if_data->_node);

  /* initialize timer */
  if_data->_reconfigure_timer.class = &_reconfigure_timer;

  return if_data;
}

/**
 * removes a layer2 config interface data
 * @param if_data interface data
 */
static void
_remove_if_data(struct l2_config_if_data *if_data) {
  if (!avl_is_node_added(&if_data->_node)) {
    return;
  }

  oonf_timer_stop(&if_data->_reconfigure_timer);
  avl_remove(&_if_data_tree, &if_data->_node);
  free (if_data);
}

/**
 * Callback when a layer2 network entry is changed/removed
 * @param ptr l2net entry
 */
static void
_cb_update_l2net(void *ptr) {
  struct oonf_layer2_net *l2net;
  struct l2_config_if_data *if_data;

  l2net = ptr;

  if_data = avl_find_element(&_if_data_tree, l2net->name, if_data, _node);
  if (if_data && !oonf_timer_is_active(&if_data->_reconfigure_timer)) {
    OONF_DEBUG(LOG_LAYER2_CONFIG, "Received update for l2net: %s", l2net->name);
    oonf_timer_set(&if_data->_reconfigure_timer, LAYER2_RECONFIG_DELAY);
  }
}

/**
 * Callback when a layer2 neighbor entry is changed/removed
 * @param ptr l2net entry
 */
static void
_cb_update_l2neigh(void *ptr) {
  struct oonf_layer2_neigh *l2neigh;
  struct l2_config_if_data *if_data;

  l2neigh = ptr;

  if_data = avl_find_element(&_if_data_tree, l2neigh->network->name, if_data, _node);
  if (if_data && !oonf_timer_is_active(&if_data->_reconfigure_timer)) {
    OONF_DEBUG(LOG_LAYER2_CONFIG, "Received update for l2neigh: %s", l2neigh->network->name);
    oonf_timer_set(&if_data->_reconfigure_timer, LAYER2_RECONFIG_DELAY);
  }
}

/**
 * Timer called for delayed layer2 config update
 * @param timer timer entry
 */
static void
_cb_reconfigure(struct oonf_timer_instance *timer) {
  struct l2_config_if_data *if_data;

  if_data = container_of(timer, typeof(*if_data), _reconfigure_timer);
  _configure_if_data(if_data);
}

/**
 * Configuration subsystem validator for linkdata
 * @param entry configuration schema entry
 * @param section_name section name the entry was set
 * @param value value of the entry
 * @param out output buffer for error messages
 * @return -1 if validation failed, 0 otherwise
 */
static int
_cb_validate_l2netdata(const struct cfg_schema_entry *entry,
    const char *section_name, const char *value, struct autobuf *out) {
  enum oonf_layer2_network_index idx;
  const char *ptr;

  ptr = NULL;

  /* search for network metadata index */
  for (idx = 0; idx < OONF_LAYER2_NET_COUNT; idx++) {
    if ((ptr = str_hasnextword(value, oonf_layer2_get_net_metadata(idx)->key))) {
      break;
    }
  }

  if (!ptr) {
    cfg_append_printable_line(out, "First work of '%s' for entry '%s'"
        " in section %s is unknown layer2 network key",
        value, entry->key.entry, section_name);
    return -1;
  }

  /* test if second word is a human readable number */
  if (cfg_validate_int(out, section_name, entry->key.entry, ptr,
      INT64_MIN, INT64_MAX, 8,
      oonf_layer2_get_net_metadata(idx)->fraction,
      oonf_layer2_get_net_metadata(idx)->binary)) {
    return -1;
  }
  return 0;
}

/**
 * Configuration subsystem validator for linkdata
 * @param entry configuration schema entry
 * @param section_name section name the entry was set
 * @param value value of the entry
 * @param out output buffer for error messages
 * @return -1 if validation failed, 0 otherwise
 */
static int
_cb_validate_l2defdata(const struct cfg_schema_entry *entry,
    const char *section_name, const char *value, struct autobuf *out) {
  enum oonf_layer2_neighbor_index idx;
  const char *ptr;

  ptr = NULL;

  /* search for network metadata index */
  for (idx = 0; idx < OONF_LAYER2_NEIGH_COUNT; idx++) {
    if ((ptr = str_hasnextword(value, oonf_layer2_get_neigh_metadata(idx)->key))) {
      break;
    }
  }

  if (!ptr) {
    cfg_append_printable_line(out, "First work of '%s' for entry '%s'"
        " in section %s is unknown layer2 neighbor key",
        value, entry->key.entry, section_name);
    return -1;
  }

  /* test if second word is a human readable number */
  if (cfg_validate_int(out, section_name, entry->key.entry, ptr,
      INT64_MIN, INT64_MAX, 8,
      oonf_layer2_get_neigh_metadata(idx)->fraction,
      oonf_layer2_get_neigh_metadata(idx)->binary)) {
    return -1;
  }
  return 0;
}

/**
 * Configuration subsystem validator for linkdata
 * @param entry configuration schema entry
 * @param section_name section name the entry was set
 * @param value value of the entry
 * @param out output buffer for error messages
 * @return -1 if validation failed, 0 otherwise
 */
static int
_cb_validate_l2neighdata(const struct cfg_schema_entry *entry,
    const char *section_name, const char *value, struct autobuf *out) {
  static const int8_t MAC48 = AF_MAC48;
  enum oonf_layer2_neighbor_index idx;
  struct isonumber_str sbuf;
  const char *ptr;

  ptr = NULL;

  /* search for network metadata index */
  for (idx = 0; idx < OONF_LAYER2_NEIGH_COUNT; idx++) {
    if ((ptr = str_hasnextword(value, oonf_layer2_get_neigh_metadata(idx)->key))) {
      break;
    }
  }

  if (!ptr) {
    cfg_append_printable_line(out, "First work of '%s' for entry '%s'"
        " in section %s is unknown layer2 neighbor key",
        value, entry->key.entry, section_name);
    return -1;
  }

  /* test if second word is a human readable number */
  ptr = str_cpynextword(sbuf.buf, ptr, sizeof(sbuf));
  if (cfg_validate_int(out, section_name, entry->key.entry, sbuf.buf,
      INT64_MIN, INT64_MAX, 8,
      oonf_layer2_get_neigh_metadata(idx)->fraction,
      oonf_layer2_get_neigh_metadata(idx)->binary)) {
    return -1;
  }

  if (!ptr) {
    cfg_append_printable_line(out, "Mac address of neighbor missing for entry '%s'"
        " in section %s", entry->key.entry, section_name);
    return -1;
  }

  /* test if third word is a mac address */
  if (cfg_validate_netaddr(out, section_name, entry->key.entry, ptr,
      false, &MAC48, 1)) {
    return -1;
  }
  return 0;
}

/**
 * Parse the parameters of a layer2 network config entry
 * @param storage buffer to store results
 * @param value configuration string
 * @return -1 if an error happened, 0 otherwise
 */
static int
_parse_l2net_config(struct l2_config_data *storage, const char *value) {
  const char *ptr;
  int idx;

  ptr = NULL;

  /* search for network metadata index */
  for (idx = 0; idx < OONF_LAYER2_NET_COUNT; idx++) {
    if ((ptr = str_hasnextword(value, oonf_layer2_get_net_metadata(idx)->key))) {
      break;
    }
  }

  if (!ptr) {
    return -1;
  }

  storage->data_idx = idx;

  /* convert number */
  return isonumber_to_s64(&storage->data, ptr,
      oonf_layer2_get_net_metadata(idx)->fraction,
      oonf_layer2_get_net_metadata(idx)->binary);
}

/**
 * Parse the parameters of a layer2 neighbor config entry
 * @param storage buffer to store results
 * @param value configuration string
 * @return -1 if an error happened, 0 otherwise
 */
static int
_parse_l2neigh_config(struct l2_config_data *storage, const char *value) {
  struct isonumber_str sbuf;
  const char *ptr;
  int idx;

  ptr = NULL;

  /* search for network metadata index */
  for (idx = 0; idx < OONF_LAYER2_NEIGH_COUNT; idx++) {
    if ((ptr = str_hasnextword(value, oonf_layer2_get_neigh_metadata(idx)->key))) {
      break;
    }
  }

  if (!ptr) {
    return -1;
  }

  storage->data_idx = idx;

  /* convert number */
  ptr = str_cpynextword(sbuf.buf, ptr, sizeof(sbuf));
  if (isonumber_to_s64(&storage->data, sbuf.buf,
      oonf_layer2_get_neigh_metadata(idx)->fraction,
      oonf_layer2_get_neigh_metadata(idx)->binary)) {
    return -1;
  }

  if (ptr) {
    if (netaddr_from_string(&storage->mac, ptr)) {
      return -1;
    }

    if (netaddr_get_address_family(&storage->mac) == AF_MAC48) {
      return 0;
    }
  }
  netaddr_invalidate(&storage->mac);
  return 0;
}

/**
 * Apply a layer2 config interface to the l2 database
 * @param if_data interface data
 */
static void
_configure_if_data(struct l2_config_if_data *if_data) {
  struct oonf_layer2_neigh *l2neigh;
  struct oonf_layer2_net *l2net;
  struct l2_config_data *entry;
  size_t i;


  l2net = oonf_layer2_net_get(if_data->interf);
  if (!l2net && if_data->count > 0) {
    l2net = oonf_layer2_net_add(if_data->interf);
    if (!l2net) {
      return;
    }
  }

  /* relabel old entries */
  if (l2net) {
    oonf_layer2_net_relabel(l2net, &_l2_origin_old, &_l2_origin_current);

    for (i=0; i<if_data->count; i++) {
      entry = &if_data->d[i];

      switch (entry->type) {
        case L2_NET:
          oonf_layer2_set_value(&l2net->data[entry->data_idx],
              &_l2_origin_current, entry->data);
          break;
        case L2_DEF:
          oonf_layer2_set_value(&l2net->neighdata[entry->data_idx],
              &_l2_origin_current, entry->data);
          break;
        case L2_NEIGH:
          l2neigh = oonf_layer2_neigh_add(l2net, &entry->mac);
          if (l2neigh) {
            oonf_layer2_set_value(&l2neigh->data[entry->data_idx],
                &_l2_origin_current, entry->data);
          }
          break;
        default:
          break;
      }
    }

    /* remove old data */
    oonf_layer2_net_remove(l2net, &_l2_origin_old);
  }

  /* stop update timer */
  oonf_timer_stop(&if_data->_reconfigure_timer);
}

/**
 * Create a help text for the l2net configuration parameter
 * @param entry configuration entry
 * @param out help output
 */
static void
_cb_valhelp_l2net(const struct cfg_schema_entry *entry __attribute((unused)),
    struct autobuf *out) {
  size_t i;

  abuf_puts(out, "    Parameter has the form '<l2net-key> <value>\n");
  abuf_puts(out, "    <l2net-key> is one of the following list;\n");

  for (i=0; i<OONF_LAYER2_NET_COUNT; i++) {
    abuf_appendf(out, "        %s\n",
        oonf_layer2_get_net_metadata(i)->key);
  }

  abuf_puts(out, "    <value> is an numeric value (with optional iso prefix)\n");
}

/**
 * Create a help text for the l2default configuration parameter
 * @param entry configuration entry
 * @param out help output
 */
static void
_cb_valhelp_l2def(const struct cfg_schema_entry *entry __attribute((unused)),
    struct autobuf *out) {
  _create_neigh_help(out, false);
}

/**
 * Create a help text for the l2neighbor configuration parameter
 * @param entry configuration entry
 * @param out help output
 */
static void
_cb_valhelp_l2neigh(const struct cfg_schema_entry *entry __attribute((unused)),
    struct autobuf *out) {
  _create_neigh_help(out, true);
}

/**
 * Create a help text for the l2default and l2neighbor
 * configuration parameter
 * @param out help output
 */
static void
_create_neigh_help(struct autobuf *out, bool mac) {
  size_t i;


  abuf_appendf(out, "    Parameter has the form '<l2neigh-key> <value>%s\n",
      mac ? " <neighbor mac>" : "");
  abuf_puts(out, "    <l2neigh-key> is one of the following list;\n");

  for (i=0; i<OONF_LAYER2_NEIGH_COUNT; i++) {
    abuf_appendf(out, "        %s\n",
        oonf_layer2_get_neigh_metadata(i)->key);
  }

  abuf_puts(out, "    <value> is an numeric value (with optional iso prefix)\n");
  if (mac) {
    abuf_puts(out, "    <mac> is the ethernet mac address of the neighbor\n");
  }
}


/**
 * Parse configuration change
 */
static void
_cb_config_changed(void) {
  struct l2_config_if_data *if_data;
  struct cfg_entry *l2net_entry, *l2def_entry, *l2neigh_entry;
  char ifbuf[IF_NAMESIZE];
  const char *ifname;
  char *txt_value;
  size_t i, total;

  ifname = cfg_get_phy_if(ifbuf, _l2_config_section.section_name);
  if_data = avl_find_element(&_if_data_tree, ifname, if_data, _node);
  if (if_data) {
    _remove_if_data(if_data);
  }

  if (!_l2_config_section.post) {
    /* section was removed */
     return;
  }

  l2net_entry = cfg_db_get_entry(_l2_config_section.post,
      _l2_config_if_entries[L2_NET].key.entry);
  l2def_entry = cfg_db_get_entry(_l2_config_section.post,
      _l2_config_if_entries[L2_DEF].key.entry);
  l2neigh_entry = cfg_db_get_entry(_l2_config_section.post,
      _l2_config_if_entries[L2_NEIGH].key.entry);

  /* calculate number of settings */
  total = 0;
  if (l2net_entry) {
    total += strarray_get_count(&l2net_entry->val);
  }
  if (l2def_entry) {
    total += strarray_get_count(&l2def_entry->val);
  }
  if (l2neigh_entry) {
    total += strarray_get_count(&l2neigh_entry->val);
  }

  if_data = _add_if_data(_l2_config_section.section_name, total);
  if (!if_data) {
    OONF_WARN(LOG_LAYER2_CONFIG, "Out of memory for %"PRINTF_SIZE_T_SPECIFIER
        " ifdata entries for interface %s", total, _l2_config_section.section_name);
    return;
  }

  /* initialize header */
  strscpy(if_data->interf, _l2_config_section.section_name, IF_NAMESIZE);
  if_data->_node.key = if_data->interf;

  avl_insert(&_if_data_tree, &if_data->_node);

  /* initialize data */
  i = 0;
  if (l2net_entry) {
    /* parse layer2 network data */
    strarray_for_each_element(&l2net_entry->val, txt_value) {
      if (!_parse_l2net_config(&if_data->d[i], txt_value)) {
        if_data->d[i].type = L2_NET;
        i++;
      }
    }
  }
  if (l2def_entry) {
    /* parse layer2 default data */
    strarray_for_each_element(&l2def_entry->val, txt_value) {
      if (!_parse_l2neigh_config(&if_data->d[i], txt_value)) {
        if_data->d[i].type = L2_DEF;
        i++;
      }
    }
  }
  if (l2neigh_entry) {
    /* parse layer2 network data */
    strarray_for_each_element(&l2neigh_entry->val, txt_value) {
      if (!_parse_l2neigh_config(&if_data->d[i], txt_value)) {
        if_data->d[i].type = L2_NEIGH;
        i++;
      }
    }
  }

  if_data->count = i;

  /* reconfigure layer2 database */
  _configure_if_data(if_data);
}
