
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

#include "common/autobuf.h"
#include "common/avl.h"
#include "common/avl_comp.h"
#include "common/common_types.h"
#include "common/list.h"
#include "common/netaddr.h"
#include "common/netaddr_acl.h"

#include "core/oonf_logging.h"
#include "core/oonf_subsystem.h"
#include "subsystems/oonf_class.h"

#include "olsrv2/olsrv2.h"
#include "olsrv2/olsrv2_routing.h"

#include "route_modifier/route_modifier.h"

/* definitions */
#define LOG_ROUTE_MODIFIER _routemodifier_subsystem.logging

/**
 * Configuration of a route modifier instance
 */
struct _routemodifier {
  /*! name of the routing filter */
  char name[16];

  /*! domain of the routing filter */
  int32_t domain;

  /*! address filter */
  struct netaddr_acl filter;

  /*! filter by prefix length, -1 to ignore */
  int32_t prefix_length;

  /*! filter by routing table id, 0 to ignore */
  int32_t table;

  /*! filter by routing protocol id, 0 to ignore */
  int32_t protocol;

  /*! filter by routing metric, 0 to ignore */
  int32_t distance;

  /*! tree of all configured routing filters */
  struct avl_node _node;
};

/* prototypes */
static int _init(void);
static void _cleanup(void);

static struct _routemodifier *_get_modifier(const char *name);
static void _destroy_modifier(struct _routemodifier *);

static bool _cb_rt_filter(
    struct nhdp_domain *, struct os_route_parameter *, bool set);
static void _cb_cfg_changed(void);

/* plugin declaration */
static struct cfg_schema_entry _modifier_entries[] = {
  CFG_MAP_INT32_MINMAX(_routemodifier, domain, "domain", "0",
      "Routing domain id for filter", 0, false, 0, 255),
  CFG_MAP_ACL(_routemodifier, filter, "matches",
      ACL_FIRST_REJECT "\0" ACL_DEFAULT_REJECT,
      "Ip addresses the filter should be applied to"),
  CFG_MAP_INT32_MINMAX(_routemodifier, prefix_length, "prefix_length", "-1",
      "Prefix length the filter should be applied to, -1 for any prefix length",
      0, false, -1, 128),
  CFG_MAP_INT32_MINMAX(_routemodifier, table, "table", "0",
      "Set routing table of matching routes to this value", 0, false, 0, 255),
  CFG_MAP_INT32_MINMAX(_routemodifier, protocol, "protocol", "0",
      "Set routing protocol of matching routes to this value", 0, false, 0, 255),
  CFG_MAP_INT32_MINMAX(_routemodifier, distance, "metric", "0",
      "Set routing metric of matching routes to this value", 0, false, 0, INT32_MAX),
};

static struct cfg_schema_section _modifier_section = {
  .type = OONF_ROUTE_MODIFIER_SUBSYSTEM,
  .mode = CFG_SSMODE_NAMED,

  .cb_delta_handler = _cb_cfg_changed,

  .entries = _modifier_entries,
  .entry_count = ARRAYSIZE(_modifier_entries),
};

static const char *_dependencies[] = {
  OONF_CLASS_SUBSYSTEM,
  OONF_OLSRV2_SUBSYSTEM,
};
static struct oonf_subsystem _routemodifier_subsystem = {
  .name = OONF_ROUTE_MODIFIER_SUBSYSTEM,
  .dependencies = _dependencies,
  .dependencies_count = ARRAYSIZE(_dependencies),
  .descr = "OLSRv2 route-modifier plugin",
  .author = "Henning Rogge",

  .cfg_section = &_modifier_section,

  .init = _init,
  .cleanup = _cleanup,
};
DECLARE_OONF_PLUGIN(_routemodifier_subsystem);

/* class definition for filters */
static struct oonf_class _modifier_class = {
  .name = "routemodifier filter",
  .size = sizeof(struct _routemodifier),
};

/* callback filter for dijkstra */
static struct olsrv2_routing_filter _dijkstra_filter = {
  .filter = _cb_rt_filter,
};

/* tree of routing filters */
static struct avl_tree _modifier_tree;

/**
 * Initialize plugin
 * @return always returns 0 (cannot fail)
 */
static int
_init(void) {
  avl_init(&_modifier_tree, avl_comp_strcasecmp, false);
  oonf_class_add(&_modifier_class);
  olsrv2_routing_filter_add(&_dijkstra_filter);
  return 0;
}

/**
 * Cleanup plugin
 */
static void
_cleanup(void) {
  struct _routemodifier *mod, *mod_it;

  avl_for_each_element_safe(&_modifier_tree, mod, _node, mod_it) {
    _destroy_modifier(mod);
  }

  olsrv2_routing_filter_remove(&_dijkstra_filter);
  oonf_class_remove(&_modifier_class);
}

/**
 * Callback for Dijkstra code to see which route should be changed
 * @param domain pointer to domain of route
 * @param route_param routing data
 * @param set true if route will be set, false otherwise
 * @return always true (we never drop a route)
 */
static bool
_cb_rt_filter(struct nhdp_domain *domain,
    struct os_route_parameter *route_param, bool set __attribute__((unused))) {
  struct _routemodifier *modifier;
#ifdef OONF_LOG_DEBUG_INFO
  struct netaddr_str nbuf;
#endif

  avl_for_each_element(&_modifier_tree, modifier, _node) {
    /* check filter matches this domain */
    if (domain->index != modifier->domain) {
      continue;
    }

    /* check prefix length */
    if (modifier->prefix_length != -1
        && modifier->prefix_length != netaddr_get_prefix_length(&route_param->key.dst)) {
      continue;
    }

    /* check if destination matches */
    if (!netaddr_acl_check_accept(&modifier->filter, &route_param->key.dst)) {
      continue;
    }

    /* apply modifiers */
    if (modifier->table) {
      OONF_DEBUG(LOG_ROUTE_MODIFIER, "Modify routing table for route to %s: %d",
          netaddr_to_string(&nbuf, &route_param->key.dst), modifier->table);
      route_param->table = modifier->table;
    }
    if (modifier->protocol) {
      OONF_DEBUG(LOG_ROUTE_MODIFIER, "Modify routing protocol for route to %s: %d",
          netaddr_to_string(&nbuf, &route_param->key.dst), modifier->protocol);
      route_param->protocol = modifier->protocol;
    }
    if (modifier->distance) {
      OONF_DEBUG(LOG_ROUTE_MODIFIER, "Modify routing distance for route to %s: %d",
          netaddr_to_string(&nbuf, &route_param->key.dst), modifier->distance);
      route_param->metric = modifier->distance;
    }
    break;
  }
  return true;
}

/**
 * Lookups a route modifier or create a new one
 * @param name name of route modifier
 * @return pointer to route modifier or NULL if out of memory
 */
static struct _routemodifier *
_get_modifier(const char *name) {
  struct _routemodifier *mod;

  mod = avl_find_element(&_modifier_tree, name, mod, _node);
  if (mod) {
    return mod;
  }

  mod = oonf_class_malloc(&_modifier_class);
  if (mod == NULL) {
    return NULL;
  }

  /* copy key and add to tree */
  strscpy(mod->name, name, sizeof(mod->name));
  mod->_node.key = mod->name;
  avl_insert(&_modifier_tree, &mod->_node);

  return mod;
}

/**
 * Free all resources associated with a route modifier
 * @param mod route modifier
 */
static void
_destroy_modifier(struct _routemodifier *mod) {
  avl_remove(&_modifier_tree, &mod->_node);
  netaddr_acl_remove(&mod->filter);
  oonf_class_free(&_modifier_class, mod);
}

/**
 * Configuration changed
 */
static void
_cb_cfg_changed(void) {
  struct _routemodifier *modifier;

  /* get existing modifier */
  modifier = _get_modifier(_modifier_section.section_name);
  if (!modifier) {
    /* out of memory */
    return;
  }

  if (_modifier_section.post == NULL) {
    /* section was removed */
    _destroy_modifier(modifier);
    return;
  }

  if (cfg_schema_tobin(modifier, _modifier_section.post,
      _modifier_entries, ARRAYSIZE(_modifier_entries))) {
    OONF_WARN(LOG_ROUTE_MODIFIER,
        "Could not convert configuration data of section '%s'",
        _modifier_section.section_name);

    if (_modifier_section.pre == NULL) {
      _destroy_modifier(modifier);
    }
    return;
  }
}
