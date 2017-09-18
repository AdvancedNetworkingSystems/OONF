
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

#include "nhdp/nhdp.h"
#include "nhdp/nhdp_db.h"
#include "nhdp/nhdp_domain.h"
#include "nhdp/nhdp_interfaces.h"

#include "common/common_types.h"
#include "common/autobuf.h"
#include "common/avl.h"
#include "common/avl_comp.h"
#include "common/container_of.h"
#include "config/cfg_schema.h"
#include "core/oonf_logging.h"
#include "subsystems/oonf_class.h"
#include "subsystems/oonf_rfc5444.h"

#include "mpr/mpr_internal.h"
#include "mpr/neighbor-graph-routing.h"
#include "mpr/neighbor-graph.h"
#include "mpr/mpr.h"

/* FIXME remove unneeded includes */

static bool _is_allowed_link_tuple(const struct nhdp_domain *domain,
    struct nhdp_interface *current_interface, struct nhdp_link *lnk);
static uint32_t _calculate_d1_x_of_n2_addr(const struct nhdp_domain *domain,
    struct neighbor_graph *graph, struct addr_node *addr);
static uint32_t _calculate_d_x_y(const struct nhdp_domain *domain,
    struct neighbor_graph *, struct n1_node *x, struct addr_node *y);
static uint32_t _calculate_d2_x_y(const struct nhdp_domain *domain,
    struct n1_node *x, struct addr_node *y);
static uint32_t _get_willingness_n1(const struct nhdp_domain *domain,
    struct n1_node *node);

static uint32_t _calculate_d1_of_y(const struct nhdp_domain *domain,
    struct neighbor_graph *graph, struct addr_node *y);

static struct neighbor_graph_interface _rt_api_interface = {
  .is_allowed_link_tuple     = _is_allowed_link_tuple,
  .calculate_d1_x_of_n2_addr = _calculate_d1_x_of_n2_addr,
  .calculate_d_x_y           = _calculate_d_x_y,
  .calculate_d2_x_y          = _calculate_d2_x_y,
  .get_willingness_n1        = _get_willingness_n1,
};

/**
 * Check if a given tuple is "reachable" according to section 18.4
 * @param neigh NHDP neighbor
 * @return true if reachable, false otherwise
 */
static bool
_is_reachable_neighbor_tuple(const struct nhdp_domain *domain, struct nhdp_neighbor *neigh) {
  struct nhdp_neighbor_domaindata *neighbordata;
  neighbordata = nhdp_domain_get_neighbordata(domain, neigh);

  return neighbordata->metric.in <= RFC7181_METRIC_MAX
      && neigh->symmetric > 0;
}

/**
 * Check if a neighbor tuple is "allowed" according to section 18.4
 * @param domain NHDP domain
 * @param neigh NHDP neighbor
 * @return true if allowed, false otherwise
 */
static bool
_is_allowed_neighbor_tuple(const struct nhdp_domain *domain,
    struct nhdp_neighbor *neigh) {
  struct nhdp_neighbor_domaindata *neighbordata;

  neighbordata = nhdp_domain_get_neighbordata(domain, neigh);
  return _is_reachable_neighbor_tuple(domain, neigh)
      && neighbordata->willingness > RFC7181_WILLINGNESS_NEVER;
}

static bool
_is_allowed_link_tuple(const struct nhdp_domain *domain,
    struct nhdp_interface *current_interface __attribute__((unused)),
    struct nhdp_link *lnk) {
  return _is_allowed_neighbor_tuple(domain, lnk->neigh);
}

static bool
_is_allowed_2hop_tuple(const struct nhdp_domain *domain, struct nhdp_l2hop *two_hop) {
  struct nhdp_l2hop_domaindata *neighdata;
  neighdata = nhdp_domain_get_l2hopdata(domain, two_hop);
  return neighdata->metric.in <= RFC7181_METRIC_MAX;
}

/**
 * Calculate d1(x) according to section 18.2 (draft 19)
 * @param domain NHDP domain
 * @param x node x
 * @return metric distance
 */
static uint32_t
_calculate_d1_x(const struct nhdp_domain *domain, struct n1_node *x) {
  struct nhdp_neighbor_domaindata *neighdata;

  neighdata = nhdp_domain_get_neighbordata(domain, x->neigh);
  return neighdata->metric.in;
}

/**
 * Calculate d2(x,y) according to section 18.2 (draft 19)
 * @param domain NHDP domain
 * @param x node x
 * @param y node y
 * @return metric distance
 */
static uint32_t
_calculate_d2_x_y(const struct nhdp_domain *domain, struct n1_node *x, struct addr_node *y) {
  struct nhdp_l2hop *l2hop;
  struct nhdp_link *lnk;
  struct nhdp_l2hop_domaindata *twohopdata;

  /* find the corresponding 2-hop entry, if it exists */
  list_for_each_element(&x->neigh->_links, lnk, _neigh_node) {
    l2hop = avl_find_element(&lnk->_2hop,
        &y->addr, l2hop, _link_node);
    if (l2hop) {
      twohopdata = nhdp_domain_get_l2hopdata(domain, l2hop);
      return twohopdata->metric.in;
    }
  }
  return RFC7181_METRIC_INFINITE;
}

static uint32_t
_calculate_d_x_y(const struct nhdp_domain *domain, 
                 struct neighbor_graph *graph, struct n1_node *x, struct addr_node *y) {
  uint32_t cost, cost1, cost2, idx;
#ifdef OONF_LOG_DEBUG_INFO
  struct netaddr_str nbuf1, nbuf2;
#endif
  
  idx = x->table_offset + y->table_offset;
  assert(graph->d_x_y_cache);
  cost = graph->d_x_y_cache[idx];
  if (!cost) {
    cost1 = _calculate_d1_x(domain, x);
    cost2 = _calculate_d2_x_y(domain, x, y);
    if (cost1 > RFC7181_METRIC_MAX || cost2 > RFC7181_METRIC_MAX) {
      cost = RFC7181_METRIC_INFINITE_PATH;
    }
    else {
      cost = cost1 + cost2;
    }
    graph->d_x_y_cache[idx] = cost;
    OONF_DEBUG(LOG_MPR, "d_x_y(%s,%s)=%u (%u,%u)",
         netaddr_to_string(&nbuf1, &x->addr),
         netaddr_to_string(&nbuf2, &y->addr),
         cost,
         x->table_offset, y->table_offset);
  }
  else {
        OONF_DEBUG(LOG_MPR, "d_x_y(%s,%s)=%u cached(%u,%u)",
         netaddr_to_string(&nbuf1, &x->addr),
         netaddr_to_string(&nbuf2, &y->addr),
         cost,
         x->table_offset, y->table_offset);
  }
  return cost;
}

/**
 * Calculate d1(y) according to section 18.2 (draft 19)
 * @param domain NHDP domain
 * @param graph neighbor graph instance
 * @param y node y
 * @return metric distance
 */
static uint32_t
_calculate_d1_of_y(const struct nhdp_domain *domain,
    struct neighbor_graph *graph, struct addr_node *y) {
  struct n1_node *node_n1;
  struct nhdp_laddr *laddr;
  struct nhdp_neighbor_domaindata *neighdata;

  /* find the N1 neighbor corresponding to this address, if it exists */
  avl_for_each_element(&graph->set_n1, node_n1, _avl_node) {
    laddr = avl_find_element(&node_n1->neigh->_neigh_addresses, y,
        laddr, _neigh_node);
    if (laddr != NULL) {
      neighdata = nhdp_domain_get_neighbordata(domain, node_n1->neigh);
      return neighdata->metric.in;
    }
  }
  return RFC7181_METRIC_INFINITE;
}

/**
 * Calculate d1(x) according to section 18.2 (draft 19)
 * @param domain NHDP domain
 * @param graph neighbor graph instance
 * @param addr node address
 * @return metric distance
 */
static uint32_t
_calculate_d1_x_of_n2_addr(const struct nhdp_domain *domain,
    struct neighbor_graph *graph, struct addr_node *addr) {
  uint32_t d1_x;

  d1_x = _calculate_d1_of_y(domain, graph, addr);

  return d1_x;
}

/**
 * Calculate N1
 * @param domain NHDP domain
 * @param graph neighbor graph instance
 */
static void
_calculate_n1(const struct nhdp_domain *domain, struct neighbor_graph *graph) {
  struct nhdp_neighbor *neigh;

#ifdef OONF_LOG_DEBUG_INFO
  struct netaddr_str buf1;
#endif
  
  OONF_DEBUG(LOG_MPR, "Calculate N1 for routing MPRs");
  
  list_for_each_element(nhdp_db_get_neigh_list(), neigh, _global_node) {
    // Reset temporary selection state 

    neigh->selection_is_mpr = false;
    if (_is_allowed_neighbor_tuple(domain, neigh)) {
      OONF_DEBUG(LOG_MPR, "Add neighbor %s in: %u", netaddr_to_string(&buf1, &neigh->originator),
          nhdp_domain_get_neighbordata(domain, neigh)->metric.in);
      mpr_add_n1_node_to_set(&graph->set_n1, neigh, NULL, 0);
    }
  }
}

static void
_calculate_n2(const struct nhdp_domain *domain, struct neighbor_graph *graph) {
  struct n1_node *n1_neigh;
  struct nhdp_link *lnk;
  struct nhdp_l2hop *twohop;
  
#ifdef OONF_LOG_DEBUG_INFO
  struct nhdp_l2hop_domaindata *l2data;
  struct nhdp_neighbor_domaindata *neighdata;
  struct netaddr_str nbuf1, nbuf2;
#endif
  
  OONF_DEBUG(LOG_MPR, "Calculate N2 for routing MPRs");

//    list_for_each_element(&nhdp_neigh_list, neigh, _global_node) {
//      list_for_each_element(&neigh->_links, link, _if_node) {
//        OONF_DEBUG(LOG_MPR, "Link status %u", link->neigh->symmetric);
//      }
//    }

  /* iterate over all two-hop neighbor addresses of N1 members */
    avl_for_each_element(&graph->set_n1, n1_neigh, _avl_node) {
      list_for_each_element(&n1_neigh->neigh->_links,
          lnk, _neigh_node) {
        avl_for_each_element(&lnk->_2hop, twohop, _link_node) {
          // OONF_DEBUG(LOG_MPR, "Link status %u", lnk->neigh->symmetric);
          if (_is_allowed_2hop_tuple(domain, twohop)) {

#ifdef OONF_LOG_DEBUG_INFO
            neighdata = nhdp_domain_get_neighbordata(domain, n1_neigh->neigh);
            l2data = nhdp_domain_get_l2hopdata(domain, twohop);
            OONF_DEBUG(LOG_MPR, "Add twohop addr %s (over %s) in: %u out: %u (path-in: %u path-out: %u)",
                    netaddr_to_string(&nbuf1, &twohop->twohop_addr),
                    netaddr_to_string(&nbuf2, &n1_neigh->addr),
                    l2data->metric.in, l2data->metric.out,
                    l2data->metric.in + neighdata->metric.in, l2data->metric.out + neighdata->metric.out);
#endif
            mpr_add_addr_node_to_set(&graph->set_n2, twohop->twohop_addr, 0);
          }
        }
      }
    }
}

/**
 * Returns the flooding/routing willingness of an N1 neighbor
 * @param domain NHDP domain
 * @param node neighbor node
 * @return willingness
 */
static uint32_t
_get_willingness_n1(const struct nhdp_domain *domain, struct n1_node *node) {
  struct nhdp_neighbor_domaindata *neighdata;

  neighdata = nhdp_domain_get_neighbordata(domain, node->neigh);
  return neighdata->willingness;
}

static struct
neighbor_graph_interface *_get_neighbor_graph_interface_routing(void) {
  return &_rt_api_interface;
}

void
mpr_calculate_neighbor_graph_routing(const struct nhdp_domain *domain,
    struct neighbor_graph *graph) {
  struct neighbor_graph_interface *methods;

  OONF_DEBUG(LOG_MPR, "Calculate neighbor graph for routing MPRs");

  methods = _get_neighbor_graph_interface_routing();

  mpr_init_neighbor_graph(graph, methods);
  _calculate_n1(domain, graph);
  _calculate_n2(domain, graph);
}
