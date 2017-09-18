
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

#include <stdio.h>
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
#include "core/oonf_cfg.h"
#include "core/oonf_logging.h"
#include "subsystems/oonf_class.h"
#include "subsystems/oonf_rfc5444.h"

#include "mpr/mpr_internal.h"
#include "mpr/neighbor-graph-flooding.h"
#include "mpr/neighbor-graph.h"
#include "mpr/mpr.h"

/* FIXME remove unneeded includes */

void
mpr_add_n1_node_to_set(struct avl_tree *set, struct nhdp_neighbor *neigh, struct nhdp_link *lnk, uint32_t offset) {
  struct n1_node *tmp_n1_neigh;
  tmp_n1_neigh = avl_find_element(set, &neigh->originator, tmp_n1_neigh, _avl_node);
  if (tmp_n1_neigh) {
    return;
  }
  tmp_n1_neigh = calloc(1, sizeof (struct n1_node));
  tmp_n1_neigh->addr = neigh->originator;
  tmp_n1_neigh->_avl_node.key = &tmp_n1_neigh->addr;
  tmp_n1_neigh->neigh = neigh;
  tmp_n1_neigh->link = lnk;
  tmp_n1_neigh->table_offset = offset;
  avl_insert(set, &tmp_n1_neigh->_avl_node);
}

void
mpr_add_addr_node_to_set(struct avl_tree *set, const struct netaddr addr, uint32_t offset) {
  struct addr_node *tmp_node;
  
  tmp_node = avl_find_element(set, &addr, tmp_node, _avl_node);
  if (tmp_node) {
    return;
  }
  tmp_node = calloc(1, sizeof (struct addr_node));
  tmp_node->addr = addr;
  tmp_node->_avl_node.key = &tmp_node->addr;
  tmp_node->table_offset = offset;
  avl_insert(set, &tmp_node->_avl_node);
}


/**
 * Initialize the MPR data set
 * @param graph neighbor graph instance
 * @param methods callback for handling graph
 */
void
mpr_init_neighbor_graph(struct neighbor_graph *graph, struct neighbor_graph_interface *methods) {
  avl_init(&graph->set_n, avl_comp_netaddr, false);
  avl_init(&graph->set_n1, avl_comp_netaddr, false);
  avl_init(&graph->set_n2, avl_comp_netaddr, false);
  avl_init(&graph->set_mpr, avl_comp_netaddr, false);
  avl_init(&graph->set_mpr_candidates, avl_comp_netaddr, false);
  graph->methods = methods;
}

/**
 * Clear a set of addresses
 * @param set AVL set to clear
 */
void
mpr_clear_addr_set(struct avl_tree *set) {
  struct addr_node *current_node, *node_it;

  avl_for_each_element_safe(set, current_node, _avl_node, node_it) {
    avl_remove(set, &current_node->_avl_node);
    free(current_node);
  }
}

/**
 * Clear set of N1 nodes
 * @param set AVL set to clear
 */
void
mpr_clear_n1_set(struct avl_tree *set) {
  struct n1_node *current_node, *node_it;

  avl_for_each_element_safe(set, current_node, _avl_node, node_it) {
    avl_remove(set, &current_node->_avl_node);
    free(current_node);
  }
}

/**
 * Clear the MPR data set
 * @param graph neighbor graph instance
 */
void
mpr_clear_neighbor_graph(struct neighbor_graph *graph) {
  mpr_clear_addr_set(&graph->set_n);
  mpr_clear_addr_set(&graph->set_n2);
  mpr_clear_n1_set(&graph->set_n1);
  mpr_clear_n1_set(&graph->set_mpr);
  mpr_clear_n1_set(&graph->set_mpr_candidates);
  
    free(graph->d_x_y_cache);
  graph->d_x_y_cache = NULL;

}

/**
 * Check if a node was selected as an MPR
 * @param graph neighbor graph instance
 * @param addr network address to check
 * @return true if mpr, false otherwise
 */
bool
mpr_is_mpr(struct neighbor_graph *graph, struct netaddr *addr) {
  struct n1_node *tmp_mpr_node;

  tmp_mpr_node = avl_find_element(&graph->set_mpr,
      addr, tmp_mpr_node, _avl_node);
  return tmp_mpr_node != NULL;
}

uint32_t
mpr_calculate_minimal_d_z_y(const struct nhdp_domain *domain,
    struct neighbor_graph *graph, struct addr_node *y) {
  struct n1_node *z_node;
  uint32_t d_z_y, min_d_z_y;
#ifdef OONF_LOG_DEBUG_INFO
  struct n1_node   *remember;
  struct netaddr_str nbuf1, nbuf2;
#endif  
  if (y->min_d_z_y) {
    return y->min_d_z_y;
  }
  
  min_d_z_y = RFC7181_METRIC_INFINITE_PATH;
#ifdef OONF_LOG_DEBUG_INFO
  remember = NULL;
#endif
  avl_for_each_element(&graph->set_n1, z_node, _avl_node) {
    d_z_y = graph->methods->calculate_d_x_y(domain, graph, z_node, y);
    if (d_z_y < min_d_z_y) {
      min_d_z_y = d_z_y;
#ifdef OONF_LOG_DEBUG_INFO
      remember = z_node;
#endif
    }
  }
  
#ifdef OONF_LOG_DEBUG_INFO
  if (remember) {
    OONF_DEBUG(LOG_MPR, "minimal d_z_y(%s) = %s (cost %u)",
               netaddr_to_string(&nbuf1, &y->addr),
               netaddr_to_string(&nbuf2, &remember->addr),
               min_d_z_y);
  }
  else {
    OONF_DEBUG(LOG_MPR, "minimal d_z_y(%s) = infinite",
               netaddr_to_string(&nbuf1, &y->addr));
  }
#endif
  y->min_d_z_y = min_d_z_y;
  return min_d_z_y;
}

/**
 * Print a set of addresses
 * @param set AVL set to print
 */
void
mpr_print_addr_set(struct avl_tree *set) {
  struct addr_node *current_node;
#ifdef OONF_LOG_DEBUG_INFO
  struct netaddr_str buf1;
#endif

  avl_for_each_element(set, current_node, _avl_node) {
    OONF_DEBUG(LOG_MPR, "%s",
        netaddr_to_string(&buf1, &current_node->addr));
  }
}

void
mpr_print_n1_set(struct nhdp_domain *domain __attribute__((unused)), struct avl_tree *set) {
  struct n1_node *current_node;
#ifdef OONF_LOG_DEBUG_INFO
  struct nhdp_neighbor_domaindata *neighbordata;
  struct netaddr_str buf1;
#endif

  avl_for_each_element(set, current_node, _avl_node) {
#ifdef OONF_LOG_DEBUG_INFO
    neighbordata = nhdp_domain_get_neighbordata(domain, current_node->neigh);

    OONF_DEBUG(LOG_MPR, "%s in: %u out: %u",
        netaddr_to_string(&buf1, &current_node->addr),
               neighbordata->metric.in,
               neighbordata->metric.out);
#endif
  }
}

/**
 * Print the MPR data sets 
 * @param graph neighbor graph instance
 */
void
mpr_print_sets(struct nhdp_domain *domain, struct neighbor_graph *graph) {
  OONF_DEBUG(LOG_MPR, "Set N");
  mpr_print_addr_set(&graph->set_n);

  OONF_DEBUG(LOG_MPR, "Set N1");
  mpr_print_n1_set(domain, &graph->set_n1);

  OONF_DEBUG(LOG_MPR, "Set N2");
  mpr_print_addr_set(&graph->set_n2);

  OONF_DEBUG(LOG_MPR, "Set MPR");
  mpr_print_n1_set(domain, &graph->set_mpr);
}

/**
 * Calculate d(y,S) according to section 18.2 (draft 19)
 * @param domain NHDP domain
 * @param graph neighbor graph instance
 * @param y graph node Y
 * @param subset_s subset of graph
 * @return metric cost
 */
uint32_t
mpr_calculate_d_of_y_s(const struct nhdp_domain *domain, struct neighbor_graph *graph, struct addr_node *y,
    struct avl_tree *subset_s) {
  uint32_t d_x_y, min_cost;
  struct n1_node *node_n1;
  
#ifdef OONF_LOG_DEBUG_INFO
  struct netaddr_str buf1;
#endif

  /* determine the minimum cost to y over all possible intermediate hops */
  min_cost = graph->methods->calculate_d1_x_of_n2_addr(domain, graph, y);
  if (min_cost > RFC7181_METRIC_MAX) {
    min_cost = RFC7181_METRIC_INFINITE_PATH;
  }
  OONF_DEBUG(LOG_MPR, "mpr_calculate_d_of_y_s(%s)", netaddr_to_string(&buf1, &y->addr));
  OONF_DEBUG(LOG_MPR, "initial cost = %u", min_cost);
  avl_for_each_element(subset_s, node_n1, _avl_node) {
    d_x_y = graph->methods->calculate_d_x_y(domain, graph, node_n1, y);
    OONF_DEBUG(LOG_MPR, "cost via %s would be = %u", netaddr_to_string(&buf1, &node_n1->addr), d_x_y);
    if (d_x_y < min_cost) {
      min_cost = d_x_y;
    }
  }

  return min_cost;
}
