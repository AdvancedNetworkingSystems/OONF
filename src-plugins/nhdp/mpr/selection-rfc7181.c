
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
#include "subsystems/oonf_rfc5444.h"
#include "subsystems/oonf_class.h"

#include "mpr/mpr_internal.h"
#include "mpr/neighbor-graph-flooding.h"
#include "mpr/neighbor-graph.h"
#include "mpr/mpr.h"
#include "mpr/selection-rfc7181.h"

/* FIXME remove unneeded includes */

static void _calculate_n(const struct nhdp_domain *domain, struct neighbor_graph *graph);
static unsigned int _calculate_r(const struct nhdp_domain *domain,
    struct neighbor_graph *graph, struct n1_node *x_node);

/**
 * Calculate N
 * 
 * This is a subset of N2 containing those addresses, for which there is no
 * direct link that has a lower metric cost than the two-hop path (so
 * it should  be covered by an MPR node).
 * 
 * @param domain NHDP domain
 * @param graph neighbor graph instance
 */
static void
_calculate_n(const struct nhdp_domain *domain, struct neighbor_graph *graph) {
  struct addr_node *y_node;
  uint32_t d1_y;
  struct n1_node *x_node;
  bool add_to_n;

  OONF_DEBUG(LOG_MPR, "Calculate N");

  avl_for_each_element(&graph->set_n2, y_node, _avl_node) {
    add_to_n = false;

    /* calculate the 1-hop cost to this node (which may be undefined) */
    d1_y = graph->methods->calculate_d1_x_of_n2_addr(domain, graph, y_node);

    /* if this neighbor can not be reached directly, we need to add it to N */
    if (d1_y == RFC7181_METRIC_INFINITE) {
      add_to_n = true;
    }
    else {

      /* check if an intermediate hop would reduce the path cost */
      avl_for_each_element(&graph->set_n1, x_node, _avl_node) {
        if (graph->methods->calculate_d_x_y(domain, graph, x_node, y_node) < d1_y) {
          add_to_n = true;
          break;
        }
      }
    }

    if (add_to_n) {
      mpr_add_addr_node_to_set(&graph->set_n, y_node->addr, y_node->table_offset);
    }
  }
}

/**
 * Calculate R(x,M)
 * 
 * For an element x in N1, the number of elements y in N for which
 * d(x,y) is defined and has minimal value among the d(z,y) for all 
 * z in N1, and no such minimal values have z in M.
 * 
 * TODO Clean up code
 * @param domain NHDP domain
 * @param graph neighbor graph instance
 * @param x_node node X
 * @return see RFC
 */
static unsigned int
_calculate_r(const struct nhdp_domain *domain, struct neighbor_graph *graph,
    struct n1_node *x_node) {
  struct addr_node *y_node;
  struct n1_node *z_node;
  uint32_t r, d_x_y, min_d_z_y;
  bool already_covered;
#ifdef OONF_LOG_DEBUG_INFO
  struct netaddr_str nbuf1, nbuf2, nbuf3;
#endif

  OONF_DEBUG(LOG_MPR, "Calculate R of N1 member %s",
      netaddr_to_string(&nbuf1, &x_node->addr));

  /* if x is an MPR node already, we know the result must be 0 */
  if (x_node->neigh->selection_is_mpr) {
    OONF_DEBUG(LOG_MPR, "X is an MPR node already, return 0");
    return 0;
  }

  r = 0;

  avl_for_each_element(&graph->set_n, y_node, _avl_node) {
    OONF_DEBUG(LOG_MPR, "-> Check y_node = %s", 
               netaddr_to_string(&nbuf1, &y_node->addr));
    /* calculate the cost to reach y through x */
    d_x_y = graph->methods->calculate_d_x_y(domain, graph, x_node, y_node);

    /* calculate the minimum cost to reach y through any node from N1 */
    min_d_z_y = mpr_calculate_minimal_d_z_y(domain, graph, y_node);

    OONF_DEBUG(LOG_MPR, "d_x_y(%s, %s) = %u, min_d_z_y(%s) = %u", netaddr_to_string(&nbuf1, &x_node->addr),
               netaddr_to_string(&nbuf2, &y_node->addr), d_x_y,
               netaddr_to_string(&nbuf3, &y_node->addr), min_d_z_y);

    if (d_x_y > min_d_z_y) {
      continue;
    }

    /* check if y is already covered by a minimum-cost node */
    already_covered = false;

    avl_for_each_element(&graph->set_n1, z_node, _avl_node) {
      if (graph->methods->calculate_d_x_y(domain, graph, z_node, y_node) == min_d_z_y
          && z_node->neigh->selection_is_mpr) {
        OONF_DEBUG(LOG_MPR, "Nope, %s is already covered by %s",
                   netaddr_to_string(&nbuf1, &y_node->addr),
                   netaddr_to_string(&nbuf2, &z_node->addr));
        already_covered = true;
        break;
      }
    }
    if (already_covered) {
      continue;
    }

    r++;
  }

  OONF_DEBUG(LOG_MPR, "Finished calculating R(x, M), result %u", r);

  return r;
}

/**
 * Add all elements x in N1 that have W(x) = WILL_ALWAYS to M.
 * @param domain NHDP domain
 * @param graph neighbor graph instance
 */
static void
_process_will_always(const struct nhdp_domain *domain, struct neighbor_graph *graph) {
  struct n1_node *current_n1_node;
#ifdef OONF_LOG_DEBUG_INFO
  struct netaddr_str buf1;
#endif
  
  OONF_DEBUG(LOG_MPR, "Process WILL_ALWAYS");

  avl_for_each_element(&graph->set_n1, current_n1_node, _avl_node) {
    if (graph->methods->get_willingness_n1(domain, current_n1_node)
        == RFC7181_WILLINGNESS_ALWAYS) {
      OONF_DEBUG(LOG_MPR, "Add neighbor %s with WILL_ALWAYS to the MPR set",
          netaddr_to_string(&buf1, &current_n1_node->addr));
      mpr_add_n1_node_to_set(&graph->set_mpr,
          current_n1_node->link->neigh,
          current_n1_node->link, current_n1_node->table_offset);
    }
  }
}

/**
 * For each element y in N for which there is only one element
 * x in N1 such that d2(x,y) is defined, add that element x to M.
 * @param domain NHDP domain
 * @param graph neighbor graph instance
 */
static void
_process_unique_mprs(const struct nhdp_domain *domain, struct neighbor_graph *graph) {
  struct n1_node *node_n1, *possible_mpr_node;
  struct addr_node *node_n;
  uint32_t possible_mprs;
#ifdef OONF_LOG_DEBUG_INFO
  struct netaddr_str buf1;
#endif
  
  OONF_DEBUG(LOG_MPR, "Process unique MPRs");

  avl_for_each_element(&graph->set_n, node_n, _avl_node) {
    /* iterate over N1 to determine the number of possible MPRs */
    possible_mprs = 0;
    possible_mpr_node = NULL;

    avl_for_each_element(&graph->set_n1, node_n1, _avl_node) {
      if (graph->methods->calculate_d2_x_y(domain, node_n1, node_n)
          <= RFC7181_METRIC_MAX) {
        /* d2(x,y) is defined for this link, so this is a possible MPR node */
        possible_mprs++; // TODO Break outer loop when this becomes > 1
        possible_mpr_node = node_n1;
      }
    }
    OONF_DEBUG(LOG_MPR, "Number of possible MPRs for N node %s is %u",
        netaddr_to_string(&buf1, &node_n->addr),
        possible_mprs);
    assert(possible_mprs > 0);
    if (possible_mprs == 1) {
      /* There is only one possible MPR to cover this 2-hop neighbor, so this
       * node must become an MPR. */
      OONF_DEBUG(LOG_MPR, "Add required neighbor %s to the MPR set",
          netaddr_to_string(&buf1, &possible_mpr_node->addr));
      mpr_add_n1_node_to_set(&graph->set_mpr,
          possible_mpr_node->neigh,
          possible_mpr_node->link,
          possible_mpr_node->table_offset);
      possible_mpr_node->neigh->selection_is_mpr = true;
    }
  }
}

/**
 * Selects a subset of nodes from N1 which are maximum 
 * regarding a given property.
 * @param domain NHDP domain for MPR calculation
 * @param graph neighbor graph instance
 * @param get_property callback for querying neighbor graph data
 */
static void
_select_greatest_by_property(const struct nhdp_domain *domain,
    struct neighbor_graph *graph,
    uint32_t(*get_property)(const struct nhdp_domain *, struct neighbor_graph*, struct n1_node*)) {
  struct avl_tree *n1_subset, tmp_candidate_subset;
  struct n1_node *node_n1,
      *greatest_prop_node;
  uint32_t current_prop,
      greatest_prop,
      number_of_greatest;

  OONF_DEBUG(LOG_MPR, "Select node with greatest property");

  greatest_prop_node = NULL;
  current_prop = greatest_prop = number_of_greatest = 0;

  avl_init(&tmp_candidate_subset, avl_comp_netaddr, false);

//  if (graph->set_mpr_candidates.count > 0) {
//    /* We already have MPR candidates, so we need to select from these
//     * (these may have resulted from a previous call to this function). */
//    n1_subset = &graph->set_mpr_candidates;
//  }
//  else {
    /* all N1 nodes are potential MPRs */
    n1_subset = &graph->set_n1;
//  }

    /*
     * Workaround for performance issues; function requires a rewrite!
     */
  avl_for_each_element(n1_subset, node_n1, _avl_node) {
    current_prop = get_property(domain, graph, node_n1);
    if (current_prop > 0) {
      if (greatest_prop_node == NULL
          || current_prop > greatest_prop) {
        greatest_prop = current_prop;
        greatest_prop_node = node_n1;
        number_of_greatest = 1;

        /* we have a unique candidate */
        mpr_clear_n1_set(&tmp_candidate_subset);
        mpr_add_n1_node_to_set(&tmp_candidate_subset, node_n1->neigh,
            node_n1->link, node_n1->table_offset);
      }
      else if (current_prop == greatest_prop) {
        /* add node to candidate subset */
        number_of_greatest++;
        mpr_add_n1_node_to_set(&tmp_candidate_subset, node_n1->neigh,
            node_n1->link, node_n1->table_offset);
      }
    }
  }

  /* write updated candidate subset */
  mpr_clear_n1_set(&graph->set_mpr_candidates);

  avl_for_each_element(&tmp_candidate_subset, node_n1, _avl_node) {
    mpr_add_n1_node_to_set(&graph->set_mpr_candidates, node_n1->neigh,
        node_n1->link, node_n1->table_offset);
  }

  /* free temporary candidate subset */
  mpr_clear_n1_set(&tmp_candidate_subset);
}

// FIXME Wrapper required for having the correct signature...

//static uint32_t
//_get_willingness_n1(const struct nhdp_domain *domain,
//    struct neighbor_graph *graph, struct n1_node *node) {
//  return graph->methods->get_willingness_n1(domain, node);
//}

/**
 * While there exists any element x in N1 with R(x, M) > 0...
 * @param domain NHDP domain
 * @param graph neighbor graph instance
 */
static void
_process_remaining(const struct nhdp_domain *domain, struct neighbor_graph *graph) {
  struct n1_node *node_n1;
  bool done;

#ifdef OONF_LOG_DEBUG_INFO
  struct netaddr_str buf1;
#endif
  
  OONF_DEBUG(LOG_MPR, "Process remaining");
  
  done = false;
  while (!done) {
    /* select node(s) by willingness */
//    OONF_DEBUG(LOG_MPR, "Select by greatest willingness");
//    _select_greatest_by_property(domain, graph,
//        &_get_willingness_n1);

    /* select node(s) by coverage */
//    if (graph->set_mpr_candidates.count > 1) {
      OONF_DEBUG(LOG_MPR, "Select by greatest coverage");
//                 graph->set_mpr_candidates.count);
      _select_greatest_by_property(domain, graph,
          &_calculate_r);
//    }

    /* TODO More tie-breaking methods might be added here 
     * Ideas from draft 19:
     *  - D(X)
     *  - Information freshness
     *  - Duration of previous MPR selection...
     */

    if (graph->set_mpr_candidates.count == 0) {
      /* no potential MPRs; we are done */
      OONF_DEBUG(LOG_MPR, "No more candidates, we are done!");
      done = true;
    }
    else if (graph->set_mpr_candidates.count == 1) {
      /* a unique candidate was found */
      node_n1 = avl_first_element(&graph->set_mpr_candidates,
          node_n1, _avl_node);
      OONF_DEBUG(LOG_MPR, "Unique candidate %s",
                 netaddr_to_string(&buf1, &node_n1->addr));
      mpr_add_n1_node_to_set(&graph->set_mpr, node_n1->neigh, node_n1->link, node_n1->table_offset);
      node_n1->neigh->selection_is_mpr = true;
      avl_remove(&graph->set_mpr_candidates, &node_n1->_avl_node);
      free(node_n1);
//      done = true;
    }
    else {
      /* Multiple candidates were found; arbitrarily add one of the 
       * candidate nodes (first in list). */
      node_n1 = avl_first_element(&graph->set_mpr_candidates,
          node_n1, _avl_node);
      OONF_DEBUG(LOG_MPR, "Multiple candidates, select %s",
                 netaddr_to_string(&buf1, &node_n1->addr));
      mpr_add_n1_node_to_set(&graph->set_mpr, node_n1->neigh, node_n1->link, node_n1->table_offset);
      node_n1->neigh->selection_is_mpr = true;
      avl_remove(&graph->set_mpr_candidates, &node_n1->_avl_node);
      free(node_n1);
    }
  }
}

/**
 * Calculate MPR
 * @param domain NHDP domain
 * @param graph neighbor graph instance
 */
void
mpr_calculate_mpr_rfc7181(const struct nhdp_domain *domain, struct neighbor_graph *graph) {
  struct n1_node *n1;
  struct addr_node *n2;
  uint32_t n1_count, n2_count, i;
  
  OONF_DEBUG(LOG_MPR, "Calculate MPR set");
  
  n1_count = graph->set_n1.count;
  n2_count = graph->set_n2.count;

  graph->d_x_y_cache = calloc(n1_count * n2_count, sizeof(uint32_t));
  
  i=0;
  avl_for_each_element(&graph->set_n1, n1, _avl_node) {
    n1->table_offset = i;
    i++;
  }
  
  i=0;
  avl_for_each_element(&graph->set_n2, n2, _avl_node) {
    n2->table_offset = i;
    i += n1_count;
  }

  _calculate_n(domain, graph);
  
  _process_will_always(domain, graph);
  _process_unique_mprs(domain, graph);
  _process_remaining(domain, graph);

  /* TODO Optional optimization step */
}
