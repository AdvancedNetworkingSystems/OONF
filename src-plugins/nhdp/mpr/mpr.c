
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

#include <errno.h>
#include <stdio.h>

#include "common/common_types.h"
#include "common/autobuf.h"
#include "common/avl.h"
#include "common/avl_comp.h"
#include "common/container_of.h"
#include "config/cfg_schema.h"
#include "core/oonf_logging.h"
#include "core/oonf_subsystem.h"
#include "subsystems/oonf_class.h"
#include "subsystems/oonf_rfc5444.h"

#include "nhdp/nhdp.h"
#include "nhdp/nhdp_db.h"
#include "nhdp/nhdp_domain.h"
#include "nhdp/nhdp_interfaces.h"

#include "mpr/mpr.h"

#include "neighbor-graph-flooding.h"
#include "neighbor-graph-routing.h"
#include "selection-rfc7181.h"

/* FIXME remove unneeded includes */

/* prototypes */
static void _early_cfg_init(void);
static int _init(void);
static void _cleanup(void);
static void _cb_update_routing_mpr(struct nhdp_domain *);
static void _cb_update_flooding_mpr(struct nhdp_domain *);

#ifndef NDEBUG
static void _validate_mpr_set(
    const struct nhdp_domain *domain, struct neighbor_graph *graph);
#endif

static const char *_dependencies[] = {
  OONF_CLASS_SUBSYSTEM,
  OONF_TIMER_SUBSYSTEM,
  OONF_NHDP_SUBSYSTEM,
};
static struct oonf_subsystem _nhdp_mpr_subsystem = {
  .name = OONF_MPR_SUBSYSTEM,
  .dependencies = _dependencies,
  .dependencies_count = ARRAYSIZE(_dependencies),
  .descr = "RFC7181 Appendix B MPR Plugin",
  .author = "Jonathan Kirchhoff",
  .early_cfg_init = _early_cfg_init,

  .init = _init,
  .cleanup = _cleanup,
};
DECLARE_OONF_PLUGIN(_nhdp_mpr_subsystem);

static struct nhdp_domain_mpr _mpr_handler = {
  .name = OONF_MPR_SUBSYSTEM,
  .update_routing_mpr = _cb_update_routing_mpr,
  .update_flooding_mpr = _cb_update_flooding_mpr,
};

/* logging sources for NHDP subsystem */
enum oonf_log_source LOG_MPR;

/**
 * Initialize additional logging sources for NHDP
 */
static void
_early_cfg_init(void) {
  LOG_MPR = _nhdp_mpr_subsystem.logging;
}

/**
 * Initialize plugin
 * @return -1 if an error happened, 0 otherwise
 */
static int
_init(void) {
  if (nhdp_domain_mpr_add(&_mpr_handler)) {
    return -1;
  }
  return 0;
}

/**
 * Cleanup plugin
 */
static void
_cleanup(void) {
}

/**
 * Updates the current routing MPR selection in the NHDP database
 * @param graph MPR neighbor graph instance
 */
static void
_update_nhdp_routing(struct nhdp_domain *domain, struct neighbor_graph *graph) {
  struct n1_node *current_mpr_node;
  struct nhdp_link *lnk;
  struct nhdp_neighbor_domaindata *neighbordata;
  
  list_for_each_element(nhdp_db_get_link_list(), lnk, _global_node) {
    neighbordata = nhdp_domain_get_neighbordata(domain, lnk->neigh);
    neighbordata->neigh_is_mpr = false;
    current_mpr_node = avl_find_element(&graph->set_mpr,
        &lnk->neigh->originator,
        current_mpr_node, _avl_node);

    neighbordata->neigh_is_mpr = current_mpr_node != NULL;
  }
}

/**
 * Updates the current flooding MPR selection in the NHDP database
 * @param graph MPR neighbor graph instance
 */
static void
_update_nhdp_flooding(struct neighbor_graph *graph) {
  struct nhdp_link *current_link;
  struct n1_node *current_mpr_node;

  list_for_each_element(nhdp_db_get_link_list(), current_link, _global_node) {
    current_mpr_node = avl_find_element(&graph->set_mpr,
        &current_link->neigh->originator,
        current_mpr_node, _avl_node);

    current_link->neigh_is_flooding_mpr = current_mpr_node != NULL;
  }
}

/**
 * Updates the current flooding MPR selection in the NHDP database
 */
static void
_clear_nhdp_flooding(void) {
  struct nhdp_link *current_link;

//  OONF_DEBUG(LOG_MPR, "Updating FLOODING MPRs");

  list_for_each_element(nhdp_db_get_link_list(), current_link, _global_node) {
    current_link->neigh_is_flooding_mpr = false;
  }
}

/**
 * Update the flooding MPR settings 
 */
static void
_cb_update_flooding_mpr(struct nhdp_domain *domain) {
  struct mpr_flooding_data flooding_data;

  memset(&flooding_data, 0, sizeof(flooding_data));
  
  _clear_nhdp_flooding();
  avl_for_each_element(nhdp_interface_get_tree(), flooding_data.current_interface, _node) {
    OONF_DEBUG(LOG_MPR, "*** Calculate flooding MPRs for interface %s ***",
        nhdp_interface_get_name(flooding_data.current_interface));
    
    mpr_calculate_neighbor_graph_flooding(domain, &flooding_data);
    mpr_calculate_mpr_rfc7181(domain, &flooding_data.neigh_graph);
    mpr_print_sets(domain, &flooding_data.neigh_graph);
#ifndef NDEBUG
    _validate_mpr_set(domain, &flooding_data.neigh_graph);
#endif
    _update_nhdp_flooding(&flooding_data.neigh_graph);
    mpr_clear_neighbor_graph(&flooding_data.neigh_graph);
  }

}

/**
 * Update the routing MPR settings for all domains
 */
static void
_cb_update_routing_mpr(struct nhdp_domain *domain) {
  struct neighbor_graph routing_graph;

  if (domain->mpr != &_mpr_handler) {
    /* we are not the routing MPR for this domain */
    return;
  }
  OONF_DEBUG(LOG_MPR, "*** Calculate routing MPRs for domain %u ***", domain->index);
    
  memset(&routing_graph, 0, sizeof(routing_graph));
  mpr_calculate_neighbor_graph_routing(domain, &routing_graph);
  mpr_calculate_mpr_rfc7181(domain, &routing_graph);
  mpr_print_sets(domain, &routing_graph);
#ifndef NDEBUG
  _validate_mpr_set(domain, &routing_graph);
#endif
  _update_nhdp_routing(domain, &routing_graph);
  mpr_clear_neighbor_graph(&routing_graph);
}

#ifndef NDEBUG

/**
 * Validate the MPR set according to section 18.3 (draft 19)
 * @param domain NHDP domaine
 * @param graph MPR neighbor graph instance
 */
static void
_validate_mpr_set(const struct nhdp_domain *domain, struct neighbor_graph *graph)
{
  struct n1_node *node_n1;
  struct addr_node *n2_addr;
  uint32_t d_y_n1;
  uint32_t d_y_mpr;

  OONF_DEBUG(LOG_MPR, "Validating MPR set");

  /* 
   * First property: If x in N1 has W(x) = WILL_ALWAYS then x is in M. 
   */
  avl_for_each_element(&graph->set_n1, node_n1,
                       _avl_node)
  {
     if (node_n1 && node_n1->link &&
	 node_n1->link->flooding_willingness == RFC7181_WILLINGNESS_ALWAYS) {
      assert(mpr_is_mpr(graph, &node_n1->addr));
    }
  }

  avl_for_each_element(&graph->set_n2, n2_addr, _avl_node)
  {
    d_y_n1 = mpr_calculate_d_of_y_s(domain, graph, n2_addr, &graph->set_n1);
    d_y_mpr = mpr_calculate_d_of_y_s(domain, graph, n2_addr, &graph->set_mpr);
    
    OONF_DEBUG(LOG_MPR, "d_y_n1 = %u", d_y_n1);
    OONF_DEBUG(LOG_MPR, "d_y_mpr = %u", d_y_mpr);

    /*
     * Second property: For any y in N2 that does not have a defined d1(y), 
     * there is at least one element in M that is also in N1(y). This is 
     * equivalent to the requirement that d(y, M) is defined.
     */
    assert(d_y_mpr < RFC7181_METRIC_INFINITE_PATH);

    /*
     * Third property: For any y in N2, d(y,M) = d(y, N1).
     */
    assert(d_y_mpr == d_y_n1);
  }
}
#endif
