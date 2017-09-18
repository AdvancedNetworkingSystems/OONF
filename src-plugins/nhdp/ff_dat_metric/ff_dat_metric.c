
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

#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>

#include "common/common_types.h"
#include "common/isonumber.h"
#include "common/autobuf.h"
#include "core/oonf_cfg.h"
#include "core/oonf_logging.h"
#include "core/oonf_subsystem.h"
#include "subsystems/oonf_class.h"
#include "subsystems/oonf_layer2.h"
#include "subsystems/oonf_rfc5444.h"
#include "subsystems/oonf_timer.h"

#include "nhdp/nhdp.h"
#include "nhdp/nhdp_domain.h"
#include "nhdp/nhdp_interfaces.h"

#include "ff_dat_metric/ff_dat_metric.h"

/* Definitions */
enum {
  DAT_SAMPLING_COUNT = 32,
};

/**
 * Configuration settings of DATFF Metric
 */
struct ff_dat_if_config {
  /*! true if metric should include link speed */
  bool ett;

  /*! selects how loss should be scaled */
  int loss_exponent;

  /*! true if MIC factor should be applied to metric */
  bool mic;

  /*! true if metric should include unicast into calculation */
  bool accept_unicast;

  /*! timer for sampling interface data */
  struct oonf_timer_instance _sampling_timer;

  /*! true if we registered the interface */
  bool registered;
};

/**
 * a single history memory cell, stores the metric
 * data for a single update interval
 */
struct link_datff_bucket {
  /*! number of RFC5444 packets received in time interval */
  uint32_t received;

  /*! sum of received and lost RFC5444 packets in time interval */
  uint32_t total;

  /*! link speed scaled to "minimum speed = 1" */
  uint32_t scaled_speed;
};

/**
 * Additional data for a nhdp_link class for metric calculation
 */
struct link_datff_data {
  /*! timer for measuring lost hellos when no further packets are received */
  struct oonf_timer_instance hello_lost_timer;

  /*! back pointer to NHDP link */
  struct nhdp_link *nhdp_link;

  /*! true if buckets contain data */
  bool contains_data;

  /*! number of missed hellos based on timeouts since last received packet */
  uint32_t missed_hellos;

  /*! current position in history ringbuffer */
  uint16_t activePtr;

  /*! last received packet sequence number */
  uint16_t last_seq_nr;

  /*! remember the last transmitted packet loss for hysteresis (scaled by 1000) */
  int64_t last_packet_success_rate;

  /*! last known hello interval */
  uint64_t hello_interval;

  /*! estimated number of neighbors of this link */
  uint32_t link_neigborhood;

  /*! history ringbuffer */
  struct link_datff_bucket buckets[DAT_SAMPLING_COUNT];
};

/* prototypes */
static void _early_cfg_init(void);
static int _init(void);
static void _cleanup(void);

static void _cb_enable_metric(void);
static void _cb_disable_metric(void);

static void _cb_link_added(void *);
static void _cb_link_changed(void *);
static void _cb_link_removed(void *);

static void _cb_nhdpif_added(void *);
static void _cb_nhdpif_removed(void *);

static void _cb_dat_sampling(struct oonf_timer_instance *);
static void _calculate_link_neighborhood(struct nhdp_link *lnk,
    struct link_datff_data *ldata);
static int _calculate_dynamic_loss_exponent(int link_neigborhood);
static uint32_t _apply_packet_loss(
    struct ff_dat_if_config *ifconfig, struct nhdp_link *lnk,
    struct link_datff_data *ldata,
    uint32_t metric, uint32_t received, uint32_t total);

static void _cb_hello_lost(struct oonf_timer_instance *);

static bool _shall_process_packet(
    struct nhdp_interface *, struct ff_dat_if_config *ifconfig);

static enum rfc5444_result _cb_process_packet(
      struct rfc5444_reader_tlvblock_context *context);

static void _reset_missed_hello_timer(struct link_datff_data *);

static const char *_link_to_string(
    struct nhdp_metric_str *buf, uint32_t metric);
static const char *_path_to_string(
    struct nhdp_metric_str *buf, uint32_t metric, uint8_t hopcount);
static const char *_int_link_to_string(struct nhdp_metric_str *,
    struct nhdp_link *);

static void _cb_cfg_changed(void);

/* plugin declaration */

/**
 * loss scaling options
 */
enum idx_loss_scaling {
  /*! linear loss scaling */
  IDX_LOSS_LINEAR,

  /*! quadratic loss scaling */
  IDX_LOSS_QUADRATIC,

  /*! cubic loss scaling */
  IDX_LOSS_CUBIC,

  /*! dynamic loss scaling */
  IDX_LOSS_DYNAMIC,
};
static const char *LOSS_SCALING[] = {
  [IDX_LOSS_LINEAR]    = "linear",
  [IDX_LOSS_QUADRATIC] = "quadratic",
  [IDX_LOSS_CUBIC]     = "cubic",
  [IDX_LOSS_DYNAMIC]   = "dynamic",
};

static struct cfg_schema_entry _datff_entries[] = {
  CFG_MAP_BOOL(ff_dat_if_config, ett, "ffdat_airtime", "true",
      "Activates the handling of linkspeed within the metric, set to false to"
      " downgrade to ETX metric"),
  CFG_MAP_CHOICE(ff_dat_if_config, loss_exponent, "ffdat_loss_exponent", "linear",
      "scaling of the packet loss influence on the metric", LOSS_SCALING),
  CFG_MAP_BOOL(ff_dat_if_config, mic, "ffdat_mic", "false",
      "Activates the MIC penalty-factor for link metrics"),
  CFG_MAP_BOOL(ff_dat_if_config, accept_unicast, "ffdat_unicast", "false",
      "Include unicast into metric calculation"),
};

/* Subsystem definition */
static struct cfg_schema_section _datff_section = {
  .type = CFG_INTERFACE_SECTION,
  .mode = CFG_INTERFACE_SECTION_MODE,
  .cb_delta_handler = _cb_cfg_changed,
  .entries = _datff_entries,
  .entry_count = ARRAYSIZE(_datff_entries),
};

static const char *_dependencies[] = {
  OONF_CLASS_SUBSYSTEM,
  OONF_LAYER2_SUBSYSTEM,
  OONF_RFC5444_SUBSYSTEM,
  OONF_TIMER_SUBSYSTEM,
  OONF_NHDP_SUBSYSTEM,
  OONF_OS_INTERFACE_SUBSYSTEM,
};
static struct oonf_subsystem _nhdp_ffdat_subsystem = {
  .name = OONF_FF_DAT_METRIC_SUBSYSTEM,
  .dependencies = _dependencies,
  .dependencies_count = ARRAYSIZE(_dependencies),
  .descr = "NHDP Funkfeuer Directional Airtime Metric plugin",
  .author = "Henning Rogge",

  .cfg_section = &_datff_section,

  .early_cfg_init = _early_cfg_init,
  .init = _init,
  .cleanup = _cleanup,
};
DECLARE_OONF_PLUGIN(_nhdp_ffdat_subsystem);

/* RFC5444 packet listener */
static struct oonf_rfc5444_protocol *_protocol;

static struct rfc5444_reader_tlvblock_consumer _packet_consumer = {
  .order = RFC5444_LQ_PARSER_PRIORITY,
  .default_msg_consumer = true,
  .start_callback = _cb_process_packet,
};

/* storage extension and listeners */
static struct oonf_class_extension _link_extenstion = {
  .ext_name = "datff linkmetric",
  .class_name = NHDP_CLASS_LINK,
  .size = sizeof(struct link_datff_data),

  .cb_add = _cb_link_added,
  .cb_change = _cb_link_changed,
  .cb_remove = _cb_link_removed,
};

static struct oonf_class_extension _nhdpif_extenstion = {
  .ext_name = "datff linkmetric",
  .class_name = NHDP_CLASS_INTERFACE,
  .size = sizeof(struct ff_dat_if_config),

  .cb_add = _cb_nhdpif_added,
  .cb_remove = _cb_nhdpif_removed,
};

/* timer for sampling in RFC5444 packets */
static struct oonf_timer_class _sampling_timer_info = {
  .name = "Sampling timer for DATFF-metric",
  .callback = _cb_dat_sampling,
};

/* timer class to measure interval between Hellos */
static struct oonf_timer_class _hello_lost_info = {
  .name = "Hello lost timer for DATFF-metric",
  .callback = _cb_hello_lost,
};

/* nhdp metric handler */
static struct nhdp_domain_metric _datff_handler = {
  .name = OONF_FF_DAT_METRIC_SUBSYSTEM,

  .metric_minimum = DATFF_LINKCOST_MINIMUM,
  .metric_maximum = DATFF_LINKCOST_MAXIMUM,

  .link_to_string = _link_to_string,
  .path_to_string = _path_to_string,
  .internal_link_to_string = _int_link_to_string,

  .enable = _cb_enable_metric,
  .disable = _cb_disable_metric,
};

/* Temporary buffer to sort incoming link speed for median calculation */
static int _rx_sort_array[DAT_SAMPLING_COUNT] = { 0 };

/* ff_dat has multiple logging targets */
enum oonf_log_source LOG_FF_DAT;
enum oonf_log_source LOG_FF_DAT_RAW;

/**
 * Initialize additional logging sources for ffdat
 */
static void
_early_cfg_init(void) {
  LOG_FF_DAT = _nhdp_ffdat_subsystem.logging;
  LOG_FF_DAT_RAW = oonf_log_register_source(OONF_FF_DAT_METRIC_SUBSYSTEM"_raw");
}


/**
 * Initialize plugin
 * @return -1 if an error happened, 0 otherwise
 */
static int
_init(void) {
  if (nhdp_domain_metric_add(&_datff_handler)) {
    return -1;
  }

  if (oonf_class_extension_add(&_nhdpif_extenstion)) {
    nhdp_domain_metric_remove(&_datff_handler);
    return -1;
  }
  if (oonf_class_extension_add(&_link_extenstion)) {
    oonf_class_extension_remove(&_link_extenstion);
    nhdp_domain_metric_remove(&_datff_handler);
    return -1;
  }
  oonf_timer_add(&_sampling_timer_info);
  oonf_timer_add(&_hello_lost_info);

  _protocol = oonf_rfc5444_get_default_protocol();

  oonf_rfc5444_add_protocol_pktseqno(_protocol);
  return 0;
}

/**
 * Cleanup plugin
 */
static void
_cleanup(void) {
  struct nhdp_interface *nhdp_if, *nhdp_if_it;
  struct ff_dat_if_config *ifconfig;

  avl_for_each_element_safe(nhdp_interface_get_tree(), nhdp_if, _node, nhdp_if_it) {
    ifconfig = oonf_class_get_extension(&_nhdpif_extenstion, nhdp_if);
    if (ifconfig->registered) {
      nhdp_interface_remove(nhdp_if);
    }
  }

  /* remove metric from core */
  nhdp_domain_metric_remove(&_datff_handler);

  oonf_rfc5444_remove_protocol_pktseqno(_protocol);
  _protocol = NULL;

  oonf_class_extension_remove(&_link_extenstion);
  oonf_class_extension_remove(&_nhdpif_extenstion);

  oonf_timer_remove(&_sampling_timer_info);
  oonf_timer_remove(&_hello_lost_info);
}

/**
 * Enable metric calculation
 */
static void
_cb_enable_metric(void) {
  struct nhdp_interface *nhdpif;
  struct nhdp_link *lnk;

  avl_for_each_element(nhdp_interface_get_tree(), nhdpif, _node) {
    _cb_nhdpif_added(nhdpif);
  }
  list_for_each_element(nhdp_db_get_link_list(), lnk, _global_node) {
    _cb_link_added(lnk);
  }

  rfc5444_reader_add_packet_consumer(&_protocol->reader, &_packet_consumer, NULL, 0);
}

/**
 * Disable metric calculation
 */
static void
_cb_disable_metric(void) {
  struct nhdp_interface *nhdpif;
  struct nhdp_link *lnk;

  rfc5444_reader_remove_packet_consumer(&_protocol->reader, &_packet_consumer);

  list_for_each_element(nhdp_db_get_link_list(), lnk, _global_node) {
    _cb_link_removed(lnk);
  }
  avl_for_each_element(nhdp_interface_get_tree(), nhdpif, _node) {
    _cb_nhdpif_removed(nhdpif);
  }
}

/**
 * Callback triggered when a new nhdp link is added
 * @param ptr nhdp link
 */
static void
_cb_link_added(void *ptr) {
  struct link_datff_data *data;
  struct nhdp_link *lnk;
  size_t i;

  lnk = ptr;
  data = oonf_class_get_extension(&_link_extenstion, lnk);

  memset(data, 0, sizeof(*data));
  // data->contains_data = false;

  for (i = 0; i<ARRAYSIZE(data->buckets); i++) {
    data->buckets[i].total = 1;
    // data->buckets[i].scaled_speed = 0;
  }

  /* initialize 'hello lost' timer for link */
  data->hello_lost_timer.class = &_hello_lost_info;

  if (lnk->itime_value > 0) {
    data->hello_interval = lnk->itime_value;
  }
  else {
    data->hello_interval = lnk->vtime_value;
  }

  /* start timer */
  _reset_missed_hello_timer(data);

  /* minimal value possible for success rate */
  data->last_packet_success_rate = 1000ll;
}

/**
 * Callback triggered when a new nhdp link is changed
 * @param ptr nhdp link
 */
static void
_cb_link_changed(void *ptr) {
  struct link_datff_data *data;
  struct nhdp_link *lnk;

  lnk = ptr;
  data = oonf_class_get_extension(&_link_extenstion, lnk);

  if (lnk->itime_value > 0) {
    data->hello_interval = lnk->itime_value;
  }
  else {
    data->hello_interval = lnk->vtime_value;
  }

  _reset_missed_hello_timer(data);
}

/**
 * Callback triggered when a nhdp link is removed from the database
 * @param ptr nhdp link
 */
static void
_cb_link_removed(void *ptr) {
  struct link_datff_data *data;

  data = oonf_class_get_extension(&_link_extenstion, ptr);

  oonf_timer_stop(&data->hello_lost_timer);
}

static void
_cb_nhdpif_added(void *ptr) {
  struct ff_dat_if_config *ifconfig;

  ifconfig = oonf_class_get_extension(&_nhdpif_extenstion, ptr);

  ifconfig->_sampling_timer.class = &_sampling_timer_info;
}

static void
_cb_nhdpif_removed(void *ptr) {
  struct ff_dat_if_config *ifconfig;

  ifconfig = oonf_class_get_extension(&_nhdpif_extenstion, ptr);

  if (ifconfig->_sampling_timer.class) {
    oonf_timer_stop(&ifconfig->_sampling_timer);
    ifconfig->_sampling_timer.class = NULL;
  }
}

/**
 * Helper for sorting datarate array
 * @param p1 pointer to integer 1
 * @param p2 pointer to integer 2
 * @return <0, 0 >0 (standard comparator output)
 */
static int
_int_comparator(const void *p1, const void *p2) {
  const int *i1 = (int *)p1;
  const int *i2 = (int *)p2;

  if (*i1 > *i2) {
    return 1;
  }
  else if (*i1 < *i2) {
    return -1;
  }
  return 0;
}

/**
 * Get the median of all recorded link speeds by sorting
 * @param ldata linkdata
 * @return median linkspeed
 */
static int
_get_median_rx_linkspeed(struct link_datff_data *ldata) {
  int zero_count;
  size_t window;
  size_t i;

  zero_count = 0;
  for (i=0; i<ARRAYSIZE(ldata->buckets); i++) {
    _rx_sort_array[i] = ldata->buckets[i].scaled_speed;
    if (_rx_sort_array[i] == 0) {
      zero_count++;
    }
  }

  window = ARRAYSIZE(ldata->buckets) - zero_count;
  if (window == 0) {
    return 1;
  }

  qsort(_rx_sort_array, ARRAYSIZE(ldata->buckets), sizeof(int), _int_comparator);

  return _rx_sort_array[zero_count + window/2];
}

/**
 * Retrieves the speed of a nhdp link, scaled to the minimum link speed
 * of this metric.
 * @param lnk nhdp link
 * @return scaled link speed, 1 if could not be retrieved.
 */
static int
_get_scaled_rx_linkspeed(struct ff_dat_if_config *ifconfig, struct nhdp_link *lnk) {
  struct os_interface *os_if;
  const struct oonf_layer2_data *l2data;
  int64_t rate;
#ifdef OONF_LOG_INFO
  struct netaddr_str nbuf;
#endif

  if (!ifconfig->ett) {
    /* ETT feature is switched off */
    return 1;
  }

  /* get local interface data  */
  os_if = nhdp_interface_get_if_listener(lnk->local_if)->data;

  l2data = oonf_layer2_neigh_query(
      os_if->name, &lnk->remote_mac, OONF_LAYER2_NEIGH_RX_BITRATE);
  if (!l2data) {
    OONF_INFO(LOG_FF_DAT, "Datarate for link %s (%s) not available",
        netaddr_to_string(&nbuf, &lnk->if_addr),
        nhdp_interface_get_name(lnk->local_if));
    return 1;
  }

  /* round up */
  rate = (oonf_layer2_get_value(l2data) + DATFF_LINKSPEED_MINIMUM - 1) / DATFF_LINKSPEED_MINIMUM;
  if (rate < 1) {
    OONF_DEBUG(LOG_FF_DAT, "Datarate for link %s (%s) too small: %"PRId64" / %"PRId64,
        netaddr_to_string(&nbuf, &lnk->if_addr),
        nhdp_interface_get_name(lnk->local_if), rate,
        oonf_layer2_get_value(l2data));
    return 1;
  }
  if (rate > DATFF_LINKSPEED_RANGE) {
    OONF_DEBUG(LOG_FF_DAT, "Datarate for link %s (%s) too large: %"PRId64" / %"PRId64,
        netaddr_to_string(&nbuf, &lnk->if_addr),
        nhdp_interface_get_name(lnk->local_if), rate,
        oonf_layer2_get_value(l2data));

    return DATFF_LINKSPEED_RANGE;
  }
  return rate;
}

/**
 * Timer callback to sample new metric values into bucket
 * @param ptr nhdp link
 */
static void
_cb_dat_sampling(struct oonf_timer_instance *ptr) {
  struct rfc7181_metric_field encoded_metric;
  struct ff_dat_if_config *ifconfig;
  struct link_datff_data *ldata;
  struct nhdp_interface *nhdp_if;
  struct nhdp_link *lnk;
  uint32_t total, received;
  uint64_t metric;
  uint32_t metric_value;
  uint32_t missing_intervals;
  size_t i;
  int rx_bitrate;
  struct netaddr_str nbuf;

  ifconfig = container_of(ptr, struct ff_dat_if_config, _sampling_timer);

  OONF_DEBUG(LOG_FF_DAT, "Calculate Metric from sampled data");

  nhdp_if = oonf_class_get_base(&_nhdpif_extenstion, ifconfig);
  list_for_each_element(&nhdp_if->_links, lnk, _if_node) {
    ldata = oonf_class_get_extension(&_link_extenstion, lnk);
    if (!ldata->contains_data) {
      /* still no data for this link */
      continue;
    }

    /* initialize counter */
    total = 0;
    received = 0;

    /* calculate metric */
    for (i=0; i<ARRAYSIZE(ldata->buckets); i++) {
      received += ldata->buckets[i].received;
      total += ldata->buckets[i].total;
    }

    if (ldata->missed_hellos > 0) {
      missing_intervals = (ldata->missed_hellos * ldata->hello_interval)
          / lnk->local_if->refresh_interval;
      if (missing_intervals > ARRAYSIZE(ldata->buckets)) {
        received = 0;
      }
      else {
        received = (received * (ARRAYSIZE(ldata->buckets) - missing_intervals))
            / ARRAYSIZE(ldata->buckets);
      }
    }

    /* update link speed */
    ldata->buckets[ldata->activePtr].scaled_speed = _get_scaled_rx_linkspeed(ifconfig, lnk);

    OONF_DEBUG(LOG_FF_DAT, "Query incoming linkspeed for link %s: %"PRIu64,
        netaddr_to_string(&nbuf, &lnk->if_addr),
        (uint64_t)(ldata->buckets[ldata->activePtr].scaled_speed) * DATFF_LINKSPEED_MINIMUM);

    /* get median scaled link speed and apply it to metric */
    rx_bitrate = _get_median_rx_linkspeed(ldata);
    if (rx_bitrate > DATFF_LINKSPEED_RANGE) {
      OONF_WARN(LOG_FF_DAT, "Metric overflow %s (%s): %d",
          netaddr_to_string(&nbuf, &lnk->if_addr),
          nhdp_interface_get_name(lnk->local_if), rx_bitrate);
      metric = 1;
    }
    else {
      metric = DATFF_LINKSPEED_RANGE / rx_bitrate;
    }

    /* calculate frame loss, use discrete values */
    if (total == 0 || received == 0
        || received * DATFF_FRAME_SUCCESS_RANGE <= total) {
      metric *= DATFF_FRAME_SUCCESS_RANGE;
    }
    else {
      metric = _apply_packet_loss(ifconfig, lnk, ldata, metric, received, total);
    }

    /* convert into something that can be transmitted over the network */
    if (metric > RFC7181_METRIC_MAX) {
      /* give the metric an upper bound */
      OONF_INFO(LOG_FF_DAT, "Metric overflow %s (%s): %"PRIu64,
          netaddr_to_string(&nbuf, &lnk->if_addr),
          nhdp_interface_get_name(lnk->local_if), metric);
      metric_value = RFC7181_METRIC_MAX;
    }
    else if (metric < RFC7181_METRIC_MIN) {
      OONF_WARN(LOG_FF_DAT, "Metric underflow %s (%s): %"PRIu64,
          netaddr_to_string(&nbuf, &lnk->if_addr),
          nhdp_interface_get_name(lnk->local_if), metric);
      metric_value = RFC7181_METRIC_MIN;
    }
    else if(!rfc7181_metric_encode(&encoded_metric, metric)) {
      metric_value = rfc7181_metric_decode(&encoded_metric);
    }
    else {
      /* metric encoding failed */
      OONF_WARN(LOG_FF_DAT, "Metric encoding failed for link %s (%s): %"PRIu64,
          netaddr_to_string(&nbuf, &lnk->if_addr),
          nhdp_interface_get_name(lnk->local_if), metric);
      metric_value = RFC7181_METRIC_MAX;
    }

    /* set metric for incoming link */
    nhdp_domain_set_incoming_metric(
        &_datff_handler, lnk, metric_value);

    OONF_DEBUG(LOG_FF_DAT, "New sampling rate for link %s (%s):"
        " %d/%d = %u (speed=%"PRIu64 ")\n",
        netaddr_to_string(&nbuf, &lnk->if_addr),
        nhdp_interface_get_name(lnk->local_if),
        received, total, metric_value, (uint64_t)(rx_bitrate) * DATFF_LINKSPEED_MINIMUM);

    /* update rolling buffer */
    ldata->activePtr++;
    if (ldata->activePtr >= ARRAYSIZE(ldata->buckets)) {
      ldata->activePtr = 0;
    }
    ldata->buckets[ldata->activePtr].received = 0;
    ldata->buckets[ldata->activePtr].total = 0;
  }
oonf_timer_set(&ifconfig->_sampling_timer, nhdp_if->refresh_interval);
}

/**
 * Calculate how many neighbors a link has
 * @param lnk nhdp link
 * @param data ff data link data
 */
static void
_calculate_link_neighborhood(struct nhdp_link *lnk, struct link_datff_data *data) {
  struct nhdp_l2hop *l2hop;
  struct nhdp_laddr *laddr;
  int count;

  /* local link neighbors */
  count = lnk->local_if->_link_originators.count;

  /* links twohop neighbors */
  avl_for_each_element(&lnk->_2hop, l2hop, _link_node) {
    if (l2hop->same_interface
        && !avl_find_element(&lnk->local_if->_link_addresses, &l2hop->twohop_addr, laddr, _if_node)) {
      count ++;
    }
  }

  data->link_neigborhood = count;
}

/**
 * Calculate the loss exponentiation based on the link neigborhood size
 * @param link_neigborhood link neighborhood count
 * @return loss exponent
 */
static int
_calculate_dynamic_loss_exponent(int link_neigborhood) {
  if (link_neigborhood < 4) {
    return 1;
  }
  if (link_neigborhood < 9) {
    return 2;
  }
  if (link_neigborhood < 15) {
    return 3;
  }
  return 4;
}

/**
 * Select discrete packet loss values and apply a hysteresis
 * @param lnk nhdp link
 * @param ldata link data object
 * @param metric metric based on linkspeed
 * @param received received packets
 * @param total total packets
 * @return metric including linkspeed and packet loss
 */
static uint32_t
_apply_packet_loss(struct ff_dat_if_config *ifconfig, struct nhdp_link *lnk,
    struct link_datff_data *ldata, uint32_t metric,
    uint32_t received, uint32_t total) {
  int64_t success_scaled_by_1000;
  int loss_exponent;
  int64_t tmp_metric;

  if (received * DATFF_FRAME_SUCCESS_RANGE < total) {
    success_scaled_by_1000 = 1000ll;
  }
  else {
    success_scaled_by_1000 = (((int64_t)DATFF_FRAME_SUCCESS_RANGE * 1000ll) * received) / total;
  }

  if (success_scaled_by_1000 >= ldata->last_packet_success_rate - 750
      && success_scaled_by_1000 <= ldata->last_packet_success_rate + 750
      ) {
    /* keep old loss rate */
    success_scaled_by_1000 = ldata->last_packet_success_rate;
  }
  else {
    /* remember new loss rate */
    ldata->last_packet_success_rate = success_scaled_by_1000;
  }

  _calculate_link_neighborhood(lnk, ldata);

  switch (ifconfig->loss_exponent) {
    case IDX_LOSS_LINEAR:
      loss_exponent = 1;
      break;
    case IDX_LOSS_QUADRATIC:
      loss_exponent = 2;
      break;
    case IDX_LOSS_CUBIC:
      loss_exponent = 3;
      break;
    case IDX_LOSS_DYNAMIC:
      loss_exponent = _calculate_dynamic_loss_exponent(ldata->link_neigborhood);
      break;
    default:
      loss_exponent = 1;
      break;
  }

  tmp_metric = metric;
  while (loss_exponent) {
    tmp_metric = (tmp_metric * (int64_t)DATFF_FRAME_SUCCESS_RANGE * 1000ll + 500ll) / success_scaled_by_1000;
    loss_exponent--;
  }

  if (ifconfig->mic && ldata->link_neigborhood > 1) {
    tmp_metric = tmp_metric * (int64_t)ldata->link_neigborhood;
  }

  if (tmp_metric > RFC7181_METRIC_MAX) {
    return RFC7181_METRIC_MAX;
  }
  if (tmp_metric < RFC7181_METRIC_MIN) {
    return RFC7181_METRIC_MIN;
  }
  return tmp_metric;
}

/**
 * Callback triggered when the next hellos should have been received
 * @param ptr timer instance that fired
 */
static void
_cb_hello_lost(struct oonf_timer_instance *ptr) {
  struct link_datff_data *ldata;

  ldata = container_of(ptr, struct link_datff_data, hello_lost_timer);

  if (ldata->contains_data) {
    ldata->missed_hellos++;

    oonf_timer_set(&ldata->hello_lost_timer, ldata->hello_interval);

    OONF_DEBUG(LOG_FF_DAT, "Missed Hello: %d", ldata->missed_hellos);
  }
}

/**
 * Check if an incoming packet should be used for metric calculation
 * @return true to process packet, false otherwise
 */
static bool
_shall_process_packet(struct nhdp_interface *nhdpif, struct ff_dat_if_config *ifconfig) {
  struct os_interface_listener *if_listener;
  if (_protocol->input.is_multicast) {
    /* accept multicast */
    return true;
  }

  if_listener = nhdp_interface_get_if_listener(nhdpif);
  if (if_listener && if_listener->data && if_listener->data->flags.unicast_only) {
    /* accept unicast for unicast-only interfaces */
    return true;
  }

  return ifconfig->accept_unicast;
}

/**
 * Callback to process all in RFC5444 packets for metric calculation. The
 * Callback ignores all unicast packets.
 * @param context RFC5444 context of the incoming packet
 * @return RFC5444 API result
 */
static enum rfc5444_result
_cb_process_packet(struct rfc5444_reader_tlvblock_context *context) {
  struct ff_dat_if_config *ifconfig;
  struct link_datff_data *ldata;
  struct nhdp_interface *interf;
  struct nhdp_laddr *laddr;
  struct nhdp_link *lnk;
  int total;

#ifdef OONF_LOG_DEBUG_INFO
  struct netaddr_str nbuf;
  struct isonumber_str timebuf;
#endif

  if (!context->has_pktseqno) {
    struct netaddr_str buf;

    OONF_WARN(LOG_FF_DAT, "Neighbor %s does not send packet sequence numbers, cannot collect datff data!",
        netaddr_socket_to_string(&buf, _protocol->input.src_socket));
    return RFC5444_OKAY;
  }

  /* get interface and link */
  interf = nhdp_interface_get(_protocol->input.interface->name);
  if (interf == NULL) {
    /* silently ignore unknown interface */
    return RFC5444_OKAY;
  }

  ifconfig = oonf_class_get_extension(&_nhdpif_extenstion, interf);
  if (!_shall_process_packet(interf, ifconfig)) {
    /* silently ignore unicasts */
    return RFC5444_OKAY;
  }

  laddr = nhdp_interface_get_link_addr(interf, _protocol->input.src_address);
  if (laddr == NULL) {
    /* silently ignore unknown link*/
    return RFC5444_OKAY;
  }

  /* log raw metric data */
  OONF_DEBUG(LOG_FF_DAT_RAW, "%s %s %u %d\n",
          oonf_clock_toIntervalString(&timebuf, oonf_clock_getNow()),
          netaddr_to_string(&nbuf, &laddr->link_addr),
          context->pkt_seqno,
          _get_scaled_rx_linkspeed(ifconfig, laddr->link));

  /* get link and its dat data */
  lnk = laddr->link;
  ldata = oonf_class_get_extension(&_link_extenstion, lnk);

  if (!ldata->contains_data) {
    ldata->contains_data = true;
    ldata->activePtr = 0;
    ldata->buckets[0].received = 1;
    ldata->buckets[0].total = 1;
    ldata->last_seq_nr = context->pkt_seqno;

    return RFC5444_OKAY;
  }

  if (context->pkt_seqno >= ldata->last_seq_nr) {
    total = context->pkt_seqno - ldata->last_seq_nr;
  }
  else {
    total = ((uint32_t)(context->pkt_seqno) + 65536) - (uint32_t)(ldata->last_seq_nr);
  }

  ldata->buckets[ldata->activePtr].received++;
  ldata->buckets[ldata->activePtr].total += total;
  ldata->last_seq_nr = context->pkt_seqno;

  _reset_missed_hello_timer(ldata);

  return RFC5444_OKAY;
}

/**
 * A Hello was received, handle data and timer changes
 * @param data link metric data
 */
static void
_reset_missed_hello_timer(struct link_datff_data *data) {
  oonf_timer_set(&data->hello_lost_timer, (data->hello_interval * 3) / 2);

  data->missed_hellos = 0;
}

/**
 * Convert DATFF metric into string representation
 * @param buf pointer to output buffer
 * @param metric metric value
 * @return pointer to output string
 */
static const char *
_link_to_string(struct nhdp_metric_str *buf, uint32_t metric) {
  uint64_t value;

  if (metric < DATFF_LINKCOST_MINIMUM) {
    value = (uint32_t)DATFF_LINKSPEED_MINIMUM
        * (uint32_t)DATFF_LINKSPEED_RANGE;
  }
  else if (metric > DATFF_LINKCOST_MAXIMUM) {
    strscpy(buf->buf, "infinite", sizeof(*buf));
    return buf->buf;
  }
  else {
    value = (uint32_t)(DATFF_LINKSPEED_MINIMUM) * (uint32_t)(DATFF_LINKSPEED_RANGE) / metric;
  }
  isonumber_from_u64((struct isonumber_str *)buf,
      value, "bit/s", 0, true, false);
  return buf->buf;
}

/**
 * Convert DATFF path metric into string representation
 * @param buf pointer to output buffer
 * @param metric path metric value
 * @return pointer to output string
 */
static const char *
_path_to_string(struct nhdp_metric_str *buf, uint32_t metric, uint8_t hopcount) {
  struct nhdp_metric_str mbuf;

  if (hopcount == 0) {
    /* prevent division by zero */
    hopcount = 1;
  }
  snprintf(buf->buf, sizeof(*buf), "%s (%u hops)",
      _link_to_string(&mbuf, metric / hopcount), hopcount);
  return buf->buf;
}

/**
 * Internal link metric to string processing
 * @param buf output buffer
 * @param lnk nhdp link
 * @return pointer to output buffer
 */
static const char *
_int_link_to_string(struct nhdp_metric_str *buf, struct nhdp_link *lnk) {
  struct link_datff_data *ldata;
  int64_t received = 0, total = 0;
  size_t i;

  ldata = oonf_class_get_extension(&_link_extenstion, lnk);

  for (i=0; i<ARRAYSIZE(ldata->buckets); i++) {
    received += ldata->buckets[i].received;
    total += ldata->buckets[i].total;
  }

  snprintf(buf->buf, sizeof(*buf), "p_recv=%"PRId64",p_total=%"PRId64","
      "speed=%"PRId64",success=%"PRId64",missed_hello=%d,lastseq=%u,lneigh=%d",
      received, total, (int64_t)_get_median_rx_linkspeed(ldata) * (int64_t)1024,
      ldata->last_packet_success_rate, ldata->missed_hellos,
      ldata->last_seq_nr, ldata->link_neigborhood);
  return buf->buf;
}

/**
 * Callback triggered when configuration changes
 */
static void
_cb_cfg_changed(void) {
  struct ff_dat_if_config *ifconfig = NULL;
  struct nhdp_interface *nhdp_if;
  const char *ifname;
  char ifbuf[IF_NAMESIZE];

  ifname = cfg_get_phy_if(ifbuf, _datff_section.section_name);

  if (_datff_section.pre == NULL) {
    /* increase nhdp_interface refcount */
    nhdp_if = nhdp_interface_add(ifname);
  }
  else {
    /* get interface */
    nhdp_if = nhdp_interface_get(ifname);
  }

  if (nhdp_if) {
    /* get block domain extension */
    ifconfig = oonf_class_get_extension(&_nhdpif_extenstion, nhdp_if);
    ifconfig->registered = true;
  }

  if (_datff_section.post == NULL) {
    /* section was removed */
    if (nhdp_if != NULL) {
      ifconfig->registered = false;

      /* decrease nhdp_interface refcount */
      nhdp_interface_remove(nhdp_if);
    }

    nhdp_if = NULL;
  }

  if (!nhdp_if) {
    return;
  }

  if (cfg_schema_tobin(ifconfig, _datff_section.post,
      _datff_entries, ARRAYSIZE(_datff_entries))) {
    OONF_WARN(LOG_FF_DAT, "Cannot convert configuration for "
        OONF_FF_DAT_METRIC_SUBSYSTEM);
    return;
  }

  /* start/change sampling timer */
  oonf_timer_set(&ifconfig->_sampling_timer, 1000);
}
