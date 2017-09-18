
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

#include "common/common_types.h"
#include "common/autobuf.h"
#include "core/oonf_cfg.h"
#include "core/oonf_logging.h"
#include "core/oonf_subsystem.h"
#include "subsystems/oonf_class.h"
#include "subsystems/oonf_rfc5444.h"
#include "subsystems/oonf_timer.h"

#include "nhdp/nhdp_hysteresis.h"
#include "nhdp/nhdp_interfaces.h"

#include "hysteresis_olsrv1/hysteresis_olsrv1.h"

/* definitions and constants */
#define LOG_HYSTERESIS_OLSRV1 _olsrv2_hysteresis_olsrv1_subsystem.logging

/**
 * hysteresis plugin configuration
 */
struct _config {
  /*! hysteresis threshold to accept a link (multiplied by 1000) */
  int accept;

  /*! hysteresis threshold to reject a link (multiplied by 1000) */
  int reject;

  /*! alpha factor for exponential aging (multiplied by 1000) */
  int scaling;
};

/**
 * extension of nhdp_link class for hysteresis calculation
 */
struct link_hysteresis_data {
  /*! timer until the next NHDP Hello should arrive */
  struct oonf_timer_instance interval_timer;

  /*! back pointer to NHDP link */
  struct nhdp_link *nhdp_link;

  /*! itime time delivered by neighbors Hello */
  uint64_t itime;

  /*! current hysteresis quality of this link */
  int32_t quality;

  /*! true if the link is considered pending */
  bool pending;

  /*! true if the link is considered lost */
  bool lost;
};

/* prototypes */
static int _init(void);
static void _cleanup(void);

static void _update_hysteresis(struct nhdp_link *,
    struct link_hysteresis_data *, bool);

static void _cb_link_added(void *);
static void _cb_link_removed(void *);

static void _cb_update_hysteresis(struct nhdp_link *,
    struct rfc5444_reader_tlvblock_context *context);
static bool _cb_is_pending(struct nhdp_link *);
static bool _cb_is_lost(struct nhdp_link *);
static const char *_cb_to_string(
    struct nhdp_hysteresis_str *, struct nhdp_link *);

static void _cb_timer_hello_lost(struct oonf_timer_instance *);
static void _cb_cfg_changed(void);
static int _cb_cfg_validate(const char *section_name,
    struct cfg_named_section *, struct autobuf *);

/* configuration options */
static struct cfg_schema_entry _hysteresis_entries[] = {
  CFG_MAP_INT32_MINMAX(_config, accept, "accept", "0.7",
      "link quality to consider a link up", 3, false, 0, 1000),
  CFG_MAP_INT32_MINMAX(_config, reject, "reject", "0.3",
      "link quality to consider a link down", 3, false, 0, 1000),
  CFG_MAP_INT32_MINMAX(_config, scaling, "scaling", "0.25",
      "exponential aging to control speed of link hysteresis", 3, false, 1, 1000),
};

static struct cfg_schema_section _hysteresis_section = {
  .type = OONF_HYSTERESIS_OLSRV1_SUBSYSTEM,
  .cb_delta_handler = _cb_cfg_changed,
  .cb_validate = _cb_cfg_validate,
  .entries = _hysteresis_entries,
  .entry_count = ARRAYSIZE(_hysteresis_entries),
};

static struct _config _hysteresis_config;

/* plugin declaration */
static const char *_dependencies[] = {
  OONF_CLASS_SUBSYSTEM,
  OONF_RFC5444_SUBSYSTEM,
  OONF_TIMER_SUBSYSTEM,
  OONF_NHDP_SUBSYSTEM,
};
static struct oonf_subsystem _olsrv2_hysteresis_olsrv1_subsystem = {
  .name = OONF_HYSTERESIS_OLSRV1_SUBSYSTEM,
  .dependencies = _dependencies,
  .dependencies_count = ARRAYSIZE(_dependencies),
  .descr = "OONFD2 olsrv1-style hysteresis plugin",
  .author = "Henning Rogge",

  .cfg_section = &_hysteresis_section,

  .init = _init,
  .cleanup = _cleanup,
};
DECLARE_OONF_PLUGIN(_olsrv2_hysteresis_olsrv1_subsystem);

/* storage extension for nhdp_link */
static struct oonf_class_extension _link_extenstion = {
  .ext_name = OONF_HYSTERESIS_OLSRV1_SUBSYSTEM,
  .class_name = NHDP_CLASS_LINK,
  .size = sizeof(struct link_hysteresis_data),
  .cb_add = _cb_link_added,
  .cb_remove = _cb_link_removed,
};

/* timer class to measure itime between Hellos */
static struct oonf_timer_class _hello_timer_info = {
  .name = "Hello itime timeout for hysteresis",
  .callback = _cb_timer_hello_lost,
};

/* hysteresis handler */
static struct nhdp_hysteresis_handler _hysteresis_handler = {
  .name = "hysteresis_olsrv1",
  .update_hysteresis = _cb_update_hysteresis,
  .is_pending = _cb_is_pending,
  .is_lost = _cb_is_lost,
  .to_string = _cb_to_string,
};

/**
 * Initialize plugin
 * @return -1 if an error happened, 0 otherwise
 */
static int
_init(void) {
  if (oonf_class_is_extension_registered(&_link_extenstion)) {
    struct nhdp_link *lnk;

    /* add all custom extensions for link */
    list_for_each_element(nhdp_db_get_link_list(), lnk, _global_node) {
      _cb_link_added(lnk);
    }
  }
  else if (oonf_class_extension_add(&_link_extenstion)) {
    return -1;
  }

  nhdp_hysteresis_set_handler(&_hysteresis_handler);
  return 0;
}

/**
 * Cleanup plugin
 */
static void
_cleanup(void) {
  struct nhdp_link *lnk;

  /* remove all custom extensions for link */
  list_for_each_element(nhdp_db_get_link_list(), lnk, _global_node) {
    _cb_link_removed(lnk);
  }

  nhdp_hysteresis_set_handler(NULL);
  oonf_class_extension_remove(&_link_extenstion);
}

/**
 * Update the quality value of a link
 * @param lnk pointer to nhdp link
 * @param data pointer to link hysteresis data
 * @param lost true if hello was lost, false if hello was received
 */
static void
_update_hysteresis(struct nhdp_link *lnk,
    struct link_hysteresis_data *data, bool lost) {
  /* calculate exponential aging */
  data->quality = data->quality * (1000 - _hysteresis_config.scaling);
  data->quality = (data->quality + 999) / 1000;
  if (!lost) {
    data->quality += _hysteresis_config.scaling;
  }

  if (!data->pending && !data->lost) {
    if (data->quality < _hysteresis_config.reject) {
      data->lost = true;
      nhdp_db_link_update_status(lnk);
    }
  }
  else {
    if (data->quality > _hysteresis_config.accept) {
      data->pending = false;
      data->lost = false;
      nhdp_db_link_update_status(lnk);
    }
  }
}

/**
 * Callback triggered when a new nhdp link is added
 * @param ptr nhdp link
 */
static void
_cb_link_added(void *ptr) {
  struct link_hysteresis_data *data;
  data = oonf_class_get_extension(&_link_extenstion, ptr);

  memset(data, 0, sizeof(*data));
  data->pending = true;
  data->nhdp_link = ptr;

  data->interval_timer.class = &_hello_timer_info;
}

/**
 * Callback triggered when a nhdp link will be removed
 * @param ptr nhdp link
 */
static void
_cb_link_removed(void *ptr) {
  struct link_hysteresis_data *data;
  data = oonf_class_get_extension(&_link_extenstion, ptr);

  oonf_timer_stop(&data->interval_timer);
}

/**
 * Callback for hysteresis handler which is triggered to
 * update the hysteresis when a HELLO is received.
 * @param lnk nhdp link
 * @param context RFC5444 tlvblock reader context
 */
static void
_cb_update_hysteresis(struct nhdp_link *lnk,
    struct rfc5444_reader_tlvblock_context *context __attribute__((unused))) {
  struct link_hysteresis_data *data;

  data = oonf_class_get_extension(&_link_extenstion, lnk);

  /* update hysteresis because of received hello */
  _update_hysteresis(lnk, data, false);

  /* store itime */
  data->itime = lnk->itime_value;

  /* first timer gets a delay */
  if (data->itime == 0) {
    data->itime = lnk->vtime_value;
  }
  oonf_timer_set(&data->interval_timer, (data->itime * 3) / 2);
}

/**
 * Callback for hysteresis handler to check if link is pending
 * @param lnk nhdp link
 * @return true if link is pending, false otherwise
 */
static bool
_cb_is_pending(struct nhdp_link *lnk) {
  struct link_hysteresis_data *data;

  data = oonf_class_get_extension(&_link_extenstion, lnk);
  return data->pending;
}

/**
 * Callback for hysteresis handler to check if link is lost
 * @param lnk nhdp link
 * @return true if link is lost, false otherwise
 */
static bool
_cb_is_lost(struct nhdp_link *lnk) {
  struct link_hysteresis_data *data;

  data = oonf_class_get_extension(&_link_extenstion, lnk);
  return data->lost;
}

/**
 * Callback for hysteresis handler to get a human readable
 * from of the current hysteresis data.
 * @param buf output buffer
 * @param lnk nhdp link
 * @return pointer to output buffer
 */
static const char *
_cb_to_string(struct nhdp_hysteresis_str *buf, struct nhdp_link *lnk) {
  struct isonumber_str fbuf;
  struct link_hysteresis_data *data;

  data = oonf_class_get_extension(&_link_extenstion, lnk);

  snprintf(buf->buf, sizeof(*buf), "quality=%s",
      isonumber_from_s64(&fbuf, data->quality, "", 3, false, true));

  return buf->buf;
}

/**
 * Timer callback triggered when Hello was lost
 * @param ptr timer instance that fired
 */
static void
_cb_timer_hello_lost(struct oonf_timer_instance *ptr) {
  struct link_hysteresis_data *data;

  data = container_of(ptr, struct link_hysteresis_data, interval_timer);

  /* update hysteresis because of lost Hello */
  _update_hysteresis(data->nhdp_link, data, true);

  /* reactivate timer */
  oonf_timer_set(&data->interval_timer, data->itime);
}

/**
 * Callback triggered when configuration changes
 */
static void
_cb_cfg_changed(void) {
  if (cfg_schema_tobin(&_hysteresis_config, _hysteresis_section.post,
      _hysteresis_entries, ARRAYSIZE(_hysteresis_entries))) {
    OONF_WARN(LOG_HYSTERESIS_OLSRV1, "Could not convert "
        OONF_HYSTERESIS_OLSRV1_SUBSYSTEM " plugin configuration");
  }
}

/**
 * Callback triggered to check validity of configuration section
 * @param section_name name of section
 * @param named configuration data of section
 * @param out output buffer for error messages
 * @return 0 if data is okay, -1 if an error happened
 */
static int
_cb_cfg_validate(const char *section_name,
    struct cfg_named_section *named, struct autobuf *out) {
  struct _config cfg;
  struct isonumber_str buf1, buf2;

  if (cfg_schema_tobin(&cfg, named, _hysteresis_entries, ARRAYSIZE(_hysteresis_entries))) {
    cfg_append_printable_line(out, "Could not parse hysteresis configuration in section %s",
        section_name);
    return -1;
  }

  if (cfg.accept <= cfg.reject) {
    cfg_append_printable_line(out, "hysteresis accept (%s) is not smaller than reject (%s) value",
        isonumber_from_s64(&buf1, cfg.accept, "", 3, false, true),
        isonumber_from_s64(&buf2, cfg.reject, "", 3, false, true));
    return -1;
  }
  return 0;
}
