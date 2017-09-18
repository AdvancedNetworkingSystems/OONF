
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
#include "common/netaddr.h"
#include "common/netaddr_acl.h"
#include "common/string.h"
#include "common/template.h"

#include "core/oonf_logging.h"
#include "core/oonf_subsystem.h"
#include "subsystems/oonf_clock.h"
#include "subsystems/oonf_telnet.h"
#include "subsystems/oonf_viewer.h"

#include "systeminfo/systeminfo.h"

/* definitions */
#define LOG_SYSTEMINFO _oonf_systeminfo_subsystem.logging

/* prototypes */
static int _init(void);
static void _cleanup(void);

static enum oonf_telnet_result _cb_systeminfo(struct oonf_telnet_data *con);
static enum oonf_telnet_result _cb_systeminfo_help(struct oonf_telnet_data *con);

static void _initialize_time_values(struct oonf_viewer_template *template);
static void _initialize_version_values(struct oonf_viewer_template *template);
static void _initialize_memory_values(
    struct oonf_viewer_template *template, struct oonf_class *c);
static void _initialize_timer_values(
    struct oonf_viewer_template *template, struct oonf_timer_class *tc);
static void _initialize_socket_values(
    struct oonf_viewer_template *template, struct oonf_socket_entry *sock);
static void _initialize_logging_values(
    struct oonf_viewer_template *template, enum oonf_log_source source);

static int _cb_create_text_time(struct oonf_viewer_template *);
static int _cb_create_text_version(struct oonf_viewer_template *);
static int _cb_create_text_memory(struct oonf_viewer_template *);
static int _cb_create_text_timer(struct oonf_viewer_template *);
static int _cb_create_text_socket(struct oonf_viewer_template *);
static int _cb_create_text_logging(struct oonf_viewer_template *);

/*
 * list of template keys and corresponding buffers for values.
 *
 * The keys are API, so they should not be changed after published
 */

/*! template key for system wall-time */
#define KEY_TIME_SYSTEM                 "time_system"

/*! template key for internal OONF relative timestamp */
#define KEY_TIME_INTERNAL               "time_internal"

/*! template key for version text */
#define KEY_VERSION_TEXT                "version_text"

/*! template key for version git commit */
#define KEY_VERSION_COMMIT              "version_commit"

/*! template key for statistic object name */
#define KEY_STATISTICS_NAME             "statistics_name"

/*! template key for current memory usage */
#define KEY_MEMORY_USAGE                "memory_usage"

/*! template key for memory freelist size */
#define KEY_MEMORY_FREELIST             "memory_freelist"

/*! template key for total memory allocations */
#define KEY_MEMORY_ALLOC                "memory_alloc"

/*! template key for recycled memory blocks */
#define KEY_MEMORY_RECYCLED             "memory_recycled"

/*! template key for timer usage */
#define KEY_TIMER_USAGE                 "timer_usage"

/*! template key for timer changes */
#define KEY_TIMER_CHANGE                "timer_change"

/*! template key for timer fired */
#define KEY_TIMER_FIRE                  "timer_fire"

/*! template key for timer long usage events*/
#define KEY_TIMER_LONG                  "timer_long"

/*! template key for socket receive events */
#define KEY_SOCKET_RECV                 "socket_recv"

/*! template key for socket send events */
#define KEY_SOCKET_SEND                 "socket_send"

/*! template key for socket long usage events */
#define KEY_SOCKET_LONG                 "socket_long"

/*! template key for name of logging source */
#define KEY_LOG_SOURCE                  "log_source"

/*! template key for number of warnings per logging source */
#define KEY_LOG_WARNINGS                "log_warnings"

/*
 * buffer space for values that will be assembled
 * into the output of the plugin
 */
static struct oonf_walltime_str         _value_system_time;
static struct isonumber_str             _value_internal_time;

static char                             _value_version_text[256];
static char                             _value_version_commit[21];

static char                             _value_stat_name[256];

static struct isonumber_str             _value_memory_usage;
static struct isonumber_str             _value_memory_freelist;
static struct isonumber_str             _value_memory_alloc;
static struct isonumber_str             _value_memory_recycled;

static struct isonumber_str             _value_timer_usage;
static struct isonumber_str             _value_timer_change;
static struct isonumber_str             _value_timer_fire;
static struct isonumber_str             _value_timer_long;

static struct isonumber_str             _value_socket_recv;
static struct isonumber_str             _value_socket_send;
static struct isonumber_str             _value_socket_long;

static char                             _value_log_source[64];
static struct isonumber_str             _value_log_warnings;

/* definition of the template data entries for JSON and table output */
static struct abuf_template_data_entry _tde_time_key[] = {
    { KEY_TIME_SYSTEM, _value_system_time.buf, true },
    { KEY_TIME_INTERNAL, _value_internal_time.buf, false },
};
static struct abuf_template_data_entry _tde_version_key[] = {
    { KEY_VERSION_TEXT, _value_version_text, true },
    { KEY_VERSION_COMMIT, _value_version_commit, true },
};
static struct abuf_template_data_entry _tde_memory_key[] = {
    { KEY_STATISTICS_NAME, _value_stat_name, true },
    { KEY_MEMORY_USAGE, _value_memory_usage.buf, false },
    { KEY_MEMORY_FREELIST, _value_memory_freelist.buf, false },
    { KEY_MEMORY_ALLOC, _value_memory_alloc.buf, false },
    { KEY_MEMORY_RECYCLED, _value_memory_recycled.buf, false },
};
static struct abuf_template_data_entry _tde_timer_key[] = {
    { KEY_STATISTICS_NAME, _value_stat_name, true },
    { KEY_TIMER_USAGE, _value_timer_usage.buf, false },
    { KEY_TIMER_CHANGE, _value_timer_change.buf, false },
    { KEY_TIMER_FIRE, _value_timer_fire.buf, false },
    { KEY_TIMER_LONG, _value_timer_long.buf, false },
};
static struct abuf_template_data_entry _tde_socket_key[] = {
    { KEY_STATISTICS_NAME, _value_stat_name, true },
    { KEY_SOCKET_RECV, _value_socket_recv.buf, false },
    { KEY_SOCKET_SEND, _value_socket_send.buf, false },
    { KEY_SOCKET_LONG, _value_socket_long.buf, false },
};
static struct abuf_template_data_entry _tde_logging_key[] = {
    { KEY_LOG_SOURCE, _value_log_source, true },
    { KEY_LOG_WARNINGS, _value_log_warnings.buf, false },
};

static struct abuf_template_storage _template_storage;

/* Template Data objects (contain one or more Template Data Entries) */
static struct abuf_template_data _td_time[] = {
    { _tde_time_key, ARRAYSIZE(_tde_time_key) },
};
static struct abuf_template_data _td_version[] = {
    { _tde_version_key, ARRAYSIZE(_tde_version_key) },
};
static struct abuf_template_data _td_memory[] = {
    { _tde_memory_key, ARRAYSIZE(_tde_memory_key) },
};
static struct abuf_template_data _td_timer[] = {
    { _tde_timer_key, ARRAYSIZE(_tde_timer_key) },
};
static struct abuf_template_data _td_socket[] = {
    { _tde_socket_key, ARRAYSIZE(_tde_socket_key) },
};
static struct abuf_template_data _td_logging[] = {
    { _tde_logging_key, ARRAYSIZE(_tde_logging_key) },
};

/* OONF viewer templates (based on Template Data arrays) */
static struct oonf_viewer_template _templates[] = {
    {
        .data = _td_time,
        .data_size = ARRAYSIZE(_td_time),
        .json_name = "time",
        .cb_function = _cb_create_text_time,
    },
    {
        .data = _td_version,
        .data_size = ARRAYSIZE(_td_version),
        .json_name = "version",
        .cb_function = _cb_create_text_version,
    },
    {
        .data = _td_memory,
        .data_size = ARRAYSIZE(_td_memory),
        .json_name = "memory",
        .cb_function = _cb_create_text_memory,
    },
    {
        .data = _td_timer,
        .data_size = ARRAYSIZE(_td_timer),
        .json_name = "timer",
        .cb_function = _cb_create_text_timer,
    },
    {
        .data = _td_socket,
        .data_size = ARRAYSIZE(_td_socket),
        .json_name = "socket",
        .cb_function = _cb_create_text_socket,
    },
    {
        .data = _td_logging,
        .data_size = ARRAYSIZE(_td_logging),
        .json_name = "logging",
        .cb_function = _cb_create_text_logging,
    },
};

/* telnet command of this plugin */
static struct oonf_telnet_command _telnet_commands[] = {
    TELNET_CMD(OONF_SYSTEMINFO_SUBSYSTEM, _cb_systeminfo,
        "", .help_handler = _cb_systeminfo_help),
};

/* plugin declaration */
static const char *_dependencies[] = {
  OONF_CLOCK_SUBSYSTEM,
  OONF_TELNET_SUBSYSTEM,
  OONF_VIEWER_SUBSYSTEM,
};

static struct oonf_subsystem _olsrv2_systeminfo_subsystem = {
  .name = OONF_SYSTEMINFO_SUBSYSTEM,
  .dependencies = _dependencies,
  .dependencies_count = ARRAYSIZE(_dependencies),
  .descr = "OLSRv2 system info plugin",
  .author = "Henning Rogge",
  .init = _init,
  .cleanup = _cleanup,
};
DECLARE_OONF_PLUGIN(_olsrv2_systeminfo_subsystem);

/**
 * Initialize plugin
 * @return -1 if an error happened, 0 otherwise
 */
static int
_init(void) {
  oonf_telnet_add(&_telnet_commands[0]);
  return 0;
}

/**
 * Cleanup plugin
 */
static void
_cleanup(void) {
  oonf_telnet_remove(&_telnet_commands[0]);
}

/**
 * Callback for the telnet command of this plugin
 * @param con pointer to telnet session data
 * @return telnet result value
 */
static enum oonf_telnet_result
_cb_systeminfo(struct oonf_telnet_data *con) {
  return oonf_viewer_telnet_handler(con->out, &_template_storage,
      OONF_SYSTEMINFO_SUBSYSTEM, con->parameter,
      _templates, ARRAYSIZE(_templates));
}

/**
 * Callback for the help output of this plugin
 * @param con pointer to telnet session data
 * @return telnet result value
 */
static enum oonf_telnet_result
_cb_systeminfo_help(struct oonf_telnet_data *con) {
  return oonf_viewer_telnet_help(con->out, OONF_SYSTEMINFO_SUBSYSTEM,
      con->parameter, _templates, ARRAYSIZE(_templates));
}

/**
 * Initialize the value buffers for the time of the system
 */
static void
_initialize_time_values(struct oonf_viewer_template *template) {
  oonf_log_get_walltime(&_value_system_time);
  isonumber_from_u64(&_value_internal_time, oonf_clock_getNow(),
      "", 3, false, template->create_raw);
}

/**
 * Initialize the value buffers for the version of OONF
 */
static void
_initialize_version_values(
    struct oonf_viewer_template *template __attribute__((unused))) {
  strscpy(_value_version_text, oonf_log_get_libdata()->version,
      sizeof(_value_version_text));
  strscpy(_value_version_commit, oonf_log_get_libdata()->git_commit,
      sizeof(_value_version_commit));
}

/**
 * Initialize the value buffers for a memory class
 */
static void
_initialize_memory_values(struct oonf_viewer_template *template,
    struct oonf_class *cl) {
  strscpy(_value_stat_name, cl->name, sizeof(_value_stat_name));

  isonumber_from_u64(&_value_memory_usage,
      oonf_class_get_usage(cl), "", 0, false, template->create_raw);
  isonumber_from_u64(&_value_memory_freelist,
      oonf_class_get_free(cl), "", 0, false, template->create_raw);
  isonumber_from_u64(&_value_memory_alloc,
      oonf_class_get_allocations(cl), "", 0, false, template->create_raw);
  isonumber_from_u64(&_value_memory_recycled,
      oonf_class_get_recycled(cl), "", 0, false, template->create_raw);
}

/**
 * Initialize the value buffers for a timer class
 */
static void
_initialize_timer_values(struct oonf_viewer_template *template,
    struct oonf_timer_class *tc) {
  strscpy(_value_stat_name, tc->name, sizeof(_value_stat_name));

  isonumber_from_u64(&_value_timer_usage,
      oonf_timer_get_usage(tc), "", 0, false, template->create_raw);
  isonumber_from_u64(&_value_timer_change,
      oonf_timer_get_changes(tc), "", 0, false, template->create_raw);
  isonumber_from_u64(&_value_timer_fire,
      oonf_timer_get_fired(tc), "", 0, false, template->create_raw);
  isonumber_from_u64(&_value_timer_long,
      oonf_timer_get_long(tc), "", 0, false, template->create_raw);
}

/**
 * Initialize the value buffers for a timer class
 */
static void
_initialize_socket_values(struct oonf_viewer_template *template,
    struct oonf_socket_entry *sock) {
  strscpy(_value_stat_name, sock->name, sizeof(_value_stat_name));

  isonumber_from_u64(&_value_socket_recv,
      oonf_socket_get_recv(sock), "", 0, false, template->create_raw);
  isonumber_from_u64(&_value_socket_send,
      oonf_socket_get_send(sock), "", 0, false, template->create_raw);
  isonumber_from_u64(&_value_socket_long,
      oonf_socket_get_long(sock), "", 0, false, template->create_raw);
}

/**
 * Initialize the value buffers for a logging source
 * @param template viewer template
 * @param source logging source
 */
static void _initialize_logging_values(
    struct oonf_viewer_template *template, enum oonf_log_source source) {
  strscpy(_value_log_source, LOG_SOURCE_NAMES[source],
      sizeof(_value_log_source));
  isonumber_from_u64(&_value_log_warnings,
      oonf_log_get_warning_count(source), "", 0, false, template->create_raw);
}

/**
 * Callback to generate text/json description of current time
 * @param template viewer template
 * @return -1 if an error happened, 0 otherwise
 */
static int
_cb_create_text_time(struct oonf_viewer_template *template) {
  /* initialize values */
  _initialize_time_values(template);

  /* generate template output */
  oonf_viewer_output_print_line(template);
  return 0;
}

/**
 * Callback to generate text/json description of version of OONF
 * @param template viewer template
 * @return -1 if an error happened, 0 otherwise
 */
static int
_cb_create_text_version(struct oonf_viewer_template *template) {
  /* initialize values */
  _initialize_version_values(template);

  /* generate template output */
  oonf_viewer_output_print_line(template);
  return 0;
}

/**
 * Callback to generate text/json description of registered memory blocks
 * @param template viewer template
 * @return -1 if an error happened, 0 otherwise
 */
static int
_cb_create_text_memory(struct oonf_viewer_template *template) {
  struct oonf_class *c;

  avl_for_each_element(oonf_class_get_tree(), c, _node) {
    _initialize_memory_values(template, c);

    /* generate template output */
    oonf_viewer_output_print_line(template);
  }

  return 0;
}

/**
 * Callback to generate text/json description of registered timers
 * @param template viewer template
 * @return -1 if an error happened, 0 otherwise
 */
static int
_cb_create_text_timer(struct oonf_viewer_template *template) {
  struct oonf_timer_class *tc;

  list_for_each_element(oonf_timer_get_list(), tc, _node) {
    _initialize_timer_values(template, tc);

    /* generate template output */
    oonf_viewer_output_print_line(template);
  }

  return 0;
}

/**
 * Callback to generate text/json description of registered sockets
 * @param template viewer template
 * @return -1 if an error happened, 0 otherwise
 */
static int
_cb_create_text_socket(struct oonf_viewer_template *template) {
  struct oonf_socket_entry *sock;

  list_for_each_element(oonf_socket_get_list(), sock, _node) {
    _initialize_socket_values(template, sock);

    /* generate template output */
    oonf_viewer_output_print_line(template);
  }

  return 0;
}

/**
 * Callback to generate text/json description for logging sources
 * @param template viewer template
 * @return -1 if an error happened, 0 otherwise
 */
static int
_cb_create_text_logging(struct oonf_viewer_template *template) {
  enum oonf_log_source source;

  for (source = 0; source < oonf_log_get_sourcecount(); source++) {
    _initialize_logging_values(template, source);

    /* generate template output */
    oonf_viewer_output_print_line(template);
  }

  return 0;
}
