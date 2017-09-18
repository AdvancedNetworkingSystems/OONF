
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

#include "common/common_types.h"
#include "common/autobuf.h"
#include "common/json.h"
#include "common/template.h"
#include "core/oonf_subsystem.h"
#include "subsystems/oonf_telnet.h" /* compile-time dependency */
#include "subsystems/oonf_viewer.h"

/* Definitions */
#define LOG_VIEWER _oonf_viewer_subsystem.logging

/* static function prototypes */
static int _init(void);
static void _cleanup(void);

/* Template call help text for telnet */
static const char _telnet_help[] =
    "\n"
    "Use '" OONF_VIEWER_JSON_FORMAT "' as the first parameter"
    " ' to generate JSON output of all keys/value pairs.\n"
    "Use '" OONF_VIEWER_JSON_RAW_FORMAT "' as the first parameter"
    " to generate JSON output of all keys/value pairs"
    "  without isoprefixes for numbers.\n"
    "Use '" OONF_VIEWER_HEAD_FORMAT "' as the first parameter to"
    " generate a headline for the table.\n"
    "Use '" OONF_VIEWER_RAW_FORMAT "' as the first parameter to"
    " generate a headline for the table without isoprefixes for numbers.\n"
    "You can also add a custom template (text with keys inside)"
    " as the last parameter instead.\n";

/* subsystem definition */
static struct oonf_subsystem _oonf_viewer_subsystem = {
  .name = OONF_VIEWER_SUBSYSTEM,
  .init = _init,
  .cleanup = _cleanup,
};
DECLARE_OONF_PLUGIN(_oonf_viewer_subsystem);

/**
 * Initialize telnet subsystem
 * @return always returns 0
 */
static int
_init(void) {
  return 0;
}

/**
 * Cleanup all allocated data of telnet subsystem
 */
static void
_cleanup(void) {
}

/**
 * Prepare a viewer template for output. The create_json and
 * create_raw variable should be initialized before calling this
 * function.
 * @param template pointer to viewer template
 * @param storage pointer to autobuffer template storage that should
 *     be printed
 * @param out pointer to output buffer
 * @param format pointer to template for output, not used for JSON output
 */
void
oonf_viewer_output_prepare(struct oonf_viewer_template *template,
    struct abuf_template_storage *storage,
    struct autobuf *out, const char *format) {
  template->out = out;

  if (template->create_json) {
    /* JSON format */
    template->_storage = NULL;
    json_init_session(&template->_json, out);

    /* start wrapper object */
    if (!template->create_only_data) {
      json_start_object(&template->_json, NULL);
    }

    /* start object with array */
    json_start_array(&template->_json, template->json_name);
  }
  else {
    if (format && *format == 0) {
      format = NULL;
    }

    /* no JSON format, generate template entries */
    template->_storage = storage;
    abuf_template_init_ext(template->_storage,
        template->data, template->data_size, format);
  }
}

/**
 * Print a link of output as a text table or JSON object. The data
 * for the output is collected from the value buffers of the template
 * storage array stored in the template.
 * @param template pointer to viewer template
 */
void
oonf_viewer_output_print_line(struct oonf_viewer_template *template) {
  if (!template->create_json) {
    abuf_add_template(template->out, template->_storage, false);
    abuf_puts(template->out, "\n");
  }
  else {
    /* JSON output */
    json_start_object(&template->_json, NULL);
    json_print_templates(&template->_json, template->data, template->data_size);
    json_end_object(&template->_json);
  }
}

/**
 * Finalize the output of a text table or JSON object
 * @param template pointer to viewer template
 */
void
oonf_viewer_output_finish(struct oonf_viewer_template *template) {
  if (template->create_json) {
    json_end_array(&template->_json);
    if (!template->create_only_data) {
      json_end_object(&template->_json);
    }
  }
}

/**
 * Print telnet help text for array of templates
 * @param out output buffer
 * @param parameter parameter of help command
 * @param template pointer to template array
 * @param count number of elements in template array
 */
void
oonf_viewer_print_help(struct autobuf *out, const char *parameter,
    struct oonf_viewer_template *template, size_t count) {
  size_t i,j,k;

  if (parameter == NULL || *parameter == 0) {
    abuf_puts(out, "Available subcommands:\n");

    for (i=0; i<count; i++) {
      if (template[i].help_line) {
        abuf_appendf(out, "\t%s: %s\n", template[i].json_name, template[i].help_line);
      }
      else {
        abuf_appendf(out, "\t%s\n", template[i].json_name);
      }
    }

    abuf_puts(out, _telnet_help);
    abuf_puts(out, "Use 'help <command> <subcommand>' to get help about a subcommand\n");
    return;
  }
  for (i=0; i<count; i++) {
    if (strcmp(parameter, template[i].json_name) == 0) {
      if (template[i].help) {
        abuf_puts(out, template[i].help);
      }
      abuf_appendf(out, "The subcommand '%s' has the following keys:\n",
          template[i].json_name);

      for (j=0; j<template[i].data_size; j++) {
        for (k=0; k<template[i].data[j].count; k++) {
          abuf_appendf(out, "\t%%%s%%\n", template[i].data[j].data[k].key);
        }
      }

      abuf_puts(out, _telnet_help);
      return;
    }
  }

  abuf_appendf(out, "Unknown subcommand %s\n", parameter);
}

/**
 * Parse the parameter of a telnet call to run the callback of the
 * corresponding template command. This function both prepares and
 * finishes a viewer template.
 * @param out pointer to output buffer
 * @param storage pointer to autobuffer template storage
 * @param param parameter of telnet call
 * @param templates pointer to array of viewer templates
 * @param count number of elements in viewer template array
 * @return -1 if an error happened, 0 otherwise
 */
int
oonf_viewer_call_subcommands(struct autobuf *out,
    struct abuf_template_storage *storage, const char *param,
    struct oonf_viewer_template *templates, size_t count) {
  const char *next = NULL, *ptr = NULL;
  int result = 0;
  size_t i;
  bool head = false;
  bool json = false;
  bool raw = false;
  bool data = false;

  if ((next = str_hasnextword(param, OONF_VIEWER_HEAD_FORMAT))) {
    head = true;
  }
  else if ((next = str_hasnextword(param, OONF_VIEWER_JSON_FORMAT))) {
    json = true;
  }
  else if ((next = str_hasnextword(param, OONF_VIEWER_RAW_FORMAT))) {
    raw = true;
  }
  else if ((next = str_hasnextword(param, OONF_VIEWER_JSON_RAW_FORMAT))) {
    json = true;
    raw = true;
  }
  else if ((next = str_hasnextword(param, OONF_VIEWER_DATA_FORMAT))) {
    json = true;
    data = true;
  }
  else if ((next = str_hasnextword(param, OONF_VIEWER_DATA_RAW_FORMAT))) {
    json = true;
    raw = true;
    data = true;
  }
  else {
    next = param;
  }

  for (i=0; i<count; i++) {
    if ((ptr = str_hasnextword(next, templates[i].json_name))) {
      templates[i].create_json = json;
      templates[i].create_raw = raw;
      templates[i].create_only_data = data;

      oonf_viewer_output_prepare(&templates[i], storage, out, ptr);

      if (head) {
        abuf_add_template(out, templates[i]._storage, true);
        abuf_puts(out, "\n");
      }
      else {
        result = templates[i].cb_function(&templates[i]);
      }

      oonf_viewer_output_finish(&templates[i]);

      return result;
    }
  }
  return 1;
}

/**
 * Handles a telnet command for a viewer including error handling
 * @param out output buffer
 * @param storage template storage object
 * @param cmd telnet command
 * @param param telnet parameter(s)
 * @param templates template viewer array
 * @param count number of template viewer entries
 * @return telnet return code
 */
enum oonf_telnet_result
oonf_viewer_telnet_handler(struct autobuf *out,
    struct abuf_template_storage *storage, const char *cmd, const char *param,
    struct oonf_viewer_template *templates, size_t count) {
  int result;

  /* sanity check */
  if (param == NULL || *param == 0) {
    abuf_appendf(out, "Error, '%s' command needs a parameter\n", cmd);
  }

  /* call template based subcommands */
  result = oonf_viewer_call_subcommands(out, storage, param, templates, count);
  if (result == 0) {
    return TELNET_RESULT_ACTIVE;
  }
  if (result < 0) {
    return TELNET_RESULT_INTERNAL_ERROR;
  }

  abuf_appendf(out, "Unknown parameter for command '%s': %s\n", cmd, param);
  return TELNET_RESULT_ACTIVE;
}

/**
 * Handles a telnet help command for a viewer including error handling
 * @param out output buffer
 * @param cmd telnet command
 * @param parameter telnet parameter(s)
 * @param template viewer template array
 * @param count number of template viewer entries
 * @return telnet return coce
 */
enum oonf_telnet_result
oonf_viewer_telnet_help(struct autobuf *out,
    const char *cmd, const char *parameter,
    struct oonf_viewer_template *template, size_t count) {
  const char *next;

  /* skip the layer2info command, NULL output is acceptable */
  next = str_hasnextword(parameter, cmd);

  /* print out own help text */
  abuf_appendf(out, "%s command:\n", cmd);
  oonf_viewer_print_help(out, next, template, count);

  return TELNET_RESULT_ACTIVE;
}
