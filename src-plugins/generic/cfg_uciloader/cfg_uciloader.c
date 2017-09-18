
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
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <uci.h>
#undef container_of

#include "common/common_types.h"
#include "common/autobuf.h"
#include "config/cfg_io.h"
#include "config/cfg.h"
#include "core/oonf_subsystem.h"

#include "core/oonf_cfg.h"

#include "cfg_uciloader/cfg_uciloader.h"

static void _early_cfg_init(void);
static void _cleanup(void);

static struct cfg_db *_cb_uci_load(const char *param, struct autobuf *log);
static int _load_section(struct uci_section *sec, struct cfg_db *db, const char *type, const char *name, struct autobuf *log);

static int _get_phy_ifname(char *phy_ifname, const char *ifname);

static struct oonf_subsystem _oonf_cfg_uciloader_subsystem = {
  .name = OONF_CFG_UCILOADER_SUBSYSTEM,
  .descr = "OONF uci handler for configuration system",
  .author = "Henning Rogge",

  .cleanup = _cleanup,
  .early_cfg_init = _early_cfg_init,

  .no_logging = true,
};
DECLARE_OONF_PLUGIN(_oonf_cfg_uciloader_subsystem);

static struct cfg_io _cfg_io_uci = {
  .name = "uci",
  .load = _cb_uci_load,
  .def = false,
};

/**
 * Callback to hook plugin into configuration system.
 */
static void
_early_cfg_init(void)
{
  cfg_io_add(oonf_cfg_get_instance(), &_cfg_io_uci);
  cfg_set_ifname_handler(_get_phy_ifname);
}

/**
 * Destructor of plugin
 */
static void
_cleanup(void)
{
  cfg_io_remove(oonf_cfg_get_instance(), &_cfg_io_uci);
  cfg_set_ifname_handler(NULL);
}

/*
 * Definition of the uci-io handler.
 *
 * This handler can read files and use a parser to
 * translate them into a configuration database
 *
 * The parameter of this parser has to be a filename
 */

/**
 * Reads a file from a filesystem, parse it with the help of a
 * configuration parser and returns a configuration database.
 * @param param file to be read
 * @param log autobuffer for logging purpose
 * @return pointer to configuration database, NULL if an error happened
 */
static struct cfg_db *
_cb_uci_load(const char *param, struct autobuf *log) {
  struct uci_context *ctx = NULL;
  struct uci_package *p = NULL;
  struct uci_element *s, *i;

  struct cfg_db *db = NULL;

  char *err = NULL;

  ctx = uci_alloc_context();
  if (!ctx) {
    cfg_append_printable_line(log, "Could not allocate uci context");
    return NULL;
  }

  if (uci_load(ctx, param, &p)) {
    goto uci_error;
  }

  db = cfg_db_add();
  if (!db) {
    goto loading_error;
  }

  uci_foreach_element(&p->sections, s) {
    struct uci_section *sec = uci_to_section(s);
    struct uci_option *names;

    names = uci_lookup_option(ctx, sec, UCI_OPTION_FOR_SECTION_NAME);
    if (!names) {
      /* a single unnamed section */
      if (_load_section(sec, db, sec->type, NULL, log)) {
        goto loading_error;
      }
    }
    else {
      switch (names->type) {
        case UCI_TYPE_STRING:
          /* section with a single name */
          if (_load_section(sec, db, sec->type, names->v.string, log)) {
            goto loading_error;
          }
          break;
        case UCI_TYPE_LIST:
          /* section with multiple names */
          uci_foreach_element(&names->v.list, i) {
            if (_load_section(sec, db, sec->type, i->name, log)) {
              goto loading_error;
            }
          }
          break;
        default:
          cfg_append_printable_line(log, "# uci-error: unknown type for option '%s'\n", names->e.name);
          goto loading_error;
      }
    }
  }

  uci_free_context(ctx);
  return db;

uci_error:
  uci_get_errorstr(ctx, &err, NULL);
  abuf_appendf(log, "%s\n", err);
  free(err);

loading_error:
  if (db) {
    cfg_db_remove(db);
  }

  uci_free_context(ctx);
  return NULL;
}

static int
_load_section(struct uci_section *sec, struct cfg_db *db, const char *type, const char *name, struct autobuf *log) {
  struct uci_element *o, *i;
  struct cfg_named_section *db_section;

  if (name) {
    db_section = cfg_db_add_namedsection(db, type, name);
  }
  else {
    db_section = cfg_db_add_unnamedsection(db, type);
  }

  if (!db_section) {
    cfg_append_printable_line(log, "Could not allocate configuration section (%s/%s)",
        db_section->section_type->type, db_section->name);
    return -1;
  }

  uci_foreach_element(&sec->options, o) {
    struct uci_option *opt = uci_to_option(o);
    if (strcmp(opt->e.name, UCI_OPTION_FOR_SECTION_NAME) == 0) {
      continue;
    }

    switch(opt->type) {
      case UCI_TYPE_STRING:
        if (!cfg_db_add_entry(db, db_section->section_type->type,
            db_section->name, opt->e.name, opt->v.string)) {
          cfg_append_printable_line(log, "Could not allocate configuration entry (%s/%s/%s)='%s'",
              db_section->section_type->type, db_section->name, opt->e.name, opt->v.string);
                return -1;
        };
        break;
      case UCI_TYPE_LIST:
        uci_foreach_element(&opt->v.list, i) {
          if (!cfg_db_add_entry(db, db_section->section_type->type,
              db_section->name, opt->e.name, i->name)) {
            cfg_append_printable_line(log, "Could not allocate configuration entry (%s/%s/%s)='%s'",
                db_section->section_type->type, db_section->name, opt->e.name, i->name);
                  return -1;
          };
        }
        break;
      default:
        cfg_append_printable_line(log, "# uci-error: unknown type for option '%s'\n", opt->e.name);
        return -1;
    }
  }
  return 0;
}

/**
 * Convert a logical interface name into a physical one
 * @param phy_ifname buffer for physical interface name
 * @param ifname logical interface name
 * @return 0 if conversion was possible, negative if an error happened
 */
static int
_get_phy_ifname(char *phy_ifname, const char *ifname) {
  struct uci_context *ctx = NULL;
  struct uci_package *p = NULL;
  struct uci_section *sec;
  struct uci_option *opt;

  int result = 0;

  ctx = uci_alloc_context();
  if (!ctx) {
    return -1;
  }

  if (uci_load(ctx, "/etc/config/network", &p)) {
    result = -2;
    goto uci_error;
  }

  sec = uci_lookup_section(ctx, p, ifname);
  if (!sec) {
    /* interface section does not exist */
    result = -3;
    goto uci_error;
  }

  if (!sec->type || strcmp(sec->type, "interface") != 0) {
    result = -4;
    goto uci_error;
  }

  opt = uci_lookup_option(ctx, sec, "ifname");
  if (!opt) {
    result = -5;
    goto uci_error;
  }

  strscpy(phy_ifname, opt->v.string, IF_NAMESIZE);

uci_error:
  uci_free_context(ctx);
  return result;
}
