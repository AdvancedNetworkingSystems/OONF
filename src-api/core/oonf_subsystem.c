
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

#include <assert.h>
#include <dlfcn.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#include "common/autobuf.h"
#include "common/common_types.h"
#include "common/list.h"
#include "common/avl.h"
#include "common/avl_comp.h"
#include "common/template.h"
#include "config/cfg_schema.h"
#include "core/oonf_libdata.h"
#include "core/oonf_logging.h"
#include "core/oonf_subsystem.h"

/* constants */
enum {
  IDX_DLOPEN_LIB,
  IDX_DLOPEN_PATH,
  IDX_DLOPEN_PRE,
  IDX_DLOPEN_POST,
  IDX_DLOPEN_VER,
};

static void _init_plugin_tree(void);
static int _init_plugin(struct oonf_subsystem *plugin);
static void _cleanup_plugin(struct oonf_subsystem *plugin);
static int _unload_plugin(struct oonf_subsystem *plugin, bool cleanup);
static void *_open_plugin(const char *filename, int *idx);
static void *_open_plugin_template(const char *filename, int template, int mode);

/*
 * List of paths to look for plugins
 *
 * The elements of the patterns are:
 *
 * %LIB%:  name of the plugin
 * %PATH%: local path (linux: ".")
 *
 * %PRE%:  shared library prefix  (linux: "liboonf_")
 * %POST%: shared library postfix (linux: ".so")
 * %VER:   version number (e.g. "0.1.0")
 */
static const char *DLOPEN_PATTERNS[] = {
  "%PATH%/%PRE%%LIB%%POST%.%VER%",
  "%PATH%/%PRE%%LIB%%POST%",
  "%PRE%%LIB%%POST%.%VER%",
  "%PRE%%LIB%%POST%",
};

/*! global tree of plugins */
struct avl_tree oonf_plugin_tree;

static bool _plugin_tree_initialized = false;

/* library loading patterns */
static struct abuf_template_data_entry _dlopen_data[] = {
  [IDX_DLOPEN_LIB]     =  { .key = "LIB" },
  [IDX_DLOPEN_PATH]    =  { .key = "PATH", .value = "." },
  [IDX_DLOPEN_PRE]     =  { .key = "PRE" },
  [IDX_DLOPEN_POST]    =  { .key = "POST" },
  [IDX_DLOPEN_VER]     =  { .key = "VER" },
};

static struct autobuf _dlopen_data_buffer;

/**
 * Initialize the plugin loader system
 * @return -1 if an error happened, 0 otherwise
 */
int
oonf_subsystem_init(void) {
  if (abuf_init(&_dlopen_data_buffer)) {
    return -1;
  }

  _init_plugin_tree();

  /* load predefined values for dlopen templates */
  _dlopen_data[IDX_DLOPEN_PRE].value =
      oonf_log_get_libdata()->sharedlibrary_prefix;
  _dlopen_data[IDX_DLOPEN_POST].value =
      oonf_log_get_libdata()->sharedlibrary_postfix;
  _dlopen_data[IDX_DLOPEN_VER].value =
      oonf_log_get_libdata()->version;
  return 0;
}

/**
 * Disable and unload all plugins
 */
void
oonf_subsystem_cleanup(void) {
  struct oonf_subsystem *plugin, *iterator;

  avl_for_each_element_safe(&oonf_plugin_tree, plugin, _node, iterator) {
    _unload_plugin(plugin, true);
  }

  abuf_free(&_dlopen_data_buffer);
}

/**
 * Add the configuration of a subsystem to the global schema
 * and do early initialization
 * @param schema pointer to configuration schema
 * @param subsystem pointer to subsystem
 */
void
oonf_subsystem_configure(struct cfg_schema *schema,
    struct oonf_subsystem *subsystem) {
  struct cfg_schema_section *schema_section;

  assert(subsystem->name);

  OONF_INFO(LOG_SUBSYSTEMS, "Configure subsystem %s", subsystem->name);

  /* add logging source */
  if (!subsystem->no_logging) {
    OONF_DEBUG(LOG_SUBSYSTEMS, "(%s) Register logging source",
        subsystem->name);
    subsystem->logging = oonf_log_register_source(subsystem->name);
  }
  else {
    subsystem->logging = LOG_MAIN;
  }

  /* early configuration */
  if (subsystem->early_cfg_init) {
    OONF_DEBUG(LOG_SUBSYSTEMS, "(%s) Call 'early_cfg_init() callback",
        subsystem->name);
    subsystem->early_cfg_init();
  }

  /* add schema sections to global schema */
  schema_section = subsystem->cfg_section;
  while (schema_section) {
    OONF_DEBUG(LOG_SUBSYSTEMS, "(%s) Add configuration section %s",
        subsystem->name, schema_section->type);

    cfg_schema_add_section(schema, schema_section);
    schema_section = schema_section->next_section;
  }
}

/**
 * Remove the configuration of a subsystem from the global schema
 * @param schema pointer to configuration schema
 * @param subsystem pointer to subsystem
 */
void
oonf_subsystem_unconfigure(struct cfg_schema *schema,
    struct oonf_subsystem *subsystem) {
  struct cfg_schema_section *schema_section;

  OONF_INFO(LOG_SUBSYSTEMS, "Unregister subsystem %s", subsystem->name);

  schema_section = subsystem->cfg_section;
  while (schema_section) {
    OONF_DEBUG(LOG_SUBSYSTEMS, "(%s) Unregister configuration section %s",
        subsystem->name, schema_section->type);
    cfg_schema_remove_section(schema, schema_section);
    schema_section = schema_section->next_section;
  }
}

/**
 * Sets the user-configured path to look for plugins
 * @param path default path
 */
void
oonf_subsystem_set_path(const char *path) {
  _dlopen_data[IDX_DLOPEN_PATH].value = path;
}

/**
 * Tell plugins to begin to shutdown
 */
void
oonf_subsystem_initiate_shutdown(void) {
  struct oonf_subsystem *plugin, *iterator;

  avl_for_each_element_safe(&oonf_plugin_tree, plugin, _node, iterator) {
    if (plugin->initiate_shutdown) {
      OONF_DEBUG(LOG_PLUGINS, "Initiate Shutdown: %s", plugin->name);
      plugin->initiate_shutdown();
    }
  }
}

/**
 * This function is called by the constructor of a plugin to
 * insert the plugin into the global list. It will be called before
 * any subsystem was initialized!
 * @param plugin pointer to plugin definition
 */
void
oonf_subsystem_hook(struct oonf_subsystem *plugin) {
  /* make sure plugin tree is initialized */
  _init_plugin_tree();

  /* check if plugin is already in tree */
  if (oonf_subsystem_get(plugin->name)) {
    return;
  }

  /* hook plugin into avl tree */
  plugin->_node.key = plugin->name;
  avl_insert(&oonf_plugin_tree, &plugin->_node);
}

/**
 * Extracts the plugin name from a library name, including optional path,
 * prefix and/or postfix
 * @param pluginname buffer for plugin name
 * @param libname library name
 */
void
oonf_subsystem_extract_name(
    struct oonf_subsystem_namebuf *pluginname, const char *libname) {
  size_t start, end;
  char *ptr;

  memset(pluginname, 0, sizeof(*pluginname));

  start = 0;
  end = strlen(libname);

  /* remove path */
  if ((ptr = strrchr(libname, '/')) != NULL) {
    start += (ptr - libname);
  }
  else if ((ptr = strrchr(libname, '\\')) != NULL) {
    start += (ptr - libname);
  }

  /* remove (oonf/app) lib prefix */
  if (str_startswith_nocase(&libname[start],
      oonf_log_get_libdata()->sharedlibrary_prefix)) {
    start += strlen(oonf_log_get_libdata()->sharedlibrary_prefix);
  }

  /* remove (oonf/app) lib postfix */
  if (str_endswith_nocase(&libname[start],
      oonf_log_get_libdata()->sharedlibrary_postfix)) {
    end -= strlen(oonf_log_get_libdata()->sharedlibrary_prefix);
  }

  if (end-start+1 <= sizeof(*pluginname)) {
    memcpy(pluginname->name, &libname[start], end-start);
  }
}

/**
 * Load a plugin and call its initialize callback
 * @param libname the name of the library(file)
 * @return plugin db object
 */
struct oonf_subsystem *
oonf_subsystem_load(const char *libname)
{
  struct oonf_subsystem *plugin;
  void *dlhandle;
  int idx;

  /* see if the plugin is there */
  if ((plugin = oonf_subsystem_get(libname)) == NULL) {
    /* attempt to load the plugin */
    dlhandle = _open_plugin(libname, &idx);

    if (dlhandle == NULL) {
      /* Logging output has already been done by _open_plugin() */
      return NULL;
    }

    /* plugin should be in the tree now */
    if ((plugin = oonf_subsystem_get(libname)) == NULL) {
      OONF_WARN(LOG_PLUGINS, "dynamic library loading failed: \"%s\"!\n", dlerror());
      dlclose(dlhandle);
      return NULL;
    }

    plugin->_dlhandle = dlhandle;
    plugin->_dlpath_index = idx;
  }
  return plugin;
}

/**
 * Call the initialization callback of a plugin to activate it.
 * Make sure that dependencies are initialized before activating it.
 * @param plugin pointer to plugin db object
 * @return -1 if initialization failed, 0 otherwise
 */
int
oonf_subsystem_call_init(struct oonf_subsystem *plugin) {
  /* start recursive dependency tracking */
  return _init_plugin(plugin);
}

/**
 * Tell plugin it should begin to free its resources
 * @param plugin pointer to plugin db object
 */
void
oonf_subsystem_initiate_unload(struct oonf_subsystem *plugin) {
  if (plugin->initiate_shutdown) {
    plugin->initiate_shutdown();
    plugin->_unload_initiated = true;
  }
}

/**
 * Unloads an active plugin. Static plugins cannot be removed until
 * final cleanup.
 * @param plugin pointer to plugin db object
 * @return 0 if plugin was removed, -1 otherwise
 */
int
oonf_subsystem_unload(struct oonf_subsystem *plugin) {
  if (plugin->initiate_shutdown != NULL && !plugin->_unload_initiated) {
    return -1;
  }
  return _unload_plugin(plugin, false);
}

/**
 * Initialize plugin tree for early loading of static plugins
 */
static void
_init_plugin_tree(void) {
  if (_plugin_tree_initialized) {
    return;
  }

  avl_init(&oonf_plugin_tree, avl_comp_strcasecmp, false);
  _plugin_tree_initialized = true;
}

/**
 * Initialize plugin and all its dependencies
 * @param plugin pointer to plugin
 * @return -1 if plugin has missing dependency,
 *    0 if dependencies were loaded,
 *    1 if a circular dependency were detected
 */
static int
_init_plugin(struct oonf_subsystem *plugin) {
  struct oonf_subsystem *dep;
  size_t i;
  int result;

  if (plugin->_initialized) {
    return 0;
  }

  /* mark plugin */
  plugin->_dependency_missing = true;

  for (i=0; i<plugin->dependencies_count; i++) {
    dep = oonf_subsystem_get(plugin->dependencies[i]);
    if (!dep) {
      OONF_WARN(LOG_PLUGINS, "Dependency '%s' missing for '%s'",
          plugin->dependencies[i], plugin->name);
      return -1;
    }

    if (dep->_dependency_missing) {
      OONF_WARN(LOG_PLUGINS, "Circular dependency, '%s' is dependency of '%s'",
          plugin->dependencies[i], plugin->name);
      return 1;
    }

    result = _init_plugin(dep);
    if (result == -1) {
      /* forward missing dependency */
      return -1;
    }
    if (result == 1) {
      /* forward circular dependency */
      OONF_WARN(LOG_PLUGINS, "Circular dependency, '%s' is dependency of '%s'",
          plugin->dependencies[i], plugin->name);
      return 1;
    }
  }

  plugin->_dependency_missing = false;

  if (plugin->_dlhandle && !_open_plugin_template(plugin->name, plugin->_dlpath_index,
      RTLD_LAZY | RTLD_NOLOAD | RTLD_GLOBAL)) {
    OONF_WARN(LOG_PLUGINS, "Could not reload plugin '%s' into global namespace",
        plugin->name);
    return -1;
  }

  if (plugin->init) {
    if (plugin->init()) {
      OONF_WARN(LOG_PLUGINS, "Init callback failed for plugin %s\n", plugin->name);
      return -1;
    }
  }

  OONF_INFO(LOG_PLUGINS, "Initialized plugin %s successful\n", plugin->name);

  if (!plugin->no_logging) {
    OONF_INFO(plugin->logging, "Plugin %s started", plugin->name);
  }

  plugin->_initialized = true;
  return 0;
}

static void
_cleanup_plugin(struct oonf_subsystem *plugin) {
  struct oonf_subsystem *rdep;
  size_t i;

  if (!plugin->_initialized) {
    return;
  }

  /* handle reverse dependencies */
  avl_for_each_element(&oonf_plugin_tree, rdep, _node) {
    /* look for reverse dependency */
    for (i=0; i<rdep->dependencies_count; i++) {
      if (strcmp(rdep->dependencies[i], plugin->name) == 0) {
        /* found a reverse dependency */
        _cleanup_plugin(rdep);
      }
    }
  }

  if (plugin->cleanup) {
    OONF_INFO(LOG_PLUGINS, "Cleanup plugin %s\n", plugin->name);
    plugin->cleanup();
  }
  plugin->_initialized = false;
}

/**
 * Internal helper function to unload a plugin using the old API
 * @param plugin pointer to plugin db object
 * @param cleanup true if this is the final cleanup
 *   before OONF shuts down, false otherwise
 * @return 0 if the plugin was removed, -1 otherwise
 */
static int
_unload_plugin(struct oonf_subsystem *plugin, bool cleanup) {
  if (!plugin->can_cleanup && !cleanup) {
    OONF_WARN(LOG_PLUGINS, "Plugin %s does not support unloading",
        plugin->name);
    return -1;
  }

  if (plugin->_initialized) {
    _cleanup_plugin(plugin);
  }

  OONF_INFO(LOG_PLUGINS, "Unloading plugin %s\n", plugin->name);

  /* remove first from tree */
  avl_remove(&oonf_plugin_tree, &plugin->_node);

  /* cleanup */
  if (plugin->_dlhandle) {
    dlclose(plugin->_dlhandle);
  }
  return 0;
}

static void *
_open_plugin_template(const char *filename, int template, int mode) {
  struct abuf_template_storage table;
  void *result;

  _dlopen_data[IDX_DLOPEN_LIB].value = filename;

  abuf_template_init(&table,
      _dlopen_data, ARRAYSIZE(_dlopen_data), DLOPEN_PATTERNS[template]);

  abuf_clear(&_dlopen_data_buffer);
  abuf_add_template(&_dlopen_data_buffer, &table, false);

  result = dlopen(abuf_getptr(&_dlopen_data_buffer), mode);
  if (!result) {
    OONF_DEBUG(LOG_PLUGINS, "dlopen (%s,0x%x) failed: %s",
        abuf_getptr(&_dlopen_data_buffer), mode, dlerror());
  }
  else {
    OONF_INFO(LOG_PLUGINS, "dlopen (%s,0x%x) succeeded\n",
        abuf_getptr(&_dlopen_data_buffer), mode);
  }
  return result;
}

/**
 * Internal helper to load plugin with different variants of the
 * filename.
 * @param filename pointer to filename
 */
static void *
_open_plugin(const char *filename, int *idx) {
  void *result;
  size_t i;

  result = NULL;
  for (i=0; i<ARRAYSIZE(DLOPEN_PATTERNS); i++) {
    result = _open_plugin_template(filename, i, RTLD_LAZY | RTLD_LOCAL);
    if (result) {
      *idx = i;
      return result;
    }
  }

  OONF_WARN(LOG_PLUGINS, "Loading of plugin %s failed.\n", filename);
  return NULL;
}
