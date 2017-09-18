
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
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common/common_types.h"
#include "common/avl.h"
#include "common/avl_comp.h"
#include "common/bitmap256.h"
#include "common/isonumber.h"
#include "common/netaddr.h"
#include "common/netaddr_acl.h"
#include "common/string.h"
#include "config/cfg.h"
#include "config/cfg_db.h"
#include "config/cfg_help.h"
#include "config/cfg_schema.h"
#include "config/cfg_validate.h"

static bool _validate_cfg_entry(
    struct cfg_db *db, struct cfg_section_type *section,
    struct cfg_named_section *named, struct cfg_entry *entry,
    const char *section_name, bool cleanup, struct autobuf *out);
static bool _section_needs_default_named_one(struct cfg_section_type *type);
static void _handle_named_section_change (struct cfg_schema_section* s_section, 
    struct cfg_db* pre_change, struct cfg_db* post_change, const char* section_name, 
    bool startup, struct cfg_named_section* pre_defnamed, 
    struct cfg_named_section* post_defnamed);
static int _handle_db_changes(struct cfg_db *pre_change,
    struct cfg_db *post_change, bool startup);

/*! string array with boolean options with value true */
const char *CFGLIST_BOOL_TRUE[] = { CFGLIST_BOOL_TRUE_VALUES };

/*! string arrray with valid boolean options */
const char *CFGLIST_BOOL[] = { CFGLIST_BOOL_VALUES };

/*! text values for configuration schema modes */
const char *CFG_SCHEMA_SECTIONMODE[CFG_SSMODE_MAX] = {
  [CFG_SSMODE_UNNAMED] = "unnamed",
  [CFG_SSMODE_NAMED] = "named",
  [CFG_SSMODE_NAMED_MANDATORY] = "named, mandatory",
  [CFG_SSMODE_NAMED_WITH_DEFAULT] = "named, default name",
};

/**
 * Initialize a schema
 * @param schema pointer to uninitialized schema
 */
void
cfg_schema_add(struct cfg_schema *schema) {
  avl_init(&schema->sections, cfg_avlcmp_keys, true);
  avl_init(&schema->entries, cfg_avlcmp_schemaentries, true);
  list_init_head(&schema->handlers);
}

/**
 * Add a section to a schema
 * @param schema pointer to configuration schema
 * @param section pointer to section
 */
void
cfg_schema_add_section(struct cfg_schema *schema,
    struct cfg_schema_section *section) {
  struct cfg_schema_entry *entry;
  size_t i;

  /* make sure definitions in compiled code are correct */
  assert (cfg_is_allowed_key(section->type));
  assert (section->def_name == NULL
      || cfg_is_allowed_section_name(section->def_name));

  /* hook section into global section tree */
  section->_section_node.key = section->type;
  avl_insert(&schema->sections, &section->_section_node);

  if (section->cb_delta_handler) {
    /* hook callback into global callback handler list */
    list_add_tail(&schema->handlers, &section->_delta_node);
  }

  for (i=0; i<section->entry_count; i++) {
    entry = &section->entries[i];

    /* make sure key name in compiled code is correct */
    assert (cfg_is_allowed_key(entry->key.entry));

    entry->_parent = section;
    entry->key.type = section->type;
    entry->_node.key = &entry->key;

    if (entry->list && entry->def.length == 1) {
      /* empty list, set length to zero */
      entry->def.length = 0;
    }

#if 0
    /* make sure all defaults are the same */
    avl_for_each_elements_with_key(&schema->entries, entry_it, _node, entry,
        &section->entries[i].key) {
      if (section->entries[i].def.value == NULL) {
        /* if we have no default, copy the one from the first existing entry */
        memcpy(&section->entries[i].def, &entry->def, sizeof(entry->def));
        break;
      }
      else {
        /* if we have one, overwrite all existing entries */
        memcpy(&entry->def, &section->entries[i].def, sizeof(entry->def));

        // TODO: maybe output some logging that we overwrite the default?
      }
    }
#endif
    avl_insert(&schema->entries, &section->entries[i]._node);
  }
}

/**
 * Removes a section from a schema
 * @param schema pointer to configuration schema
 * @param section pointer to section
 */
void
cfg_schema_remove_section(struct cfg_schema *schema, struct cfg_schema_section *section) {
  size_t i;

  if (section->_section_node.key) {
    avl_remove(&schema->sections, &section->_section_node);
    section->_section_node.key = NULL;

    for (i=0; i<section->entry_count; i++) {
      avl_remove(&schema->entries, &section->entries[i]._node);
      section->entries[i]._node.key = NULL;
    }
  }
  if (list_is_node_added(&section->_delta_node)) {
    list_remove(&section->_delta_node);
  }
}

/**
 * Validates a database with a schema
 * @param db pointer to configuration database
 * @param cleanup if true, bad values will be removed from the database
 * @param ignore_unknown_sections true if the validation should skip sections
 *   in the database that have no schema.
 * @param out autobuffer for validation output
 * @return 0 if validation found no problems, -1 otherwise
 */
int
cfg_schema_validate(struct cfg_db *db,
    bool cleanup, bool ignore_unknown_sections,
    struct autobuf *out) {
  char section_name[256];
  struct cfg_section_type *section, *section_it;
  struct cfg_named_section *named, *named_it;
  struct cfg_entry *entry, *entry_it;

  struct cfg_schema_section *schema_section;
  struct cfg_schema_section *schema_section_first, *schema_section_last;
  struct cfg_schema_entry *schema_entry;
  size_t i;

  bool error = false;
  bool warning = false;
  bool hasName = false;

  if (db->schema == NULL) {
    return -1;
  }

  CFG_FOR_ALL_SECTION_TYPES(db, section, section_it) {
    /* check for missing schema sections */
    schema_section_first = avl_find_element(&db->schema->sections, section->type,
        schema_section_first, _section_node);

    if (schema_section_first == NULL) {
      if (ignore_unknown_sections) {
        continue;
      }

      cfg_append_printable_line(out,
          "Cannot find schema for section type '%s'", section->type);

      if (cleanup) {
        cfg_db_remove_sectiontype(db, section->type);
      }

      error |= true;
      continue;
    }

    schema_section_last = avl_find_le_element(&db->schema->sections, section->type,
        schema_section_last, _section_node);

    /* iterate over all schema for a certain section type */
    avl_for_element_range(schema_section_first, schema_section_last, schema_section, _section_node) {
      /* check data of named sections in db */
      CFG_FOR_ALL_SECTION_NAMES(section, named, named_it) {
        warning = false;
        hasName = cfg_db_is_named_section(named);

        if (hasName) {
          if (schema_section->mode == CFG_SSMODE_UNNAMED) {
            cfg_append_printable_line(out, "The section type '%s'"
                " has to be used without a name"
                " ('%s' was given as a name)", section->type, named->name);

            warning = true;
          }
        }

        if (hasName && !cfg_is_allowed_section_name(named->name)) {
          cfg_append_printable_line(out, "The section name '%s' for"
              " type '%s' contains illegal characters",
              named->name, section->type);
          warning = true;
        }

        /* test abort condition */
        if (warning && cleanup) {
          /* remove bad named section */
          cfg_db_remove_namedsection(db, section->type, named->name);
        }

        error |= warning;

        if (warning) {
          continue;
        }

        /* initialize section_name field for validate */
        snprintf(section_name, sizeof(section_name), "'%s%s%s'",
            section->type, hasName ? "=" : "", hasName ? named->name : "");

        /* check for bad values */
        CFG_FOR_ALL_ENTRIES(named, entry, entry_it) {
          warning = _validate_cfg_entry(
              db, section, named, entry, section_name,
              cleanup, out);
          error |= warning;
        }

        /* check custom section validation if everything was fine */
        if (!error && schema_section->cb_validate != NULL) {
          if (schema_section->cb_validate(section_name, named, out)) {
            error = true;
          }
        }
      }
    }
    if (cleanup && avl_is_empty(&section->names)) {
      /* if section type is empty, remove it too */
      cfg_db_remove_sectiontype(db, section->type);
    }
  }

  avl_for_each_element(&db->schema->sections, schema_section, _section_node) {
    section = cfg_db_find_sectiontype(db, schema_section->type);
    if (schema_section->mode == CFG_SSMODE_NAMED_MANDATORY) {
      /* search for missing mandatory sections */
      if (section == NULL || avl_is_empty(&section->names)) {
        warning = true;
      }
      else {
        named = avl_first_element(&section->names, named, node);
        warning = !cfg_db_is_named_section(named) && section->names.count < 2;
      }
      if (warning) {
        cfg_append_printable_line(out, "Missing mandatory section of type '%s'",
            schema_section->type);
      }
      error |= warning;
    }

    /* check for missing values */
    for (i=0; i<schema_section->entry_count; i++) {
      schema_entry = &schema_section->entries[i];
      if (strarray_is_empty_c(&schema_entry->def)) {
        /* found a mandatory schema entry */

        warning = true;
        if (section) {
          named = cfg_db_get_unnamed_section(section);
          if (named) {
            /* entry not in unnamed section */
            warning = cfg_db_get_entry(named, schema_entry->key.entry) == NULL;
            if (named->name && warning) {
              /* no mandatory value in unnamed section, check named sections */
              warning = false;

              avl_for_each_element(&section->names, named, node) {
                if (named->name != NULL
                    && cfg_db_get_entry(named, schema_entry->key.entry) == NULL) {
                  /* found a named section without mandatory entry */
                  warning = true;
                  break;
                }
              }
            }
          }
          else {
            /* no unnamed section */
            warning = true;
          }
        }
        if (warning) {
          cfg_append_printable_line(out, "Missing mandatory entry of type '%s' and key '%s'",
              schema_section->type, schema_entry->key.entry);
        }
        error |= warning;
      }
    }
  }
  return error ? -1 : 0;
}

/**
 * Convert the entries of a db section into binary representation by
 * using the mappings defined in a schema section. The function assumes
 * that the section was already validated.
 * @param target pointer to target binary buffer
 * @param named pointer to named section, might be NULL to refer to
 *   default settings
 * @param entries pointer to array of schema entries
 * @param count number of schema entries
 * @return 0 if conversion was successful, -(1+index) of the
 *   failed conversion array entry if an error happened.
 *   An error might result in a partial initialized target buffer.
 */
int
cfg_schema_tobin(void *target, struct cfg_named_section *named,
    const struct cfg_schema_entry *entries, size_t count) {
  char *ptr;
  size_t i;
  const struct const_strarray *value;

  ptr = (char *)target;

  for (i=0; i<count; i++) {
    if (entries[i].cb_to_binary == NULL) {
      continue;
    }

    value = cfg_db_get_schema_entry_value(named, &entries[i]);
    if (entries[i].cb_to_binary(&entries[i], value, ptr + entries[i].bin_offset)) {
      /* error in conversion */
      return -1-i;
    }
  }
  return 0;
}

/**
 * Compare two databases with the same schema and call their change listeners
 * @param pre_change database before change
 * @param post_change database after change
 * @return -1 if databases have different schema, 0 otherwise
 */
int
cfg_schema_handle_db_changes(struct cfg_db *pre_change, struct cfg_db *post_change) {
  return _handle_db_changes(pre_change, post_change, false);
}

/**
 * Handle trigger of delta callbacks on program startup. Call every trigger
 * except for CFG_SSMODE_UNNAMED_OPTIONAL_STARTUP_TRIGGER mode.
 * @param post_db pointer to new configuration database
 * @return -1 if an error happened, 0 otherwise
 */
int
cfg_schema_handle_db_startup_changes(struct cfg_db *post_db) {
  struct cfg_db *pre_db;
  int result;

  pre_db = cfg_db_add();
  if (pre_db == NULL) {
    return -1;
  }
  cfg_db_link_schema(pre_db, post_db->schema);

  result = _handle_db_changes(pre_db, post_db, true);
  cfg_db_remove(pre_db);
  return result;
}

/**
 * AVL comparator for two cfg_schema_entry_key entities.
 * Will compare key.type first, if these are the same it will
 * compare key.entry. NULL is valid as an entry and is smaller
 * than all non-NULL entries. NULL is NOT valid as a type.
 *
 * @param p1 pointer to first key
 * @param p2 pointer to second key
 * @return <0 if p1 comes first, 0 if both are the same, >0 otherwise
 */
int
cfg_avlcmp_schemaentries(const void *p1, const void *p2) {
  const struct cfg_schema_entry_key *key1, *key2;
  int result;

  key1 = p1;
  key2 = p2;

  result = cfg_avlcmp_keys(key1->type, key2->type);
  if (result != 0) {
    return result;
  }

  return cfg_avlcmp_keys(key1->entry, key2->entry);
}

/**
 * Schema entry validator for string maximum length.
 * See CFG_VALIDATE_STRING_LEN() macro in cfg_schema.h
 * @param entry pointer to schema entry
 * @param section_name name of section type and name
 * @param value value of schema entry, NULL for help text generation
 * @param out pointer to autobuffer for validator output
 * @return 0 if validation found no problems, -1 otherwise
 */
int
cfg_schema_validate_strlen(const struct cfg_schema_entry *entry,
    const char *section_name, const char *value, struct autobuf *out) {
  return cfg_validate_strlen(
      out, section_name, entry->key.entry, value, entry->validate_param[0].s);
}

/**
 * Schema entry validator for strings printable characters
 * and a maximum length.
 * See CFG_VALIDATE_PRINTABLE*() macros in cfg_schema.h
 * @param entry pointer to schema entry
 * @param section_name name of section type and name
 * @param value value of schema entry
 * @param out pointer to autobuffer for validator output
 * @return 0 if validation found no problems, -1 otherwise
 */
int
cfg_schema_validate_printable(const struct cfg_schema_entry *entry,
    const char *section_name, const char *value, struct autobuf *out) {
  return cfg_validate_printable(
      out, section_name, entry->key.entry, value, entry->validate_param[0].s);
}

/**
 * Schema entry validator for choice (list of possible strings)
 * List selection will be case insensitive.
 * See CFG_VALIDATE_CHOICE() macro in cfg_schema.h
 * @param entry pointer to schema entry
 * @param section_name name of section type and name
 * @param value value of schema entry
 * @param out pointer to autobuffer for validator output
 * @return 0 if validation found no problems, -1 otherwise
 */
int
cfg_schema_validate_choice(const struct cfg_schema_entry *entry,
    const char *section_name, const char *value, struct autobuf *out) {
  return cfg_validate_choice(out, section_name, entry->key.entry, value,
      entry->validate_param[0].ptr, entry->validate_param[1].s);
}

/**
 * Schema entry validator for integers.
 * See CFG_VALIDATE_INT*() and CFG_VALIDATE_FRACTIONAL*() macros in cfg_schema.h
 * @param entry pointer to schema entry
 * @param section_name name of section type and name
 * @param value value of schema entry
 * @param out pointer to autobuffer for validator output
 * @return 0 if validation found no problems, -1 otherwise
 */
int
cfg_schema_validate_int(const struct cfg_schema_entry *entry,
    const char *section_name, const char *value, struct autobuf *out) {
  return cfg_validate_int(out, section_name, entry->key.entry, value,
      entry->validate_param[0].i64, entry->validate_param[1].i64,
      entry->validate_param[2].i16[0],
      entry->validate_param[2].i16[1],
      entry->validate_param[2].i16[2] == 2);
}

/**
 * Schema entry validator for network addresses and prefixes.
 * See CFG_VALIDATE_NETADDR*() macros in cfg_schema.h
 * @param entry pointer to schema entry
 * @param section_name name of section type and name
 * @param value value of schema entry
 * @param out pointer to autobuffer for validator output
 * @return 0 if validation found no problems, -1 otherwise
 */
int
cfg_schema_validate_netaddr(const struct cfg_schema_entry *entry,
    const char *section_name, const char *value, struct autobuf *out) {
  return cfg_validate_netaddr(out, section_name, entry->key.entry, value,
      entry->validate_param[1].b, entry->validate_param[0].i8, 5);
}

/**
 * Schema entry validator for access control lists.
 * See CFG_VALIDATE_ACL*() macros.
 * @param entry pointer to schema entry
 * @param section_name name of section type and name
 * @param value value of schema entry
 * @param out pointer to autobuffer for validator output
 * @return 0 if validation found no problems, -1 otherwise
 */
int
cfg_schema_validate_acl(const struct cfg_schema_entry *entry,
    const char *section_name, const char *value, struct autobuf *out) {
  return cfg_validate_acl(out, section_name, entry->key.entry, value,
      entry->validate_param[1].b, entry->validate_param[0].i8, 5);
}

/**
 * Schema entry validator for a bitmap256 object.
 * See CFG_VALIDATE_BITMAP256() macros.
 * @param entry pointer to schema entry
 * @param section_name name of section type and name
 * @param value value of schema entry
 * @param out pointer to autobuffer for validator output
 * @return 0 if validation found no problems, -1 otherwise
 */
int
cfg_schema_validate_bitmap256(const struct cfg_schema_entry *entry,
    const char *section_name, const char *value, struct autobuf *out) {
  return cfg_validate_bitmap256(out, section_name, entry->key.entry, value);
}

/**
 * Help generator for string maximum length validator.
 * See CFG_VALIDATE_STRING_LEN() macro in cfg_schema.h
 * @param entry pointer to schema entry
 * @param out pointer to autobuffer for help output
 */
void
cfg_schema_help_strlen(
    const struct cfg_schema_entry *entry, struct autobuf *out) {
  cfg_help_strlen(out, entry->validate_param[0].s);
}

/**
 * Help generator for strings printable characters
 * and a maximum length validator.
 * See CFG_VALIDATE_PRINTABLE*() macros in cfg_schema.h
 * @param entry pointer to schema entry
 * @param out pointer to autobuffer for validator output
 */
void
cfg_schema_help_printable(
    const struct cfg_schema_entry *entry, struct autobuf *out) {
  cfg_help_printable(out, entry->validate_param[0].s);
}

/**
 * Help generator for choice (list of possible strings) validator
 * List selection will be case insensitive.
 * See CFG_VALIDATE_CHOICE() macro in cfg_schema.h
 * @param entry pointer to schema entry
 * @param out pointer to autobuffer for validator output
 */
void
cfg_schema_help_choice(
    const struct cfg_schema_entry *entry, struct autobuf *out) {
  cfg_help_choice(out, true, entry->validate_param[0].ptr,
      entry->validate_param[1].s);
}

/**
 * Help generator for a fractional integer.
 * See CFG_VALIDATE_INT*() macros in cfg_schema.h
 * @param entry pointer to schema entry
 * @param out pointer to autobuffer for validator output
 */
void
cfg_schema_help_int(const struct cfg_schema_entry *entry, struct autobuf *out) {
  cfg_help_int(out, entry->validate_param[0].i64, entry->validate_param[1].i64,
      entry->validate_param[2].i16[0],
      entry->validate_param[2].i16[1],
      entry->validate_param[2].i16[2] == 2);
}

/**
 * Help generator for network addresses and prefixes validator.
 * See CFG_VALIDATE_NETADDR*() macros in cfg_schema.h
 * @param entry pointer to schema entry
 * @param out pointer to autobuffer for validator output
 */
void
cfg_schema_help_netaddr(
    const struct cfg_schema_entry *entry, struct autobuf *out) {
  cfg_help_netaddr(out, true, entry->validate_param[1].b,
      entry->validate_param[0].i8, 5);
}

/**
 * Help generator for access control list validator.
 * See CFG_VALIDATE_ACL*() macros in cfg_schema.h
 * @param entry pointer to schema entry
 * @param out pointer to autobuffer for validator output
 */
void
cfg_schema_help_acl(
    const struct cfg_schema_entry *entry, struct autobuf *out) {
  cfg_help_acl(out, true, entry->validate_param[1].b,
      entry->validate_param[0].i8, 5);
}

/**
 * Help generator for bit-array validator.
 * See CFG_VALIDATE_BITMAP256() macros in cfg_schema.h
 * @param entry pointer to schema entry
 * @param out pointer to autobuffer for validator output
 */
void
cfg_schema_help_bitmap256(
    const struct cfg_schema_entry *entry __attribute__((unused)),
    struct autobuf *out) {
  cfg_help_bitmap256(out, true);
}

/**
 * Binary converter for string pointers. This validator will
 * allocate additional memory for the string.
 * See CFG_MAP_STRING() and CFG_MAP_STRING_LEN() macro
 * in cfg_schema.h
 * @param s_entry pointer to configuration entry schema.
 * @param value pointer to value of configuration entry.
 * @param reference pointer to binary output buffer.
 * @return 0 if conversion succeeded, -1 otherwise.
 */
int
cfg_schema_tobin_strptr(const struct cfg_schema_entry *s_entry __attribute__((unused)),
    const struct const_strarray *value, void *reference) {
  char **ptr;

  if (s_entry->bin_size != sizeof(*ptr)) {
    return -1;
  }

  ptr = (char **)reference;
  if (*ptr) {
    free(*ptr);
  }

  *ptr = strdup(strarray_get_first_c(value));
  return *ptr == NULL ? -1 : 0;
}

/**
 * Binary converter for string arrays.
 * See CFG_MAP_STRING_ARRAY() macro in cfg_schema.h
 * @param s_entry pointer to configuration entry schema.
 * @param value pointer to value of configuration entry.
 * @param reference pointer to binary output buffer.
 * @return 0 if conversion succeeded, -1 otherwise.
 */
int
cfg_schema_tobin_strarray(const struct cfg_schema_entry *s_entry,
    const struct const_strarray *value, void *reference) {
  char *ptr;

  if (s_entry->bin_size < s_entry->validate_param[0].s) {
    return -1;
  }

  ptr = (char *)reference;

  strscpy(ptr, strarray_get_first_c(value), s_entry->validate_param[0].s);
  return 0;
}

/**
 * Binary converter for integers chosen as an index in a predefined
 * string list.
 * See CFG_MAP_CHOICE() macro in cfg_schema.h
 * @param s_entry pointer to configuration entry schema.
 * @param value pointer to value of configuration entry.
 * @param reference pointer to binary output buffer.
 * @return 0 if conversion succeeded, -1 otherwise.
 */
int
cfg_schema_tobin_choice(const struct cfg_schema_entry *s_entry,
    const struct const_strarray *value, void *reference) {
  int *ptr;

  if (s_entry->bin_size != sizeof(int)) {
    return -1;
  }

  ptr = (int *)reference;

  *ptr = cfg_get_choice_index(strarray_get_first_c(value),
      s_entry->validate_param[0].ptr, s_entry->validate_param[1].s);
  return 0;
}

/**
 * Binary converter for integers.
 * See CFG_VALIDATE_FRACTIONAL*() macro in cfg_schema.h
 * @param s_entry pointer to configuration entry schema.
 * @param value pointer to value of configuration entry.
 * @param reference pointer to binary output buffer.
 * @return 0 if conversion succeeded, -1 otherwise.
 */
int
cfg_schema_tobin_int(const struct cfg_schema_entry *s_entry,
    const struct const_strarray *value, void *reference) {
  int64_t i;
  int result;

  if (s_entry->bin_size != s_entry->validate_param[2].u16[0]) {
    return -1;
  }

  result = isonumber_to_s64(&i, strarray_get_first_c(value),
      s_entry->validate_param[2].u16[1], s_entry->validate_param[2].u16[2] == 2);
  if (result == 0) {
    switch (s_entry->validate_param[2].u16[0]) {
      case 4:
        *((int32_t *)reference) = i;
        break;
      case 8:
        *((int64_t *)reference) = i;
        break;
      default:
        return -1;
    }
  }
  return result;
}

/**
 * Binary converter for netaddr objects.
 * See CFG_MAP_NETADDR*() macros in cfg_schema.h
 * @param s_entry pointer to configuration entry schema.
 * @param value pointer to value of configuration entry.
 * @param reference pointer to binary output buffer.
 * @return 0 if conversion succeeded, -1 otherwise.
 */int
cfg_schema_tobin_netaddr(const struct cfg_schema_entry *s_entry __attribute__((unused)),
    const struct const_strarray *value, void *reference) {
  struct netaddr *ptr;

  if (s_entry->bin_size != sizeof(*ptr)) {
    return -1;
  }

  ptr = (struct netaddr *)reference;

  return netaddr_from_string(ptr, strarray_get_first_c(value));
}

/**
 * Schema entry binary converter for ACL entries.
 * See CFG_MAP_ACL_*() macros.
 * @param s_entry pointer to schema entry.
 * @param value pointer to value to configuration entry
 * @param reference pointer to binary target
 * @return -1 if an error happened, 0 otherwise
 */
int
cfg_schema_tobin_acl(const struct cfg_schema_entry *s_entry __attribute__((unused)),
     const struct const_strarray *value, void *reference) {
  struct netaddr_acl *ptr;

  if (s_entry->bin_size != sizeof(*ptr)) {
    return -1;
  }

  ptr = (struct netaddr_acl *)reference;
  netaddr_acl_remove(ptr);

  return netaddr_acl_from_strarray(ptr, value);
}

/**
 * Schema entry binary converter for bitmap256 entries.
 * See CFG_MAP_BITMAP256() macros.
 * @param s_entry pointer to schema entry.
 * @param value pointer to value to configuration entry
 * @param reference pointer to binary target
 * @return -1 if an error happened, 0 otherwise
 */
int
cfg_schema_tobin_bitmap256(const struct cfg_schema_entry *s_entry __attribute__((unused)),
     const struct const_strarray *value, void *reference) {
  struct bitmap256 *bitmap;
  const char *ptr;
  int idx;

  if (s_entry->bin_size != sizeof(*bitmap)) {
    return -1;
  }

  bitmap = (struct bitmap256 *)reference;
  memset(bitmap, 0, sizeof(*bitmap));

  strarray_for_each_element(value, ptr) {
    errno = 0;
    if (strcasecmp(ptr, BITMAP256_ALL) == 0) {
      memset(bitmap, 255, sizeof(*bitmap));
    }
    else if (strcasecmp(ptr, BITMAP256_NONE) == 0) {
      memset(bitmap, 0, sizeof(*bitmap));
    }
    else if (*ptr == '-') {
      idx = strtol(&ptr[1], NULL, 10);
      if (!errno) {
        bitmap256_reset(bitmap, idx);
      }
    }
    else {
      idx = strtol(ptr, NULL, 10);
      if (!errno) {
        bitmap256_set(bitmap, idx);
      }
    }
  }
  return 0;
}

 /**
  * Binary converter for booleans.
  * See CFG_MAP_BOOL() macro in cfg_schema.h
  * @param s_entry pointer to configuration entry schema.
  * @param value pointer to value of configuration entry.
  * @param reference pointer to binary output buffer.
  * @return 0 if conversion succeeded, -1 otherwise.
  */
int
cfg_schema_tobin_bool(const struct cfg_schema_entry *s_entry __attribute__((unused)),
    const struct const_strarray *value, void *reference) {
  bool *ptr;

  if (s_entry->bin_size != sizeof(*ptr)) {
    return -1;
  }

  ptr = (bool *)reference;

  *ptr = cfg_get_bool(strarray_get_first_c(value));
  return 0;
}

/**
 * Binary converter for list of strings.
 * See CFG_MAP_STRINGLIST() macro in cfg_schema.h
 * @param s_entry pointer to configuration entry schema.
 * @param value pointer to value of configuration entry.
 * @param reference pointer to binary output buffer.
 * @return 0 if conversion succeeded, -1 otherwise.
 */
int
cfg_schema_tobin_stringlist(const struct cfg_schema_entry *s_entry __attribute__((unused)),
    const struct const_strarray *value, void *reference) {
  struct strarray *array;

  if (s_entry->bin_size != sizeof(*array)) {
    return -1;
  }

  array = (struct strarray *)reference;

  if (!value->value[0]) {
    strarray_init(array);
    return 0;
  }
  return strarray_copy_c(array, value);
}

/**
 * Check if a section_type contains no named section
 * @param type pointer to section_type
 * @return true if section type contains no named section
 */
static bool
_section_needs_default_named_one(struct cfg_section_type *type) {
  struct cfg_named_section *named;

  if (type == NULL || type->names.count == 0) {
    /* no named sections there, so we need the default one */
    return true;
  }

  if (type->names.count > 1) {
    /* more than one section, that means at least one named one */
    return false;
  }

  /* we have exactly one section inside */
  named = avl_first_element(&type->names, named, node);

  /* we need the default if the existing section has no name */
  return !cfg_db_is_named_section(named);
}

/**
 * Compare two sets of databases and trigger delta listeners according to connected
 * schema.
 * @param pre_change pre-change database
 * @param post_change post-change database
 * @param startup if true, also trigger unnamed sections which don't change, but are
 *   of type CFG_SSMODE_UNNAMED (and not CFG_SSMODE_UNNAMED_OPTIONAL_STARTUP_TRIGGER).
 * @return -1 if an error happened, 0 otherwise
 */
static int
_handle_db_changes(struct cfg_db *pre_change, struct cfg_db *post_change, bool startup) {
  struct cfg_section_type default_section_type[2];
  struct cfg_named_section default_named_section[2];
  struct cfg_schema_section *s_section;
  struct cfg_section_type *pre_type, *post_type;
  struct cfg_named_section *pre_named, *post_named, *named_it;
  struct cfg_named_section * pre_defnamed, *post_defnamed;

  if (pre_change->schema == NULL || pre_change->schema != post_change->schema) {
    /* no valid schema found */
    return -1;
  }

  /* initialize default named section mechanism */
  memset(default_named_section, 0, sizeof(default_named_section));
  memset(default_section_type, 0, sizeof(default_section_type));

  avl_init(&default_named_section[0].entries, cfg_avlcmp_keys, false);
  avl_init(&default_named_section[1].entries, cfg_avlcmp_keys, false);
  default_named_section[0].section_type = &default_section_type[0];
  default_named_section[1].section_type = &default_section_type[1];

  default_section_type[0].db = pre_change;
  default_section_type[1].db = post_change;

  list_for_each_element(&pre_change->schema->handlers, s_section, _delta_node) {
    /* get section types in both databases */
    pre_type = cfg_db_find_sectiontype(pre_change, s_section->type);
    post_type = cfg_db_find_sectiontype(post_change, s_section->type);

    /* prepare for default named section */
    pre_defnamed = NULL;
    post_defnamed = NULL;

    if (s_section->mode == CFG_SSMODE_NAMED_WITH_DEFAULT) {
      /* check if we need a default section for pre_change db */
      if (!startup && _section_needs_default_named_one(pre_type)) {
        /* initialize dummy section type for pre-change db */
        default_section_type[0].type = s_section->type;

        /* initialize dummy named section for pre-change */
        default_named_section[0].name = s_section->def_name;

        /* remember decision */
        pre_defnamed = &default_named_section[0];
      }

      /* check if we need a default section for post_change db */
      if (_section_needs_default_named_one(post_type)) {
        /* initialize dummy section type for post-change db */
        default_section_type[1].type = s_section->type;

        /* initialize dummy named section for post-change */
        default_named_section[1].name = s_section->def_name;

        /* remember decision */
        post_defnamed = &default_named_section[1];
      }
    }

    if (post_type) {
      /* handle new named sections and changes */
      pre_named = NULL;
      CFG_FOR_ALL_SECTION_NAMES(post_type, post_named, named_it) {
        _handle_named_section_change(s_section, pre_change, post_change,
            post_named->name, startup, pre_defnamed, post_defnamed);
      }
    }
    if (pre_type) {
      /* handle removed named sections */
      post_named = NULL;
      CFG_FOR_ALL_SECTION_NAMES(pre_type, pre_named, named_it) {
        if (post_type) {
          post_named = cfg_db_get_named_section(post_type, pre_named->name);
        }

        if (!post_named) {
          _handle_named_section_change(s_section, pre_change, post_change,
              pre_named->name, startup, pre_defnamed, post_defnamed);
        }
      }
    }
    if (startup && s_section->mode == CFG_SSMODE_UNNAMED
        && pre_type == NULL && post_type == NULL) {
      /* send change signal on startup for unnamed section */
      _handle_named_section_change(s_section, pre_change, post_change, NULL, true,
          pre_defnamed, post_defnamed);
    }
    if ((pre_defnamed != NULL) != (post_defnamed != NULL)) {
      /* status of default named section changed */
      _handle_named_section_change(s_section, pre_change, post_change,
          s_section->def_name, true, pre_defnamed, post_defnamed);
    }
  }
  return 0;
}

/**
 * Validates on configuration entry.
 * @param db pointer to database
 * @param section pointer to database section type
 * @param named pointer to named section
 * @param entry pointer to configuration entry
 * @param section_name name of section including type (for debug output)
 * @param cleanup true if bad _entries should be removed
 * @param out error output buffer
 * @return true if an error happened, false otherwise
 */
static bool
_validate_cfg_entry(struct cfg_db *db, struct cfg_section_type *section,
    struct cfg_named_section *named, struct cfg_entry *entry,
    const char *section_name, bool cleanup, struct autobuf *out) {
  struct cfg_schema_entry *schema_entry, *s_entry_it;
  struct cfg_schema_entry_key key;
  bool warning, do_remove;
  char *ptr1;

  warning = false;
  ptr1 = NULL;

  key.type = section->type;
  key.entry = entry->name;

  avl_for_each_elements_with_key(
      &db->schema->entries, schema_entry, _node, s_entry_it, &key) {

    if (schema_entry->cb_validate == NULL) {
      continue;
    }

    /* now validate syntax */
    ptr1 = entry->val.value;

    do_remove = false;
    while (!strarray_is_empty(&entry->val)
        && ptr1 < entry->val.value + entry->val.length) {
      if (!do_remove && schema_entry->cb_validate(schema_entry, section_name, ptr1, out) != 0) {
        /* warning is generated by the validate callback itself */
        warning = true;
      }

      if ((warning || do_remove) && cleanup) {
        /* illegal entry found, remove it */
        strarray_remove_ext(&entry->val, ptr1, false);
      }
      else {
        ptr1 += strlen(ptr1) + 1;
      }

      if (!schema_entry->list) {
        do_remove = true;
      }
    }

    if (strarray_is_empty(&entry->val)) {
      /* remove entry */
      cfg_db_remove_entry(db, section->type, named->name, entry->name);
    }
  }
  return warning;
}

/**
 * Handle changes in a single named section
 * @param s_section schema entry for section
 * @param pre_change pointer to database before changes
 * @param post_change pointer to database after changes
 * @param section_name name of section, might be NULL for unnamed one
 * @param startup true comparison against empty database at startup
 * @param pre_defnamed named section with default name before change
 * @param post_defnamed named section with default name after change
 */
static void
_handle_named_section_change(struct cfg_schema_section *s_section,
    struct cfg_db *pre_change, struct cfg_db *post_change,
    const char *section_name, bool startup,
    struct cfg_named_section *pre_defnamed,
    struct cfg_named_section *post_defnamed) {
  struct cfg_schema_entry *entry;
  bool changed;
  size_t i;

  if ((s_section->mode == CFG_SSMODE_NAMED
       || s_section->mode == CFG_SSMODE_NAMED_MANDATORY
       || s_section->mode == CFG_SSMODE_NAMED_WITH_DEFAULT)
      && section_name == NULL) {
    /*
     * ignore unnamed data entry for named sections, they are only
     * used for delivering defaults
     */
    return;
  }

  s_section->pre = cfg_db_find_namedsection(pre_change, s_section->type, section_name );
  s_section->post = cfg_db_find_namedsection(post_change, s_section->type, section_name );

  if (s_section->mode == CFG_SSMODE_NAMED_WITH_DEFAULT
      && strcasecmp(s_section->def_name, section_name ) == 0) {
    /* use the default named sections if necessary */
    if (s_section->pre == NULL && !startup) {
      s_section->pre = pre_defnamed;
    }
    if (s_section->post == NULL) {
      s_section->post = post_defnamed;
    }
  }

  changed = false;

  if ((s_section->mode == CFG_SSMODE_NAMED
      || s_section->mode == CFG_SSMODE_NAMED_MANDATORY
      || s_section->mode == CFG_SSMODE_NAMED_WITH_DEFAULT)
      && (s_section->pre == NULL) != (s_section->post == NULL)) {
    /* section vanished or appeared */
    changed = true;
  }

  for (i=0; i<s_section->entry_count; i++) {
    entry = &s_section->entries[i];

    /* read values */
    entry->pre = cfg_db_get_entry_value(
        pre_change, s_section->type, section_name, entry->key.entry);
    entry->post = cfg_db_get_entry_value(
        post_change, s_section->type, section_name, entry->key.entry);

    entry->delta_changed = strarray_cmp_c(entry->pre, entry->post);
    changed |= entry->delta_changed;
  }

  if (changed || startup) {
    s_section->section_name = section_name;
    s_section->cb_delta_handler();
  }
}
