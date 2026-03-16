/*
 * configtoml.h -- TOML configuration file parser for Eggdrop
 *
 * Copyright (C) 2026 Eggheads Development Team
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 */

#ifndef _EGG_CONFIGTOML_H
#define _EGG_CONFIGTOML_H

/*
 * readtomlconfig() -- parse a TOML config file and drive the same
 * Tcl variable and command interface as readtclprog() does when
 * evaluating a traditional eggdrop.conf Tcl script.
 *
 * Returns 1 on success, 0 on failure (mirrors readtclprog contract).
 */
int readtomlconfig(const char *fname);

/*
 * prescan_paths() -- quick pre-scan of the config file to extract
 * [paths] settings (lang_dir, mod_path) before init_language(1) is called
 * and before modules are loaded, so files and modules are found on the
 * first attempt regardless of section ordering in the config file.
 */
void prescan_paths(const char *fname);

/*
 * run_setup_wizard() -- interactive first-time configuration wizard.
 * Prompts the user for essential settings and writes a ready-to-use
 * TOML config file to outfile.
 *
 * Returns 0 on success, non-zero on failure.
 */
int run_setup_wizard(const char *outfile);

#endif /* _EGG_CONFIGTOML_H */
