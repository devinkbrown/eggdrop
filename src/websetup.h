/*
 * websetup.h -- HTTP-based first-launch configuration wizard
 *
 * Copyright (C) 2026 Eggheads Development Team
 */

#ifndef _EGG_WEBSETUP_H
#define _EGG_WEBSETUP_H

/*
 * run_web_setup() -- start a simple HTTP server on the given port
 * that serves an interactive setup wizard. On form submission,
 * writes a TOML config to outfile and returns 0.
 *
 * Returns 0 on success, non-zero on failure.
 */
int run_web_setup(int port, const char *outfile);

#endif /* _EGG_WEBSETUP_H */
