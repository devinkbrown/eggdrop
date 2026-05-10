/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * tclpbkdf2.c -- tcl functions for pbkdf2.mod
 *
 * Written by thommey and Michael Ortmann
 *
 * Copyright (C) 2017 - 2025 Eggheads Development Team
 */

/* Tcl command handlers for pbkdf2 module. In non-Tcl builds these compile
 * but are never registered (add_tcl_commands is a no-op). */

static char *pbkdf2_encrypt(const char *);

static int tcl_encpass2 STDVAR
{
  BADARGS(2, 2, " string");
  Tcl_SetResult(irp, pbkdf2_encrypt(argv[1]), TCL_STATIC);
  return TCL_OK;
}

static int tcl_pbkdf2 STDVAR
{
  int hex, digestlen;
  unsigned int rounds;
  opssl_hmac_algo_t algo;
  unsigned char buf[256];
  char buf_hex[256];
  Tcl_Obj *result = 0;

  BADARGS(5, 6, " ?-bin? pass salt rounds digest");
  if (argc == 6) {
    if (!strcmp(argv[1], "-bin"))
      hex = 0;
    else {
      Tcl_AppendResult(irp, "bad option ", argv[1], ": must be -bin", NULL);
      return TCL_ERROR;
    }
  }
  else
    hex = 1;
  rounds = atoi(argv[3 + !hex]);
  if (pbkdf2_get_algo(argv[4 + !hex], &algo, &digestlen)) {
    Tcl_AppendResult(irp, "PBKDF2 error: Unknown message digest '", argv[4 + !hex], "'.", NULL);
    return TCL_ERROR;
  }
  if (opssl_pbkdf2(algo,
                   (const uint8_t *) argv[1 + !hex], strlen(argv[1 + !hex]),
                   (const uint8_t *) argv[2 + !hex], strlen(argv[2 + !hex]),
                   rounds, buf, digestlen) != 1) {
    Tcl_AppendResult(irp, "PBKDF2 key derivation error: ",
                     opssl_err_string(opssl_err_get()), ".", NULL);
    return TCL_ERROR;
  }
  if (hex) {
    static const char _HEX[] = "0123456789ABCDEF";
    for (int i = 0; i < digestlen; i++) {
      buf_hex[i * 2]     = _HEX[(buf[i] >> 4) & 0xf];
      buf_hex[i * 2 + 1] = _HEX[buf[i] & 0xf];
    }
    result = Tcl_NewByteArrayObj((unsigned char *) buf_hex, digestlen * 2);
    explicit_bzero(buf_hex, digestlen * 2);
  }
  else
    result = Tcl_NewByteArrayObj(buf, digestlen);
  explicit_bzero(buf, digestlen);
  Tcl_SetObjResult(irp, result);
  return TCL_OK;
}

static tcl_cmds my_tcl_cmds[] = {
  {"encpass2", tcl_encpass2},
  {"pbkdf2",   tcl_pbkdf2},
  {NULL,       NULL}
};
