/*
 * tclfiles.c -- part of filesys.mod
 *   Tcl stubs for file system commands moved here to support modules
 */
/*
 * Copyright (C) 1997 Robey Pointer
 * Copyright (C) 1999 - 2025 Eggheads Development Team
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

/* Tcl command handlers for filesys module. In non-Tcl builds these compile
 * but are never registered (add_tcl_commands is a no-op). */

static int tcl_getdesc STDVAR
{
  char *s = nullptr;

  BADARGS(3, 3, " dir file");

  filedb_getdesc(argv[1], argv[2], &s);
  if (s) {
    Tcl_AppendResult(irp, s, nullptr);
    my_free(s);
    return TCL_OK;
  } else {
    Tcl_AppendResult(irp, "filedb access failed", nullptr);
    return TCL_ERROR;
  }
}

static int tcl_setdesc STDVAR
{
  BADARGS(4, 4, " dir file desc");

  filedb_setdesc(argv[1], argv[2], argv[3]);
  return TCL_OK;
}

static int tcl_getowner STDVAR
{
  char *s = nullptr;

  BADARGS(3, 3, " dir file");

  filedb_getowner(argv[1], argv[2], &s);
  if (s) {
    Tcl_AppendResult(irp, s, nullptr);
    my_free(s);
    return TCL_OK;
  } else {
    Tcl_AppendResult(irp, "filedb access failed", nullptr);
    return TCL_ERROR;
  }
}

static int tcl_setowner STDVAR
{
  BADARGS(4, 4, " dir file owner");

  filedb_setowner(argv[1], argv[2], argv[3]);
  return TCL_OK;
}

static int tcl_getgots STDVAR
{
  BADARGS(3, 3, " dir file");

  [[maybe_unused]] int i = filedb_getgots(argv[1], argv[2]);
  Tcl_AppendResult(irp, int_to_base10(i), nullptr);
  return TCL_OK;
}

static int tcl_setlink STDVAR
{
  BADARGS(4, 4, " dir file link");

  filedb_setlink(argv[1], argv[2], argv[3]);
  return TCL_OK;
}

static int tcl_getlink STDVAR
{
  char *s = nullptr;

  BADARGS(3, 3, " dir file");

  filedb_getlink(argv[1], argv[2], &s);
  if (s) {
    Tcl_AppendResult(irp, s, nullptr);
    return TCL_OK;
  } else {
    Tcl_AppendResult(irp, "filedb access failed", nullptr);
    return TCL_ERROR;
  }
}

static int tcl_setpwd STDVAR
{
  BADARGS(3, 3, " idx dir");

  int i = egg_atoi(argv[1]);
  int idx = findanyidx(i);
  if ((idx < 0) || (dcc[idx].type != &DCC_FILES)) {
    Tcl_AppendResult(irp, "invalid idx", nullptr);
    return TCL_ERROR;
  }
  files_setpwd(idx, argv[2]);

  return TCL_OK;
}

static int tcl_getpwd STDVAR
{
  BADARGS(2, 2, " idx");

  int i = egg_atoi(argv[1]);
  int idx = findanyidx(i);
  if ((idx < 0) || (dcc[idx].type != &DCC_FILES)) {
    Tcl_AppendResult(irp, "invalid idx", nullptr);
    return TCL_ERROR;
  }
  Tcl_AppendResult(irp, dcc[idx].u.file->dir, nullptr);

  return TCL_OK;
}

static int tcl_getfiles STDVAR
{
  BADARGS(2, 2, " dir");

  filedb_getfiles(irp, argv[1]);
  return TCL_OK;
}

static int tcl_getdirs STDVAR
{
  BADARGS(2, 2, " dir");

  filedb_getdirs(irp, argv[1]);
  return TCL_OK;
}

static int tcl_hide STDVAR
{
  BADARGS(3, 3, " dir file");

  filedb_change(argv[1], argv[2], FILEDB_HIDE);
  return TCL_OK;
}

static int tcl_unhide STDVAR
{
  BADARGS(3, 3, " dir file");

  filedb_change(argv[1], argv[2], FILEDB_UNHIDE);
  return TCL_OK;
}

static int tcl_share STDVAR
{
  BADARGS(3, 3, " dir file");

  filedb_change(argv[1], argv[2], FILEDB_SHARE);
  return TCL_OK;
}

static int tcl_unshare STDVAR
{
  BADARGS(3, 3, " dir file");

  filedb_change(argv[1], argv[2], FILEDB_UNSHARE);
  return TCL_OK;
}

static int tcl_setflags STDVAR
{
  FILE *fdb;
  filedb_entry *fdbe;
  char *s = nullptr, *p, *d;

  BADARGS(3, 4, " dir ?flags ?channel??");

  malloc_strcpy(s, argv[1]);
  if (s[strlen(s) - 1] == '/')
    s[strlen(s) - 1] = 0;
  p = strrchr(s, '/');
  if (p == nullptr) {
    p = s;
    d = "";
  } else {
    *p = 0;
    p++;
    d = s;
  }

  fdb = filedb_open(d, 0);
  if (!fdb) {
    Tcl_AppendResult(irp, "-3", nullptr);  /* filedb access failed */
    my_free(s);
    return TCL_OK;
  }
  filedb_readtop(fdb, nullptr);
  fdbe = filedb_matchfile(fdb, ftell(fdb), p);
  my_free(s);

  if (!fdbe) {
    Tcl_AppendResult(irp, "-1", nullptr);  /* No such dir */
    return TCL_OK;
  }
  if (!(fdbe->stat & FILE_DIR)) {
    Tcl_AppendResult(irp, "-2", nullptr);  /* Not a dir */
    return TCL_OK;
  }
  if (argc >= 3) {
    struct flag_record fr = { FR_GLOBAL | FR_CHAN };
    char f[100];

    break_down_flags(argv[2], &fr, nullptr);
    build_flags(f, &fr, nullptr);
    malloc_strcpy_nocheck(fdbe->flags_req, f);
  } else
    my_free(fdbe->flags_req);
  if (argc == 4)
    malloc_strcpy(fdbe->chan, argv[3]);

  filedb_updatefile(fdb, fdbe->pos, fdbe, UPDATE_ALL);
  free_fdbe(&fdbe);
  filedb_close(fdb);
  Tcl_AppendResult(irp, "0", nullptr);
  return TCL_OK;
}

static int tcl_getflags STDVAR
{
  filedb_entry *fdbe;
  char *s = nullptr, *p, *d;

  BADARGS(2, 2, " dir");

  malloc_strcpy(s, argv[1]);
  if (s[strlen(s) - 1] == '/')
    s[strlen(s) - 1] = 0;
  p = strrchr(s, '/');
  if (p == nullptr) {
    p = s;
    d = "";
  } else {
    *p = 0;
    p++;
    d = s;
  }

  fdbe = filedb_getentry(d, p);
  /* Directory doesn't exist? */
  if (!fdbe || !(fdbe->stat & FILE_DIR)) {
    Tcl_AppendResult(irp, "", nullptr);
    my_free(s);
    free_fdbe(&fdbe);
    return TCL_OK;
  }
  if (fdbe->flags_req) {
    malloc_strcpy(s, fdbe->flags_req);
    if (s[0] == '-')
      s[0] = 0;
  } else
    s[0] = 0;
  Tcl_AppendElement(irp, s);
  Tcl_AppendElement(irp, fdbe->chan);
  my_free(s);
  free_fdbe(&fdbe);
  return TCL_OK;
}

static int tcl_mkdir STDVAR
{
  FILE *fdb;
  filedb_entry *fdbe;
  char *s = nullptr, *t, *d, *p;
  struct flag_record fr = { FR_GLOBAL | FR_CHAN };

  BADARGS(2, 4, " dir ?required-flags ?channel??");

  malloc_strcpy(s, argv[1]);

  if (s[strlen(s) - 1] == '/')
    s[strlen(s) - 1] = 0;

  p = strrchr(s, '/');
  if (p == nullptr) {
    p = s;
    d = "";
  } else {
    *p = 0;
    p++;
    d = s;
  }

  fdb = filedb_open(d, 0);
  if (!fdb) {
    Tcl_AppendResult(irp, "-3", nullptr);  /* filedb access failed */
    my_free(s);
    return TCL_OK;
  }
  filedb_readtop(fdb, nullptr);
  fdbe = filedb_matchfile(fdb, ftell(fdb), p);

  if (!fdbe) {
    {
      op_strbuf_t _b;
      op_strbuf_init(&_b);
      op_strbuf_appendf(&_b, "%s%s/%s", dccdir, d, p);
      t = op_strbuf_steal(&_b);
    }
    if (mkdir(t, 0755) != 0) {
      Tcl_AppendResult(irp, "1", nullptr);
      my_free(t);
      my_free(s);
      filedb_close(fdb);
      return TCL_OK;
    }
    fdbe = malloc_fdbe();
    fdbe->stat = FILE_DIR;
    malloc_strcpy(fdbe->filename, argv[1]);
    fdbe->uploaded = now;
  } else if (!(fdbe->stat & FILE_DIR)) {
    Tcl_AppendResult(irp, "2", nullptr);
    free_fdbe(&fdbe);
    my_free(s);
    filedb_close(fdb);
    return TCL_OK;
  }
  if (argc >= 3) {
    char f[100];

    break_down_flags(argv[2], &fr, nullptr);
    build_flags(f, &fr, nullptr);
    malloc_strcpy_nocheck(fdbe->flags_req, f);
  } else if (fdbe->flags_req) {
    my_free(fdbe->flags_req);
  }
  if (argc == 4) {
    malloc_strcpy(fdbe->chan, argv[3]);
  } else if (fdbe->chan)
    my_free(fdbe->chan);

  if (!fdbe->pos)
    fdbe->pos = POS_NEW;
  filedb_updatefile(fdb, fdbe->pos, fdbe, UPDATE_ALL);
  filedb_close(fdb);
  free_fdbe(&fdbe);

  Tcl_AppendResult(irp, "0", nullptr);
  return TCL_OK;
}

static int tcl_rmdir STDVAR
{
  FILE *fdb;
  filedb_entry *fdbe;
  char *s = nullptr, *t, *d, *p;

  BADARGS(2, 2, " dir");

  malloc_strcpy(s, argv[1]);
  if (s[strlen(s) - 1] == '/')
    s[strlen(s) - 1] = 0;
  p = strrchr(s, '/');
  if (p == nullptr) {
    p = s;
    d = "";
  } else {
    *p = 0;
    p++;
    d = s;
  }

  fdb = filedb_open(d, 0);
  if (!fdb) {
    Tcl_AppendResult(irp, "1", nullptr);
    my_free(s);
    return TCL_OK;
  }
  filedb_readtop(fdb, nullptr);
  fdbe = filedb_matchfile(fdb, ftell(fdb), p);

  if (!fdbe) {
    Tcl_AppendResult(irp, "1", nullptr);
    filedb_close(fdb);
    my_free(s);
    return TCL_OK;
  }
  if (!(fdbe->stat & FILE_DIR)) {
    Tcl_AppendResult(irp, "1", nullptr);
    filedb_close(fdb);
    free_fdbe(&fdbe);
    my_free(s);
    return TCL_OK;
  }
  /* Erase '.filedb' and '.files' if they exist */
  {
    op_strbuf_t _b;
    op_strbuf_init(&_b);
    op_strbuf_appendf(&_b, "%s%s/%s/.filedb", dccdir, d, p);
    t = op_strbuf_steal(&_b);
    unlink(t);
    op_strbuf_appendf(&_b, "%s%s/%s/.files", dccdir, d, p);
    op_free(t);
    t = op_strbuf_steal(&_b);
    unlink(t);
    op_strbuf_appendf(&_b, "%s%s/%s", dccdir, d, p);
    op_free(t);
    t = op_strbuf_steal(&_b);
  }
  my_free(s);
  if (rmdir(t) == 0) {
    filedb_delfile(fdb, fdbe->pos);
    filedb_close(fdb);
    free_fdbe(&fdbe);
    my_free(t);
    Tcl_AppendResult(irp, "0", nullptr);
    return TCL_OK;
  }
  my_free(t);
  free_fdbe(&fdbe);
  filedb_close(fdb);
  Tcl_AppendResult(irp, "1", nullptr);
  return TCL_OK;
}

static int tcl_mv_cp(Tcl_Interp *irp, int argc, char **argv, int copy)
{
  char *p, *fn = nullptr, *oldpath = nullptr, *s = nullptr, *s1 = nullptr;
  char *newfn = nullptr, *newpath = nullptr;
  int ok = 0, only_first, skip_this;
  FILE *fdb_old, *fdb_new;
  filedb_entry *fdbe_old, *fdbe_new;
  long where;

  BADARGS(3, 3, " oldfilepath newfilepath");

  malloc_strcpy(fn, argv[1]);
  p = strrchr(fn, '/');
  if (p != nullptr) {
    *p = 0;
    malloc_strcpy(s, fn);
    memmove(fn, p + 1, strlen(p + 1) + 1);
    if (!resolve_dir("/", s, &oldpath, -1)) {
      /* Tcl can do * anything */
      Tcl_AppendResult(irp, "-1", nullptr);        /* Invalid source */
      my_free(fn);
      my_free(oldpath);
      return TCL_OK;
    }
    my_free(s);
  } else
    malloc_strcpy(oldpath, "/");
  malloc_strcpy(s, argv[2]);
  if (!resolve_dir("/", s, &newpath, -1)) {
    /* Destination is not just a directory */
    p = strrchr(s, '/');
    if (!p) {
      malloc_strcpy(newfn, s);
      s[0] = 0;
    } else {
      *p = 0;
      malloc_strcpy(newfn, p + 1);
    }
    my_free(newpath);
    if (!resolve_dir("/", s, &newpath, -1)) {
      Tcl_AppendResult(irp, "-2", nullptr);        /* Invalid desto */
      my_free(newpath);
      my_free(s);
      my_free(newfn);
      return TCL_OK;
    }
  } else
    malloc_strcpy(newfn, "");
  my_free(s);

  /* Stupidness checks */
  if ((!strcmp(oldpath, newpath)) && (!newfn[0] || !strcmp(newfn, fn))) {
    my_free(newfn);
    my_free(fn);
    my_free(oldpath);
    my_free(newpath);
    Tcl_AppendResult(irp, "-3", nullptr);  /* Stupid copy to self */
    return TCL_OK;
  }
  /* Be aware of 'cp * this.file' possibility: ONLY COPY FIRST ONE */
  if ((strchr(fn, '?') || strchr(fn, '*')) && newfn[0])
    only_first = 1;
  else
    only_first = 0;

  fdb_old = filedb_open(oldpath, 0);
  if (!strcmp(oldpath, newpath))
    fdb_new = fdb_old;
  else
    fdb_new = filedb_open(newpath, 0);
  if (!fdb_old || !fdb_new) {
    my_free(newfn);
    my_free(fn);
    my_free(oldpath);
    my_free(newpath);
    if (fdb_old)
      filedb_close(fdb_old);
    else if (fdb_new)
      filedb_close(fdb_new);
    Tcl_AppendResult(irp, "-5", nullptr);  /* DB access failed */
    return -1;
  }

  filedb_readtop(fdb_old, nullptr);
  fdbe_old = filedb_matchfile(fdb_old, ftell(fdb_old), fn);
  if (!fdbe_old) {
    my_free(newfn);
    my_free(fn);
    my_free(oldpath);
    my_free(newpath);
    if (fdb_new != fdb_old)
      filedb_close(fdb_new);
    filedb_close(fdb_old);
    Tcl_AppendResult(irp, "-4", nullptr);  /* No match */
    return -2;
  }
  while (fdbe_old) {
    where = ftell(fdb_old);
    skip_this = 0;
    if (!(fdbe_old->stat & (FILE_HIDDEN | FILE_DIR))) {
      {
        op_strbuf_t _b;
        op_strbuf_init(&_b);
        if (oldpath[0])
          op_strbuf_appendf(&_b, "%s%s/%s", dccdir, oldpath, fdbe_old->filename);
        else
          op_strbuf_appendf(&_b, "%s%s", dccdir, fdbe_old->filename);
        s = op_strbuf_steal(&_b);
        const char *newfn_eff = newfn[0] ? newfn : fdbe_old->filename;
        if (newpath[0])
          op_strbuf_appendf(&_b, "%s%s/%s", dccdir, newpath, newfn_eff);
        else
          op_strbuf_appendf(&_b, "%s%s", dccdir, newfn_eff);
        s1 = op_strbuf_steal(&_b);
      }
      if (!strcmp(s, s1)) {
        Tcl_AppendResult(irp, "-3", nullptr);      /* Stupid copy to self */
        skip_this = 1;
      }
      /* Check for existence of file with same name in new dir */
      filedb_readtop(fdb_new, nullptr);
      fdbe_new = filedb_matchfile(fdb_new, ftell(fdb_new),
                                  newfn[0] ? newfn : fdbe_old->filename);
      if (fdbe_new) {
        /* It's ok if the entry in the new dir is a normal file (we'll
         * just scrap the old entry and overwrite the file) -- but if
         * it's a directory, this file has to be skipped.
         */
        if (fdbe_new->stat & FILE_DIR)
          skip_this = 1;
        else
          filedb_delfile(fdb_new, fdbe_new->pos);
        free_fdbe(&fdbe_new);
      }
      if (!skip_this) {
        if ((fdbe_old->sharelink) ||
            ((copy ? copyfile(s, s1) : movefile(s, s1)) == 0)) {
          /* Raw file moved okay: create new entry for it */
          ok++;
          fdbe_new = malloc_fdbe();
          fdbe_new->stat = fdbe_old->stat;
          /* We don't have to worry about any entries to be
           * nullptr, because malloc_strcpy takes care of that.
           */
          malloc_strcpy(fdbe_new->flags_req, fdbe_old->flags_req);
          malloc_strcpy(fdbe_new->chan, fdbe_old->chan);
          malloc_strcpy(fdbe_new->filename, fdbe_old->filename);
          malloc_strcpy(fdbe_new->desc, fdbe_old->desc);
          if (newfn[0])
            malloc_strcpy(fdbe_new->filename, newfn);
          malloc_strcpy(fdbe_new->uploader, fdbe_old->uploader);
          fdbe_new->uploaded = fdbe_old->uploaded;
          fdbe_new->size = fdbe_old->size;
          fdbe_new->gots = fdbe_old->gots;
          malloc_strcpy(fdbe_new->sharelink, fdbe_old->sharelink);
          filedb_addfile(fdb_new, fdbe_new);
          if (!copy)
            filedb_delfile(fdb_old, fdbe_old->pos);
          free_fdbe(&fdbe_new);
        }
      }
      my_free(s);
      my_free(s1);
    }
    free_fdbe(&fdbe_old);
    fdbe_old = filedb_matchfile(fdb_old, where, fn);
    if (ok && only_first) {
      free_fdbe(&fdbe_old);
    }
  }
  if (fdb_old != fdb_new)
    filedb_close(fdb_new);
  filedb_close(fdb_old);
  if (!ok)
    Tcl_AppendResult(irp, "-4", nullptr);  /* No match */
  else {
    Tcl_AppendResult(irp, int_to_base10(ok), nullptr);
  }
  my_free(newfn);
  my_free(fn);
  my_free(oldpath);
  my_free(newpath);
  return TCL_OK;
}

static int tcl_mv STDVAR
{
  return tcl_mv_cp(irp, argc, argv, 0);
}

static int tcl_cp STDVAR
{
  return tcl_mv_cp(irp, argc, argv, 1);
}

static int tcl_fileresend_send(ClientData cd, Tcl_Interp *irp, int argc,
                               char *argv[], int resend)
{
  BADARGS(3, 4, " idx filename ?nick?");

  int i   = egg_atoi(argv[1]);
  int idx = findanyidx(i);
  if (idx < 0 || dcc[idx].type != &DCC_FILES) {
    Tcl_AppendResult(irp, "invalid idx", nullptr);
    return TCL_ERROR;
  }
  if (argc == 4)
    i = files_reget(idx, argv[2], argv[3], resend);
  else
    i = files_reget(idx, argv[2], "", resend);
  Tcl_AppendResult(irp, int_to_base10(i), nullptr);
  return TCL_OK;
}

static int tcl_fileresend STDVAR
{
  return tcl_fileresend_send(cd, irp, argc, argv, 1);
}

static int tcl_filesend STDVAR
{
  return tcl_fileresend_send(cd, irp, argc, argv, 0);
}

static tcl_cmds mytcls[] = {
  {"getdesc",    tcl_getdesc},
  {"getowner",   tcl_getowner},
  {"setdesc",    tcl_setdesc},
  {"setowner",   tcl_setowner},
  {"getgots",    tcl_getgots},
  {"getpwd",     tcl_getpwd},
  {"setpwd",     tcl_setpwd},
  {"getlink",    tcl_getlink},
  {"setlink",    tcl_setlink},
  {"getfiles",   tcl_getfiles},
  {"getdirs",    tcl_getdirs},
  {"hide",       tcl_hide},
  {"unhide",     tcl_unhide},
  {"share",      tcl_share},
  {"unshare",    tcl_unshare},
  {"filesend",   tcl_filesend},
  {"fileresend", tcl_fileresend},
  {"mkdir",      tcl_mkdir},
  {"rmdir",      tcl_rmdir},
  {"cp",         tcl_cp},
  {"mv",         tcl_mv},
  {"getflags",   tcl_getflags},
  {"setflags",   tcl_setflags},
  {nullptr,         nullptr}
};
