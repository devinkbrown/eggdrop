/*
 * dbcompat.c -- part of filesys.mod
 *   Compatibility functions to convert older DBs to the newest version.
 *
 * Written for filedb3 by Fabian Knittel <fknittel@gmx.de>
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

/* Convert '.files' db to newest db. Returns 1 if a valid file is
 * found and could be converted, 0 in all other cases.
 *
 * '.files' is a text file which contains file records built up in the
 * following way:
 *      '<filename> <nick> <tm> <gots>\n'
 *      '- <comment>\n'
 *      '- <comment>\n'
 *      ...
 */
static int convert_old_files(char *path, char *newfiledb)
{
  FILE *f, *fdb;
  char s[121], *fn, *nick, *tm, *s1;
  filedb_entry *fdbe = NULL;
  int in_file = 0, i;
  struct stat st;

  {
    size_t s1len = strlen(path) + 8;
    s1 = nmalloc(s1len);
    snprintf(s1, s1len, "%s/.files", path);
  }
  f = fopen(s1, "r");
  my_free(s1);
  if (f == NULL)
    return 0;

  fdb = fopen(newfiledb, "w+b");
  if (!fdb) {
    putlog(LOG_MISC, "*", "(!) Can't create filedb in %s", newfiledb);
    fclose(f);
    return 0;
  }
  lockfile(fdb);
  lockfile(f);
  filedb_initdb(fdb);

  putlog(LOG_FILES, "*", FILES_CONVERT, path);
  /* Scan contents of .files and painstakingly create .filedb entries */
  while (fgets(s, sizeof s, f) != NULL) {
    s1 = s;
    if (s[strlen(s) - 1] == '\n')
      s[strlen(s) - 1] = 0;
    fn = newsplit(&s1);
    rmspace(fn);
    if ((fn[0]) && (fn[0] != ';') && (fn[0] != '#')) {
      /* Not comment */
      if (fn[0] == '-') {
        /* Adjust comment for current file */
        if (in_file && fdbe) {
          rmspace(s);
          if (fdbe->desc) {
            size_t desc_sz = strlen(fdbe->desc) + strlen(s) + 2;
            fdbe->desc = nrealloc(fdbe->desc, desc_sz);
            strlcat(fdbe->desc, "\n", desc_sz);
            strlcat(fdbe->desc, s, desc_sz);
          } else {
            size_t desc_sz = strlen(s) + 1;
            fdbe->desc = nmalloc(desc_sz);
            strlcpy(fdbe->desc, s, desc_sz);
          }
        }
      } else {
        if (fdbe) {
          /* File pending. Write to DB */
          filedb_addfile(fdb, fdbe);
          free_fdbe(&fdbe);
        }
        fdbe = malloc_fdbe();
        in_file = 1;
        nick = newsplit(&s1);
        rmspace(nick);
        tm = newsplit(&s1);
        rmspace(tm);
        rmspace(s1);
        i = strlen(fn) - 1;
        if (fn[i] == '/')
          fn[i] = 0;
        malloc_strcpy(fdbe->filename, fn);
        malloc_strcpy(fdbe->uploader, nick);
        fdbe->gots = atoi(s1);
        fdbe->uploaded = atoi(tm);
        snprintf(s, sizeof s, "%s/%s", path, fn);
        if (stat(s, &st) == 0) {
          /* File is okay */
          if (S_ISDIR(st.st_mode)) {
            fdbe->stat |= FILE_DIR;
            if (nick[0] == '+') {
              char x[100];

              /* Only do global flags, it's an old one */
              struct flag_record fr = { FR_GLOBAL, 0, 0, 0, 0, 0 };

              break_down_flags(nick + 1, &fr, NULL);
              build_flags(x, &fr, NULL);
              /* We only want valid flags */
              malloc_strcpy_nocheck(fdbe->flags_req, x);
            }
          }
          fdbe->size = st.st_size;
        } else
          in_file = 0;        /* skip */
      }
    }
  }
  if (fdbe) {
    /* File pending. Write to DB */
    filedb_addfile(fdb, fdbe);
    free_fdbe(&fdbe);
  }
  fseeko(fdb, 0, SEEK_END);
  unlockfile(f);
  unlockfile(fdb);
  fclose(fdb);
  fclose(f);
  return 1;
}

/* Reads file DB v1 entries from fdb_s and saves them to fdb_t in
 * v3 format.
 */
static void convert_version1(FILE *fdb_s, FILE *fdb_t)
{
  filedb1 fdb1;

  fseek(fdb_s, 0L, SEEK_SET);
  while (fread(&fdb1, sizeof fdb1, 1, fdb_s) && !ferror(fdb_s)) {
    if (!(fdb1.stat & FILE_UNUSED)) {
      filedb_entry *fdbe = malloc_fdbe();

      fdbe->stat = fdb1.stat;
      if (fdb1.filename[0])
        malloc_strcpy(fdbe->filename, fdb1.filename);
      if (fdb1.desc[0])
        malloc_strcpy(fdbe->desc, fdb1.desc);
      if (fdb1.uploader[0])
        malloc_strcpy(fdbe->uploader, fdb1.uploader);
      if (fdb1.flags_req[0])
        malloc_strcpy(fdbe->flags_req, (char *) fdb1.flags_req);
      fdbe->uploaded = fdb1.uploaded;
      fdbe->size = fdb1.size;
      fdbe->gots = fdb1.gots;
      if (fdb1.sharelink[0])
        malloc_strcpy(fdbe->sharelink, fdb1.sharelink);
      filedb_addfile(fdb_t, fdbe);
      free_fdbe(&fdbe);
    }
  }
}

/* Reads file DB v2 entries from fdb_s and saves them to fdb_t in
 * v3 format.
 */
static void convert_version2(FILE *fdb_s, FILE *fdb_t)
{
  filedb2 fdb2;

  fseek(fdb_s, 0L, SEEK_SET);
  while (fread(&fdb2, sizeof fdb2, 1, fdb_s) && !ferror(fdb_s)) {
    if (!(fdb2.stat & FILE_UNUSED)) {
      filedb_entry *fdbe = malloc_fdbe();

      fdbe->stat = fdb2.stat;
      if (fdb2.filename[0])
        malloc_strcpy(fdbe->filename, fdb2.filename);
      if (fdb2.desc[0])
        malloc_strcpy(fdbe->desc, fdb2.desc);
      if (fdb2.chname[0])
        malloc_strcpy(fdbe->chan, fdb2.chname);
      if (fdb2.uploader[0])
        malloc_strcpy(fdbe->uploader, fdb2.uploader);
      if (fdb2.flags_req[0])
        malloc_strcpy(fdbe->flags_req, fdb2.flags_req);
      fdbe->uploaded = fdb2.uploaded;
      fdbe->size = fdb2.size;
      fdbe->gots = fdb2.gots;
      if (fdb2.sharelink[0])
        malloc_strcpy(fdbe->sharelink, fdb2.sharelink);
      filedb_addfile(fdb_t, fdbe);
      free_fdbe(&fdbe);
    }
  }
}

/* Converts old versions of the filedb to the newest. Returns 1 if all went
 * well and otherwise 0.
 *
 * The old content is first copied to a backup file while the original is
 * still locked, then the original is truncated and the new DB is written
 * directly into it.  The lock is held throughout so there is no window
 * where another process can access a partially-converted or missing file.
 * On failure the backup is used to restore the original content.
 *
 * Also remember to check the returned *fdb_s on failure, as it could be
 * NULL.
 */
static int convert_old_db(FILE **fdb_s, char *filedb)
{
  filedb_top fdbt;
  int ret = 0;                  /* Default to 'failure' */

  filedb_readtop(*fdb_s, &fdbt);
  /* Old DB version? */
  if (fdbt.version > 0 && fdbt.version < FILEDB_VERSION3) {
    char *tempdb;
    FILE *fdb_backup;

    putlog(LOG_MISC, "*", "Converting old filedb %s to newest format.",
           filedb);
    /* Create backup name */
    tempdb = nmalloc(strlen(filedb) + 5);
    simple_sprintf(tempdb, "%s-tmp", filedb);

    /* Step 1: Copy old content to backup while original is still locked */
    if (fcopyfile(*fdb_s, tempdb) != 0) {
      putlog(LOG_MISC, "*", "(!) Backing up filedb %s before conversion failed.",
             filedb);
      my_free(tempdb);
      return 0;
    }

    fdb_backup = fopen(tempdb, "rb");
    if (!fdb_backup) {
      putlog(LOG_MISC, "*", "(!) Opening backup filedb %s failed.", tempdb);
      unlink(tempdb);
      my_free(tempdb);
      return 0;
    }

    /* Step 2: Truncate the original file and write the new DB into it.
     * The lock is kept throughout - no unlock/reopen race window. */
    if (ftruncate(fileno(*fdb_s), 0) == 0) {
      rewind(*fdb_s);
      filedb_initdb(*fdb_s);

      if (fdbt.version == FILEDB_VERSION1)
        convert_version1(fdb_backup, *fdb_s);   /* v1 -> v3 */
      else
        convert_version2(fdb_backup, *fdb_s);   /* v2 -> v3 */

      fflush(*fdb_s);
      ret = 1;
    } else {
      putlog(LOG_MISC, "*",
             "(!) Truncating filedb %s for in-place conversion failed.",
             filedb);
    }

    fclose(fdb_backup);

    if (ret) {
      unlink(tempdb);           /* Remove backup on success */
    } else {
      /* Restore original from backup */
      putlog(LOG_MISC, "*",
             "(!) Restoring filedb %s from backup after failed conversion.",
             filedb);
      if (ftruncate(fileno(*fdb_s), 0) == 0) {
        FILE *restore = fopen(tempdb, "rb");
        if (restore) {
          char buf[512];
          size_t n;
          rewind(*fdb_s);
          while ((n = fread(buf, 1, sizeof buf, restore)) > 0)
            fwrite(buf, 1, n, *fdb_s);
          fflush(*fdb_s);
          fclose(restore);
        }
      }
      unlink(tempdb);
    }
    my_free(tempdb);
    /* Database already at the newest version? */
  } else if (fdbt.version == FILEDB_VERSION3)
    ret = 1;
  else
    putlog(LOG_MISC, "*", "(!) Unknown db version: %d", fdbt.version);
  if (!ret)
    putlog(LOG_MISC, "*", "Conversion of filedb %s failed.", filedb);
  return ret;
}
