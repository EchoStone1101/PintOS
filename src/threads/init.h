#ifndef THREADS_INIT_H
#define THREADS_INIT_H

#include <debug.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/** Page directory with kernel mappings only. */
extern uint32_t *init_page_dir;

/** Command line buffer size */
#define CMD_BUFFER_SIZE 2048

/** Command line max argument count */
#define CMD_MAXARGS 500

/** These sizes are chosen so that one command line buffer and its tokens
    together fit in one 4KB page. This fact is utilized in process_execute()
    where both are put in a newly allocated page, avoiding growing the stack
    too much. */

/** Untility struct for command parsing */
struct cmdline_tokens {
  int argc;                   /* Number of arguments */
  char *argv[CMD_MAXARGS];    /* The arguments list */
  enum builtins_t {           /* Indicates if argv[0] is a builtin command */
    BUILTIN_NONE,
    BUILTIN_EXIT,
    BUILTIN_WHOAMI,} builtins;
};

/** Command line parser; also used in process.c to parse
    user program arguments. */
int cmd_parseline (char *cmdline, struct cmdline_tokens *tok);




#endif /**< threads/init.h */
