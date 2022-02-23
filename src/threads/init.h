#ifndef THREADS_INIT_H
#define THREADS_INIT_H

#include <debug.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/** Page directory with kernel mappings only. */
extern uint32_t *init_page_dir;

/** Kernel shell line buffer size */
#define KS_BUFFER_SIZE 64

/** Kernel shell command max argument count */
#define KS_MAXARGS 16

/** Untility struct for command parsing */
struct cmdline_tokens {
int argc;                     /* Number of arguments */
  char *argv[KS_MAXARGS];     /* The arguments list */
  enum builtins_t {           /* Indicates if argv[0] is a builtin command */
    BUILTIN_NONE,
    BUILTIN_EXIT,
    BUILTIN_WHOAMI,} builtins;
};

#endif /**< threads/init.h */
