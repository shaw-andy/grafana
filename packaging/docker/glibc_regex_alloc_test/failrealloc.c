#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

/* Fail one realloc inside the loaded GNU C Library after failrealloc_arm.
   The index is 1-based among realloc calls made while armed. Index 0
   counts those calls and fails none. A failing realloc returns NULL and
   leaves the original block allocated, which is what realloc does when
   it cannot grow a block. */

static void *(*real_realloc)(void *, size_t);
static int armed;
static int fail_at;
static int seen;

static void resolve(void) {
  if (real_realloc == NULL)
    real_realloc = dlsym(RTLD_NEXT, "realloc");
}

void failrealloc_arm(int index_1based) {
  resolve();
  fail_at = index_1based;
  seen = 0;
  armed = 1;
}

void *realloc(void *ptr, size_t size) {
  resolve();
  if (armed) {
    seen++;
    if (fail_at > 0 && seen == fail_at)
      return NULL;
  }
  return real_realloc(ptr, size);
}

static void write_count(void) __attribute__((destructor));
static void write_count(void) {
  if (!armed)
    return;
  /* Stop counting before snprintf, which may itself call realloc. */
  armed = 0;
  char buf[64];
  int n = snprintf(buf, sizeof buf, "armed_reallocs=%d\n", seen);
  if (n > 0)
    (void) write(2, buf, (size_t) n);
}
