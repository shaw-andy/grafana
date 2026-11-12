#define _GNU_SOURCE
#include <dlfcn.h>
#include <locale.h>
#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Arm the preloaded realloc interposer. The interposer is what makes one
   allocation inside regcomp or regexec fail; this file only drives the
   library calls. */
static void arm(int n) {
  void (*fn)(int) = dlsym(RTLD_DEFAULT, "failrealloc_arm");
  if (fn == NULL) {
    fprintf(stderr, "failrealloc_arm missing\n");
    exit(2);
  }
  fn(n);
}

static int compile_pattern(const char *pattern, int fail) {
  regex_t re;
  arm(fail);
  int rc = regcomp(&re, pattern, REG_EXTENDED);
  printf("regcomp=%d\n", rc);
  if (rc == 0)
    regfree(&re);
  return 0;
}

static int execute_pattern(const char *pattern, const char *subject, int fail) {
  regex_t re;
  int rc = regcomp(&re, pattern, REG_EXTENDED);
  if (rc != 0) {
    printf("regcomp=%d\n", rc);
    return 0;
  }
  arm(fail);
  regmatch_t matches[4];
  int er = regexec(&re, subject, 4, matches, 0);
  printf("regexec=%d\n", er);
  regfree(&re);
  return 0;
}

int main(int argc, char **argv) {
  /* UTF-8 makes bracket ranges take the multibyte build_range_exp path. */
  if (setlocale(LC_ALL, "") == NULL && setlocale(LC_ALL, "C.UTF-8") == NULL)
    setlocale(LC_ALL, "C.utf8");

  if (argc < 4) {
    fprintf(stderr, "usage: %s <comp|exec> <fail-index> <pattern> [subject]\n", argv[0]);
    return 2;
  }
  int fail = atoi(argv[2]);
  if (strcmp(argv[1], "comp") == 0)
    return compile_pattern(argv[3], fail);
  if (strcmp(argv[1], "exec") == 0)
    return execute_pattern(argv[3], argc > 4 ? argv[4] : "", fail);
  fprintf(stderr, "unknown mode %s\n", argv[1]);
  return 2;
}
