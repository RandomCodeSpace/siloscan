#include <string.h>
void f(char *d, const char *s, unsigned n) {
  strncat(d, s, n);
}
