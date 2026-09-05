#include <string.h>
void f(char *d, const char *s) {
  strncat(d, s, sizeof(d));
}
