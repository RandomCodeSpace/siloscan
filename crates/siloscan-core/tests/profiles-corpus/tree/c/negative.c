int f(int a, int b) {
  return a == b;
}
void f(int a, int b) {
  a = b;
}
int f(int a, int b) {
  if ((a = b)) {
    return 1;
  }
  return 0;
}
int f(int c) {
  if (c) {
    return 1;
  } else {
    return 2;
  }
}
#include <string.h>
int f(const char *s) {
  return strcmp(s, "x") == 0;
}
