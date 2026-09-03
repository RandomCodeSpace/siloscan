int f(int a) {
  return a == a;
}
void f(int a) {
  a = a;
}
int f(int a, int b) {
  if (a = b) {
    return 1;
  }
  return 0;
}
int f(int c) {
  if (c) {
    return 1;
  } else {
    return 1;
  }
}
int f(const char *s) {
  return s == "x";
}
