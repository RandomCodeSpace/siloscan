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
