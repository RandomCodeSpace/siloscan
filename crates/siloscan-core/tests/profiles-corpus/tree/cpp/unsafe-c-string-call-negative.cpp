void f(Buf& b, char* d, const char* s, unsigned n) {
  b.strcpy(s);
  snprintf(d, n, "%s", s);
  std::strncpy(d, s, n);
}
