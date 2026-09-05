class C {
  int m() {
    try { return 1; } finally { close(); }
  }
  void close() {}
}
