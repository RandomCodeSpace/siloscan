class C {
  void m(boolean c) {
    if (c) { g(); }
    for (int i = 0; i < 3; i++) { g(); }
  }
  void g() {}
}
