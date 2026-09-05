void f() {
  try { g(); } catch (std::runtime_error e) { h(); }
}
