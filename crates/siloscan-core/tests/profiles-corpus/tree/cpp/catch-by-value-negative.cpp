void f() {
  try { g(); } catch (const std::runtime_error& e) { h(); }
  try { g(); } catch (std::runtime_error& e) { h(); }
  try { g(); } catch (...) { h(); }
  try { g(); } catch (int e) { h(); }
}
