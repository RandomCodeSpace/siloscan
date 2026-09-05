bool f(const std::vector<int>& v) {
  if (v.empty()) { return true; }
  return v.size() == 1;
}
