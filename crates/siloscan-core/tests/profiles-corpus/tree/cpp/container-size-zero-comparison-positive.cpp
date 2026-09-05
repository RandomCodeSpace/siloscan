bool f(const std::vector<int>& v, const std::string* s) {
  if (v.size() == 0) { return true; }
  return s->length() != 0;
}
