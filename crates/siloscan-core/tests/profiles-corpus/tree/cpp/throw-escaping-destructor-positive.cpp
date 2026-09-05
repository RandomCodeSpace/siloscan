struct T {
  ~T() {
    if (dirty_) {
      throw std::runtime_error("x");
    }
  }
  bool dirty_;
};
