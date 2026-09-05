struct U {
  ~U() {
    log("never throw here");
  }
};
struct V {
  ~V() {
    try {
      flush();
    } catch (const std::exception&) {
      throw;
    }
  }
};
