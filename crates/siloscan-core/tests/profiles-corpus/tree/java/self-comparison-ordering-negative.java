class C {
  boolean m(int a, int b) {
    return a < b;
  }
  boolean nan(double d) {
    return d != d;
  }
  boolean n(double d) {
    return Double.isNaN(d);
  }
}
