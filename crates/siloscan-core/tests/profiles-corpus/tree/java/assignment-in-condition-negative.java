import java.io.BufferedReader;
class C {
  void m(BufferedReader r) throws Exception {
    String line;
    while ((line = r.readLine()) != null) { g(line); }
  }
  void n(boolean a, boolean b) {
    if (a == b) { }
  }
  void g(String s) {}
}
