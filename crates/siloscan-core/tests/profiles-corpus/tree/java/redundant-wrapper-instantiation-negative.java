import java.nio.charset.StandardCharsets;
class C {
  Object a = new String(bytes(), StandardCharsets.UTF_8);
  Object b = Integer.valueOf(3);
  Object c = new StringBuilder("x");
  byte[] bytes() { return new byte[0]; }
}
