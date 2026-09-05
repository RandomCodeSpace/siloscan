function w0() {
  return evaluate(s);
}
function w1() {
  return o.eval(s);
}
function w2() {
  setTimeout(() => g(), 10);
}
function w3() {
  setTimeout(g, 10, "arg");
}
function w4() {
  const f = new FunctionCache();
}
