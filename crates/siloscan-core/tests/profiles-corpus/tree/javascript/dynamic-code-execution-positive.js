function w0() {
  return eval(s);
}
function w1() {
  setTimeout("g()", 10);
}
function w2() {
  setInterval(`g()`, 10);
}
function w3() {
  const f = new Function("a", "return a;");
}
