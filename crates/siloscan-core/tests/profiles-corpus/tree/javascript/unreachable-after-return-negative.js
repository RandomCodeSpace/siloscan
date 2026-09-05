function w0() {
  function f() { const x = 2; return x; }
}
function w1() {
  function f() { return g(); function g() { return 1; } }
}
function w2() {
  function f() { return g(); function* g() { yield 1; } }
}
