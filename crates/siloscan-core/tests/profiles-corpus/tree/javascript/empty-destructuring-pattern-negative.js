function w0() {
  function f({ a }) { return a; }
}
function w1() {
  const o = {};
}
function w2() {
  const { a = {} } = o;
}
function w3() {
  function f({ a } = {}) { return a; }
}
