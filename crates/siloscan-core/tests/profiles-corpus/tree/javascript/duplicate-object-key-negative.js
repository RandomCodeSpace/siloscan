function w0() {
  const o = { a: 1, b: 2 };
}
function w1() {
  const o = { a: 1, n: { a: 2 } };
}
function w2() {
  const o = { [k]: 1, [k]: 2 };
}
function w3() {
  const o = { a, a };
}
