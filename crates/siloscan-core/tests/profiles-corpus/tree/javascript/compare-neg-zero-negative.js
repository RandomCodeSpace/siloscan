function w0() {
  return Object.is(x, -0);
}
function w1() {
  return x === -1;
}
function w2() {
  return x === 0;
}
function w3() {
  return x < -0;
}
