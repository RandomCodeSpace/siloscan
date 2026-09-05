function w0() {
  throw new Error("bad");
}
function w1() {
  throw e;
}
function w2() {
  throw makeError("bad");
}
