function w0() {
  const p = new Promise((res) => { res(1); });
}
function w1() {
  const p = new Promise(asyncHelper);
}
function w2() {
  const p = new Deferred(async (res) => { await g(); });
}
