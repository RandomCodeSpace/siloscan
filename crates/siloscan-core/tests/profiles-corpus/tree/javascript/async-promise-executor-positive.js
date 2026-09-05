function w0() {
  const p = new Promise(async (res) => { await g(); res(1); });
}
function w1() {
  const p = new Promise(async function (res) { await g(); res(1); });
}
