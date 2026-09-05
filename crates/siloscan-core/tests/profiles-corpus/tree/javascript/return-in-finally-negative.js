function w0() {
  try { return g(); } finally { cleanup(); }
}
function w1() {
  try { return g(); } finally { if (x) { h(); } }
}
function w2() {
  try { return g(); } finally { const done = () => { return 1; }; done(); }
}
