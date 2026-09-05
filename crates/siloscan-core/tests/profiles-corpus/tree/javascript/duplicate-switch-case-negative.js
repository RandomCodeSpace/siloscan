function w0() {
  switch (x) { case 1: return 1; case 2: return 2; }
}
function w1() {
  switch (x) { case 1: case 2: return 1; }
}
function w2() {
  switch (x) { case 1: return 1; } switch (y) { case 1: return 2; }
}
