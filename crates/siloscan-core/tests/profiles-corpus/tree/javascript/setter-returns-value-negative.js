function w0() {
  class C { set x(v) { this._x = v; } }
}
function w1() {
  class C { set x(v) { if (!v) { return; } this._x = v; } }
}
function w2() {
  class C { get x() { return this._x; } }
}
