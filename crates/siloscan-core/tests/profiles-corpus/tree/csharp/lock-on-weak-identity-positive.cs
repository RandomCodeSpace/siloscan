class C { void M() { lock (this) { G(); } } }
class D { void M() { lock (typeof(D)) { G(); } } }
class E { void M() { lock ("gate") { G(); } } }
