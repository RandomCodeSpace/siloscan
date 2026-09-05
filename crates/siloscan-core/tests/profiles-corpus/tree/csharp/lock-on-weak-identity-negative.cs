class C { private readonly object _gate = new object(); void M() { lock (_gate) { G(); } } }
