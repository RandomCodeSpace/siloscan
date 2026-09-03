class C { void M() { try { G(); } catch (System.Exception) {} } }
class C { bool M(int a) { return a == a; } }
class C { void M() { try { G(); } catch (System.Exception e) { throw e; } } }
class C { async void M() { await G(); } }
class C { int M(bool c) { if (c) { return 1; } else { return 1; } } }
