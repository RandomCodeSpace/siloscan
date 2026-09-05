class C { void M() { try { G(); } catch (System.Exception e) { Log(e); } } }
class C { bool M(int a, int b) { return a == b; } }
class C { void M() { try { G(); } catch (System.Exception e) { Log(e); throw; } } }
class C { async System.Threading.Tasks.Task M() { await G(); } }
class C { int M(bool c) { if (c) { return 1; } else { return 2; } } }
