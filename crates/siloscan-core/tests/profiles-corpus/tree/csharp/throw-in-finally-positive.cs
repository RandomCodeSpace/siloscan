class C { void M() { try { G(); } finally { throw new System.InvalidOperationException(); } } }
