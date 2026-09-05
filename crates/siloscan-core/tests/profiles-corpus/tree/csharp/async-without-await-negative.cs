class C { void M() { Work(); } }
class D { async System.Threading.Tasks.Task N() { await G(); } }
class E {
  async System.Threading.Tasks.Task O() {
    await foreach (var row in Rows()) {
      Use(row);
    }
  }
  async System.Threading.Tasks.Task P() {
    await using var handle = Open();
    Use(handle);
  }
}
