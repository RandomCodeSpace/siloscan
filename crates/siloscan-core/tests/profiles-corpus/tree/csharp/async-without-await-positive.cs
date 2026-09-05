class C { async System.Threading.Tasks.Task M() { Work(); } }
class E {
  async System.Threading.Tasks.Task N() {
    System.Func<System.Threading.Tasks.Task> inner = async () => { await G(); };
    Register(inner);
  }
}
