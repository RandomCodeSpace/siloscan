class C { void M(object timer) { timer.Pause(100); } }
class D { void Poll() { System.Threading.Thread.Sleep(100); } }
class E {
  async System.Threading.Tasks.Task M() {
    System.Action work = () => { System.Threading.Thread.Sleep(100); };
    await G(work);
  }
}
