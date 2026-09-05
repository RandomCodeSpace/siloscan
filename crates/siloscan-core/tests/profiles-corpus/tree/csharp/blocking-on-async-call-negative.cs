class C { async System.Threading.Tasks.Task M() { var x = await LoadAsync(); Use(x); }
          int N() { var t = LoadAsync(); return t.Result; } }
