class C { int M() { return _client.LoadAsync().Result; } void N() { SaveAsync().Wait(); } }
