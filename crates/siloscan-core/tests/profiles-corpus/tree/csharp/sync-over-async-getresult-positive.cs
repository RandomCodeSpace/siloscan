class C { void M() { FetchAsync().GetAwaiter().GetResult(); } void N() { _client.FetchAsync().GetAwaiter().GetResult(); } }
