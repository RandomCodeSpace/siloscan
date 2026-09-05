class C { bool M(string a, string b) { return string.Equals(a, b, System.StringComparison.OrdinalIgnoreCase); }
          bool N(string a, string b) { return a.ToLower().Equals(b.ToLower()); } }
