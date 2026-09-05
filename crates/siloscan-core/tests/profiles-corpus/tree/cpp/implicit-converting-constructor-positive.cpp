struct Bar { Bar(int a); };
struct Qux { Qux(int a) : a_(a) {} int a_; };
class Foo { public: Foo(int a); };
class Baz { public: Baz(int a) : a_(a) {} int a_; };
