struct Bar {
  explicit Bar(int a);
  Bar(const Bar& o);
  Bar(Bar&& o);
  Bar(int a, int b);
  Bar();
  Bar(std::initializer_list<int> l);
};
