struct D : B {
  void f() override;
  virtual void g();
  void h() final;
  virtual void i() = 0;
};
