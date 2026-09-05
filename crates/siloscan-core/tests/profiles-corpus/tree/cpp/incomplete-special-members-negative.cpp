class MoveOnly {
public:
  ~MoveOnly();
  MoveOnly(const MoveOnly&) = delete;
  MoveOnly& operator=(const MoveOnly&) = delete;
};
class Copyable {
public:
  ~Copyable();
  Copyable(const Copyable& other);
  Copyable& operator=(const Copyable& other);
};
class NoDestructor {
public:
  NoDestructor();
};
class Defaulted {
public:
  ~Defaulted() = default;
};
