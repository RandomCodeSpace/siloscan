struct s { int x; };
int f(struct s *p) {
  return p != NULL && p->x;
}
int h(struct s *p, int n) {
  return p != NULL || n > 0;
}
