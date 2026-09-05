struct s { int x; };
int f(struct s *p) {
  return p != NULL || p->x;
}
int g(struct s *p) {
  return p != NULL || p->x > 0;
}
