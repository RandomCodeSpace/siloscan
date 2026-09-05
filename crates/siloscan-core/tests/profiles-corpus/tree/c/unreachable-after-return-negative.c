int f(struct probe *p) {
#ifdef USE_HTTPSRR
  if (!p->memory && !p->extra)
#else
  if (!p->memory)
#endif
    return 1;
  return 0;
}
