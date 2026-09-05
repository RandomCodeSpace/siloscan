def f(g):
    try:
        return g()
    finally:
        return 0
