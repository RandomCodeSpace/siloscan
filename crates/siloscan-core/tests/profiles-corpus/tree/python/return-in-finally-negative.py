def f(g):
    try:
        return g()
    finally:
        g.close()
