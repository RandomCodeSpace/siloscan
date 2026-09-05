def f(x):
    if x == 1 or x == 2:
        return 1
    if x == 1 or x in (2, 3):
        return 2
    return 0
