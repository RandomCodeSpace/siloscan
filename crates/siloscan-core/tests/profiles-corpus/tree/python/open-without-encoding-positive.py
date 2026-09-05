def f(path):
    with open(path) as fh:
        return fh.read()


def g(path, text):
    with open(path, "w") as fh:
        fh.write(text)
