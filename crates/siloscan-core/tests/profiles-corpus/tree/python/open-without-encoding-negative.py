from pathlib import Path


def f(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def g(path):
    with open(path, "rb") as fh:
        return fh.read()


def h(path):
    return Path(path).open()
