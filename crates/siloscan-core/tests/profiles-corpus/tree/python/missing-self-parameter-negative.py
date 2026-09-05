class C:
    def f(self):
        return self

    @staticmethod
    def g(x):
        return x

    @classmethod
    def h(cls):
        return cls

    def i(self, *args):
        return args

    def j(self, x):
        def inner(y):
            return y
        return inner(x)


def outer():
    def helper(x):
        return x
    return helper
