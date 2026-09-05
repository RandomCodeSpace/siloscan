import subprocess


def f(cmd):
    return subprocess.run(cmd, shell=False)
