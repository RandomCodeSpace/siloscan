import yaml
import json


def f(text):
    return yaml.load(text, Loader=yaml.SafeLoader)


def g(fh):
    return json.load(fh)
