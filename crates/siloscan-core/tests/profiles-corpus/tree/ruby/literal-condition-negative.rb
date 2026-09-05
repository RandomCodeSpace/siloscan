def f(x)
  if x
    1
  end
end

def g
  while true
    break
  end
end

def h
  if RUBY_VERSION >= '3.0'
    1
  end
end

def k
  g if true
end
