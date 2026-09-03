def f
  g
rescue Exception => e
  h(e)
end
def f
  x = g rescue nil
  x
end
def f(a)
  a = a
  a
end
def f(c)
  if c
    1
  else
    1
  end
end
def f
  g
ensure
  return 1
end
