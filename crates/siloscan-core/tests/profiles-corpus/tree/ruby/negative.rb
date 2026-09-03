def f
  g
rescue StandardError => e
  h(e)
end
def f
  begin
    g
  rescue StandardError
    nil
  end
end
def f(a)
  @a = a
  @a
end
def f(c)
  if c
    1
  else
    2
  end
end
def f
  g
ensure
  h
end
