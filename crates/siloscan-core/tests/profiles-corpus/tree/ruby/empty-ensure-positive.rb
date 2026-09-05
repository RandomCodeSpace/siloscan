def f
  g
ensure
end

def h
  g
ensure
  # nothing to clean up
end
