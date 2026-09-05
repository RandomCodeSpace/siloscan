def f
  g
rescue StandardError
  h
rescue Exception
  i
end

def g
  g
rescue ArgumentError
  i
rescue StandardError
  h
end

def h
  g
rescue ArgumentError
  i
end
