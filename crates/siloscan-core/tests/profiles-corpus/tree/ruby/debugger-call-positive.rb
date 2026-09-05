def f
  binding.pry
end

def g
  debugger
  h
end

items.each do |i|
  byebug
  h(i)
end

def k(x)
  if x
    debugger
  end
end

debugger
