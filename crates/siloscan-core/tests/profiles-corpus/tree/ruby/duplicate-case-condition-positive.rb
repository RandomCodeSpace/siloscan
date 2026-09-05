def f(x)
  case x
  when 1 then a
  when 2 then b
  when 1 then c
  end
end

def g(x)
  case x
  when 1, 2 then a
  when 2 then b
  end
end
