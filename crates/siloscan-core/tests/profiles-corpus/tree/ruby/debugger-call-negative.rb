def f(debugger)
  debugger.step
end

debugger = Debugger.new
debugger.start

def g
  logger.debug('x')
end

def h
  binding.local_variable_get(:x)
end
