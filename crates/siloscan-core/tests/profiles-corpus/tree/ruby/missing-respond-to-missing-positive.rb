class Proxy
  def method_missing(name, *args)
    @target.send(name, *args)
  end
end
