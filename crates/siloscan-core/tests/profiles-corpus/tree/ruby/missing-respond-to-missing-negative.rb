class Complete
  def method_missing(name, *args)
    @target.send(name, *args)
  end

  def respond_to_missing?(name, include_private = false)
    @target.respond_to?(name, include_private)
  end
end

class Plain
  def call(name)
    @target.send(name)
  end
end

class Outer
  def method_missing(name, *args)
    @target.send(name, *args)
  end

  def respond_to_missing?(name, include_private = false)
    @target.respond_to?(name, include_private)
  end

  class Inner
    def respond_to_missing?(name, include_private = false)
      true
    end
  end
end

class Host
  def build
    Module.new do
      def method_missing(name, *args)
        super
      end
    end
  end

  def stub(obj)
    def obj.method_missing(*a, &b)
      60.send(*a, &b)
    end
  end
end
