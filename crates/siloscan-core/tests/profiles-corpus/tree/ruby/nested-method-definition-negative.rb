class A
  def build
    self.class.define_method(:g) { 1 }
  end
end

class B
  def build
    Class.new do
      def g
        1
      end
    end
  end
end
