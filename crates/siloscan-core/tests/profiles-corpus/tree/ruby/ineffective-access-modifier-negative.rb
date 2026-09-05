class B
  private

  def helper
    1
  end
end

class C
  def self.helper
    1
  end
end

class D
  private_class_method

  def self.helper
    1
  end
end

class E
  protected

  def self.helper
    1
  end
end

class F
  private

  def instance_helper
    1
  end

  def self.helper
    2
  end
end
