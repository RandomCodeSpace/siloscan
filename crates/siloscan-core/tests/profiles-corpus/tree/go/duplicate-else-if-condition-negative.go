package p

func try(a int) (bool, error) { return a > 0, nil }

func f(a int) (bool, error) {
	var ok bool
	var err error
	if ok, err = try(a); ok {
		return ok, err
	} else if ok, err = try(a + 1); ok {
		return ok, err
	}
	return false, nil
}
