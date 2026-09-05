package p

func f(err error) bool {
	return err.Error() == "not found"
}
