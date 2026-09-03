package p

func WalkUnder(values []int) int {
	total := 0
	for _, value := range values {
		for _, value := range values {
			for _, value := range values {
				for _, value := range values {
					for _, value := range values {
						total += value
					}
				}
			}
		}
	}
	return total
}
