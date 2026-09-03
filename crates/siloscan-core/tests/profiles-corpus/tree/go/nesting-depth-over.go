package p

func WalkOver(values []int) int {
	total := 0
	for _, value := range values {
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
	}
	return total
}
