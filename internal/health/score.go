package health

// Calculate returns a health score 0-100 based on resource usage and recent incidents.
func Calculate(cpuPct, memPct, diskPct float64, recentCritical, recentHigh int) float64 {
	score := 100.0

	if cpuPct > 95 {
		score -= 30
	} else if cpuPct > 80 {
		score -= 10
	}
	if memPct > 95 {
		score -= 30
	} else if memPct > 80 {
		score -= 10
	}
	if diskPct > 95 {
		score -= 30
	} else if diskPct > 80 {
		score -= 10
	}

	critDeduct := float64(recentCritical) * 15
	if critDeduct > 30 {
		critDeduct = 30
	}
	highDeduct := float64(recentHigh) * 5
	if highDeduct > 20 {
		highDeduct = 20
	}
	score -= critDeduct + highDeduct

	if score < 0 {
		score = 0
	}
	return score
}
