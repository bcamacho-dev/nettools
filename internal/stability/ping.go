package stability

import (
	"context"
	"fmt"
	"time"

	probing "github.com/prometheus-community/pro-bing"

	"nettools/internal/model"
)

func Probe(ctx context.Context, target string, count int) (model.Stability, error) {
	if count < 3 {
		count = 3
	}
	if count > 30 {
		count = 30
	}
	st, err := run(ctx, target, count, true)
	if err == nil {
		return st, nil
	}
	st2, err2 := run(ctx, target, count, false)
	if err2 != nil {
		return model.Stability{}, fmt.Errorf("ping privilegiado: %v; ping sem privilégio: %w", err, err2)
	}
	return st2, nil
}

func run(ctx context.Context, target string, count int, privileged bool) (model.Stability, error) {
	pinger, err := probing.NewPinger(target)
	if err != nil {
		return model.Stability{}, err
	}
	pinger.Count = count
	pinger.Interval = 200 * time.Millisecond
	pinger.Timeout = time.Duration(count)*pinger.Interval + 3*time.Second
	pinger.SetPrivileged(privileged)
	if err := pinger.RunWithContext(ctx); err != nil {
		return model.Stability{}, err
	}
	stats := pinger.Statistics()
	return model.Stability{
		Target:   target,
		At:       time.Now().UTC(),
		Sent:     stats.PacketsSent,
		Recv:     stats.PacketsRecv,
		Loss:     stats.PacketLoss,
		MinMS:    ms(stats.MinRtt),
		AvgMS:    ms(stats.AvgRtt),
		MaxMS:    ms(stats.MaxRtt),
		JitterMS: ms(Jitter(stats.Rtts)),
	}, nil
}

func Jitter(rtts []time.Duration) time.Duration {
	if len(rtts) < 2 {
		return 0
	}
	var sum time.Duration
	for i := 1; i < len(rtts); i++ {
		d := rtts[i] - rtts[i-1]
		if d < 0 {
			d = -d
		}
		sum += d
	}
	return sum / time.Duration(len(rtts)-1)
}

func ms(d time.Duration) float64 {
	return float64(d.Microseconds()) / 1000
}
