package unban

import (
	"context"
	"time"
)

func Loop(ctx context.Context, list *List) {
	list.unban()
	list.save()

	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			list.unban()
			list.save()
		}
	}
}
