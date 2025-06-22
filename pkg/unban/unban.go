package unban

import (
	"context"
	"time"
)

func Loop(ctx context.Context, list *List) {
	list.unban()
	list.save()

	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Hour):
			list.unban()
			list.save()
		}
	}
}
