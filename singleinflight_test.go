package dns

import (
	"sync"
	"testing"
	"time"
)

func TestSingleInflight(t *testing.T) {

	var group singleflight
	nr := 100
	rtt := make([]time.Duration, nr)

	// prevent data races and set expected start times with these two waitgroups:
	var wg, done sync.WaitGroup
	wg.Add(nr - 1) // this one tells leader that followers are all started
	done.Add(nr)   // this one blocks test until all goroutines saved results to rtt slice

	go func() {
		_, rtt[0], _ = group.Do("samekey", func() (*Msg, time.Duration, error) {
			wg.Wait()
			return nil, 1, nil
		})
		done.Done()
	}()

	for i := 1; i < nr; i++ {
		go func(pos int) {
			go wg.Done() // delay executing "done", trying to assume that Do would have better chance to enter
			_, rtt[pos], _ = group.Do("samekey", func() (*Msg, time.Duration, error) {
				return nil, 2, nil // :( should not get here
			})
			done.Done()
		}(i)
	}

	wg.Wait()
	done.Wait()

	wrong := 0
	for _, result := range rtt[1:] {
		if result != rtt[0] {
			wrong++
		}
	}
	if wrong > 0 {
		t.Errorf("all values should be equal, got %d wrong", wrong)
	}
}
