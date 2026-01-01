package cycletls

import (
	"context"
	"errors"
	"sync"
)

var ErrWindowClosed = errors.New("credit window closed")

// -----------------------------------------------------------------------------
// Frame sender
// -----------------------------------------------------------------------------

type frameSender struct {
	ctx context.Context
	out chan<- []byte
}

func newFrameSender(ctx context.Context, out chan<- []byte) *frameSender {
	return &frameSender{
		ctx: ctx,
		out: out,
	}
}

// send envoie le buffer tel quel.
// L'appelant ne doit plus modifier buf après l'appel.
func (s *frameSender) send(buf []byte) bool {
	select {
	case <-s.ctx.Done():
		return false
	case s.out <- buf:
		return true
	}
}

// -----------------------------------------------------------------------------
// Credit window (sémaphore pondéré)
// -----------------------------------------------------------------------------

// creditWindow est un sémaphore pondéré.
// Un pointeur nil représente une capacité de crédit infinie.
type creditWindow struct {
	mu     sync.Mutex
	cond   *sync.Cond
	window int64
	closed bool
}

func newCreditWindow(initial int64) *creditWindow {
	if initial < 0 {
		panic("creditWindow: negative initial window")
	}

	cw := &creditWindow{
		window: initial,
	}
	cw.cond = sync.NewCond(&cw.mu)
	return cw
}

// guard vérifie si la requête est triviale ou infinie.
func (cw *creditWindow) guard(n int64) bool {
	return cw == nil || n <= 0
}

// Acquire bloque jusqu'à ce que n crédits soient disponibles,
// puis les consomme atomiquement.
//
// L'attente est annulable via le contexte.
func (cw *creditWindow) Acquire(n int64, ctx context.Context) error {
	if cw.guard(n) {
		return nil
	}

	cw.mu.Lock()
	defer cw.mu.Unlock()

	for {
		if cw.closed {
			return ErrWindowClosed
		}

		if cw.window >= n {
			cw.window -= n
			return nil
		}

		if err := ctx.Err(); err != nil {
			return err
		}

		cw.cond.Wait()
	}
}

// TryAcquire tente de consommer n crédits sans bloquer.
func (cw *creditWindow) TryAcquire(n int64) bool {
	if cw.guard(n) {
		return true
	}

	cw.mu.Lock()
	defer cw.mu.Unlock()

	if cw.closed || cw.window < n {
		return false
	}

	cw.window -= n
	return true
}

// Add ajoute des crédits et réveille les goroutines en attente.
func (cw *creditWindow) Add(n int64) {
	if cw.guard(n) {
		return
	}

	cw.mu.Lock()
	defer cw.mu.Unlock()

	if cw.closed {
		return
	}

	cw.window += n
	cw.cond.Broadcast()
}

// Close ferme logiquement la fenêtre et réveille tous les waiters.
func (cw *creditWindow) Close() {
	if cw == nil {
		return
	}

	cw.mu.Lock()
	defer cw.mu.Unlock()

	if cw.closed {
		return
	}

	cw.closed = true
	cw.cond.Broadcast()
}
