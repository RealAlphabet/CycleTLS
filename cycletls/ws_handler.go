package cycletls

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/sync/errgroup"
)

const (
	pongWait       = 30 * time.Second
	pingPeriod     = (pongWait * 9) / 10 // ping avant expiration
	writeWait      = 10 * time.Second
	requestTimeout = 2 * time.Hour
)

//
// -----------------------------------------------------------------------------
// WebSocket abstraction
// -----------------------------------------------------------------------------

type wsConn interface {
	ReadMessage() (int, []byte, error)
	WriteBinary([]byte) error
	Close() error
	SetCloseHandler(func(code int, text string) error)
}

type gorillaConn struct {
	*websocket.Conn
}

func (g gorillaConn) WriteBinary(data []byte) error {
	_ = g.Conn.SetWriteDeadline(time.Now().Add(writeWait))
	return g.Conn.WriteMessage(websocket.BinaryMessage, data)
}

func newGorillaConn(ws *websocket.Conn) wsConn {
	_ = ws.SetReadDeadline(time.Now().Add(pongWait))

	ws.SetPongHandler(func(string) error {
		_ = ws.SetReadDeadline(time.Now().Add(pongWait))
		return nil
	})

	return gorillaConn{Conn: ws}
}

//
// -----------------------------------------------------------------------------
// Packet readers
// -----------------------------------------------------------------------------

// readInitPacket lit le premier packet "init" envoyé par le client.
// Il initialise la requête et retourne la fenêtre de crédit initiale.
func readInitPacket(conn wsConn) (cycleTLSRequest, uint32, error) {
	msgType, payload, err := conn.ReadMessage()
	if err != nil {
		return cycleTLSRequest{}, 0, err
	}

	if msgType != websocket.BinaryMessage {
		return cycleTLSRequest{}, 0, fmt.Errorf("expected binary init packet")
	}

	reader := NewReader(payload)

	requestID, err := reader.ReadString()
	if err != nil {
		return cycleTLSRequest{}, 0, err
	}

	method, err := reader.ReadString()
	if err != nil {
		return cycleTLSRequest{}, 0, err
	}
	if method != "init" {
		return cycleTLSRequest{}, 0, fmt.Errorf("unexpected method %q", method)
	}

	initialWindow, err := reader.ReadU32()
	if err != nil {
		return cycleTLSRequest{}, 0, err
	}

	optionsJSON, err := reader.ReadString()
	if err != nil {
		return cycleTLSRequest{}, 0, err
	}

	var opts Options
	if err := json.Unmarshal([]byte(optionsJSON), &opts); err != nil {
		return cycleTLSRequest{}, 0, err
	}

	return cycleTLSRequest{
		RequestID: requestID,
		Options:   opts,
	}, initialWindow, nil
}

// readCreditPacket lit les packets "credit" envoyés par le client.
// Ils permettent de recharger la fenêtre de crédit côté serveur.
func readCreditPacket(conn wsConn, expectedRequestID string) (uint32, error) {
	msgType, payload, err := conn.ReadMessage()
	if err != nil {
		return 0, err
	}

	if msgType != websocket.BinaryMessage {
		return 0, fmt.Errorf("expected binary credit packet")
	}

	reader := NewReader(payload)

	requestID, err := reader.ReadString()
	if err != nil {
		return 0, err
	}
	if requestID != expectedRequestID {
		return 0, fmt.Errorf("unexpected request id %q", requestID)
	}

	method, err := reader.ReadString()
	if err != nil {
		return 0, err
	}
	if method != "credit" {
		return 0, fmt.Errorf("unexpected method %q", method)
	}

	credits, err := reader.ReadU32()
	if err != nil {
		return 0, err
	}

	return credits, nil
}

//
// -----------------------------------------------------------------------------
// WebSocket request handler
// -----------------------------------------------------------------------------

func handleWSRequest(ws *websocket.Conn) {
	conn := newGorillaConn(ws)

	// Contexte racine de la requête
	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()

	// errgroup permet :
	// - d'attendre toutes les goroutines
	// - de propager la première erreur
	g, ctx := errgroup.WithContext(ctx)

	// Canal d'écriture vers le WebSocket.
	// IMPORTANT : le dispatcher est le SEUL propriétaire de la fermeture.
	writeCh := make(chan []byte, 32)

	var limiter *creditWindow
	var once sync.Once

	// cleanup ferme définitivement la connexion.
	// Il est safe à appeler plusieurs fois.
	cleanup := func() {
		once.Do(func() {
			if limiter != nil {
				limiter.Close()
			}
			_ = conn.Close()
		})
	}

	defer cleanup()

	conn.SetCloseHandler(func(code int, text string) error {
		log.Println("websocket closed by peer", code, text)
		cancel()
		return nil
	})

	// -----------------------------------------------------------------
	// Ping goroutine and write
	// -----------------------------------------------------------------

	controlCh := make(chan struct{}, 1)

	// ping goroutine
	g.Go(func() error {
		ticker := time.NewTicker(pingPeriod)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				select {
				case controlCh <- struct{}{}:
				default:
				}
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	})

	// -----------------------------------------------------------------
	// Init handshake
	// -----------------------------------------------------------------

	req, initialWindow, err := readInitPacket(conn)
	if err != nil {
		debugLogger.Print("init error: ", err)
		return
	}

	res := processRequest(req, ctx)

	limiter = newCreditWindow(int64(initialWindow))
	res.limiter = limiter

	// -----------------------------------------------------------------
	// Writer goroutine (unique writer vers le WebSocket)
	// -----------------------------------------------------------------

	g.Go(func() error {
		defer cancel()

		for {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case _, ok := <-controlCh:
				if !ok {
					return nil
				}
				err := ws.WriteControl(
					websocket.PingMessage,
					nil,
					time.Now().Add(writeWait),
				)
				if err != nil {
					return err
				}
			case buf, ok := <-writeCh:
				if !ok {
					return nil
				}
				err := conn.WriteBinary(buf)
				if err != nil {
					return err
				}
			}
		}
	})

	// -----------------------------------------------------------------
	// Credit reader loop
	// -----------------------------------------------------------------

	g.Go(func() error {
		defer cancel()

		for {
			credits, err := readCreditPacket(conn, req.RequestID)
			if err != nil {
				return err
			}
			limiter.Add(int64(credits))
		}
	})

	// -----------------------------------------------------------------
	// Dispatcher
	// -----------------------------------------------------------------
	//
	// Le dispatcher :
	// - produit les frames
	// - écrit dans writeCh
	// - FERME writeCh quand il a terminé
	//

	g.Go(func() error {
		defer close(writeCh)

		sender := newFrameSender(ctx, writeCh)
		dispatcherAsync(res, *sender)

		// IMPORTANT :
		// à ce point :
		// - plus aucun message ne sera produit
		// - le writer va drainer writeCh puis s'arrêter
		return nil
	})

	// -----------------------------------------------------------------
	// Attente finale
	// -----------------------------------------------------------------

	if err := g.Wait(); err != nil {
		debugLogger.Println("request error:", err)
	}
}
