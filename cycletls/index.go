package cycletls

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"io"
	"log"
	nhttp "net/http"
	"net/url"
	"os"
	"runtime"
	"strings"
	"time"

	http "github.com/Danny-Dasilva/fhttp"
	"github.com/gorilla/websocket"
	utls "github.com/refraction-networking/utls"
)

// Time wraps time.Time overriddin the json marshal/unmarshal to pass
// timestamp as integer
type Time struct {
	time.Time
}

// A Cookie represents an HTTP cookie as sent in the Set-Cookie header of an
// HTTP response or the Cookie header of an HTTP request.
//
// See https://tools.ietf.org/html/rfc6265 for details.
type Cookie struct {
	Name  string `json:"name"`
	Value string `json:"value"`

	Path        string `json:"path"`   // optional
	Domain      string `json:"domain"` // optional
	Expires     time.Time
	JSONExpires Time   `json:"expires"`    // optional
	RawExpires  string `json:"rawExpires"` // for reading cookies only

	// MaxAge=0 means no 'Max-Age' attribute specified.
	// MaxAge<0 means delete cookie now, equivalently 'Max-Age: 0'
	// MaxAge>0 means Max-Age attribute present and given in seconds
	MaxAge   int            `json:"maxAge"`
	Secure   bool           `json:"secure"`
	HTTPOnly bool           `json:"httpOnly"`
	SameSite nhttp.SameSite `json:"sameSite"`
	Raw      string
	Unparsed []string `json:"unparsed"` // Raw text of unparsed attribute-value pairs
}

// Options sets CycleTLS client options
type Options struct {
	URL       string            `json:"url"`
	Method    string            `json:"method"`
	Headers   map[string]string `json:"headers"`
	Body      string            `json:"body"`
	BodyBytes []byte            `json:"bodyBytes"` // New field for binary request data

	// TLS fingerprinting options
	Ja3              string `json:"ja3"`
	Ja4r             string `json:"ja4r"` // JA4 raw format with explicit cipher/extension values
	HTTP2Fingerprint string `json:"http2Fingerprint"`
	QUICFingerprint  string `json:"quicFingerprint"`
	DisableGrease    bool   `json:"disableGrease"` // Disable GREASE for exact JA4 matching

	// Browser identification
	UserAgent string `json:"userAgent"`

	// Connection options
	Proxy              string   `json:"proxy"`
	ServerName         string   `json:"serverName"` // Custom TLS SNI override
	Cookies            []Cookie `json:"cookies"`
	Timeout            int      `json:"timeout"`
	DisableRedirect    bool     `json:"disableRedirect"`
	HeaderOrder        []string `json:"headerOrder"`
	OrderAsProvided    bool     `json:"orderAsProvided"` //TODO
	InsecureSkipVerify bool     `json:"insecureSkipVerify"`

	// Protocol options
	ForceHTTP1 bool   `json:"forceHTTP1"`
	ForceHTTP3 bool   `json:"forceHTTP3"`
	Protocol   string `json:"protocol"` // "http1", "http2", "http3", "websocket", "sse"

	// TLS 1.3 specific options
	TLS13AutoRetry bool `json:"tls13AutoRetry"` // Automatically retry with TLS 1.3 compatible curves (default: true)

	// Connection reuse options
	EnableConnectionReuse bool `json:"enableConnectionReuse"` // Enable connection reuse across requests (default: true)
}

type cycleTLSRequest struct {
	RequestID string  `json:"requestId"`
	Options   Options `json:"options"`
}

// rename to request+client+options
type fullRequest struct {
	req       *http.Request
	client    http.Client
	ctx       context.Context
	cancel    context.CancelFunc
	limiter   *creditWindow
	options   cycleTLSRequest
	sseClient *SSEClient       // For SSE connections
	wsClient  *WebSocketClient // For WebSocket connections
}

// CycleTLS creates full request and response
type CycleTLS struct {
	ReqChan    chan fullRequest
	RespChan   chan Response // V1 default: chan Response for backward compatibility
	RespChanV2 chan []byte   `json:"-"` // V2 performance: chan []byte for opt-in users
}

// Option configures a CycleTLS client
type Option func(*CycleTLS)

// WithRawBytes enables the performance enhancement channel (RespChanV2 chan []byte)
// Use this option for performance-critical applications that can handle raw byte responses
func WithRawBytes() Option {
	return func(client *CycleTLS) {
		if client.RespChanV2 == nil {
			client.RespChanV2 = make(chan []byte, 100)
		}
	}
}

var debugLogger = log.New(os.Stdout, "DEBUG: ", log.Ldate|log.Ltime|log.Lshortfile)

// Handle protocol-specific clients
func processRequest(request cycleTLSRequest, parentCtx context.Context) (result fullRequest) {
	switch {
	case request.Options.Protocol == "websocket":
		return dispatchWebSocketRequest(request, parentCtx)

	case request.Options.Protocol == "sse":
		return dispatchSSERequest(request, parentCtx)

	case request.Options.Protocol == "http3" || request.Options.ForceHTTP3:
		return dispatchHTTP3Request(request, parentCtx)

	default:
		return dispatchHTTPRequest(request, parentCtx)
	}
}

func dispatchHTTPRequest(request cycleTLSRequest, parentCtx context.Context) (result fullRequest) {
	ctx, cancel := context.WithCancel(parentCtx)

	var browser = Browser{
		// TLS fingerprinting options
		JA3:              request.Options.Ja3,
		JA4r:             request.Options.Ja4r,
		HTTP2Fingerprint: request.Options.HTTP2Fingerprint,
		QUICFingerprint:  request.Options.QUICFingerprint,
		DisableGrease:    request.Options.DisableGrease,

		// Browser identification
		UserAgent: request.Options.UserAgent,

		// Connection options
		ServerName:         request.Options.ServerName,
		Cookies:            request.Options.Cookies,
		InsecureSkipVerify: request.Options.InsecureSkipVerify,
		ForceHTTP1:         request.Options.ForceHTTP1,
		ForceHTTP3:         request.Options.ForceHTTP3,

		// TLS 1.3 specific options
		TLS13AutoRetry: request.Options.TLS13AutoRetry,

		// Header ordering
		HeaderOrder: request.Options.HeaderOrder,
	}

	// Default to true for connection reuse
	enableConnectionReuse := true
	if request.Options.EnableConnectionReuse == false {
		// Only disable if explicitly set to false
		enableConnectionReuse = false
	}

	client, err := newClientWithReuse(
		browser,
		request.Options.Timeout,
		request.Options.DisableRedirect,
		request.Options.UserAgent,
		enableConnectionReuse,
		request.Options.Proxy,
	)
	if err != nil {
		log.Fatal(err)
	}

	// Handle both string body and byte body
	var bodyReader io.Reader
	if len(request.Options.BodyBytes) > 0 {
		bodyReader = bytes.NewReader(request.Options.BodyBytes)
	} else {
		bodyReader = strings.NewReader(request.Options.Body)
	}
	req, err := http.NewRequestWithContext(ctx, strings.ToUpper(request.Options.Method), request.Options.URL, bodyReader)
	if err != nil {
		log.Fatal(err)
	}
	headerorder := []string{}
	//master header order, all your headers will be ordered based on this list and anything extra will be appended to the end
	//if your site has any custom headers, see the header order chrome uses and then add those headers to this list
	if len(request.Options.HeaderOrder) > 0 {
		//lowercase headers
		for _, v := range request.Options.HeaderOrder {
			lowercasekey := strings.ToLower(v)
			headerorder = append(headerorder, lowercasekey)
		}
	} else {
		headerorder = append(headerorder,
			"host",
			"connection",
			"cache-control",
			"device-memory",
			"viewport-width",
			"rtt",
			"downlink",
			"ect",
			"sec-ch-ua",
			"sec-ch-ua-mobile",
			"sec-ch-ua-full-version",
			"sec-ch-ua-arch",
			"sec-ch-ua-platform",
			"sec-ch-ua-platform-version",
			"sec-ch-ua-model",
			"upgrade-insecure-requests",
			"user-agent",
			"accept",
			"sec-fetch-site",
			"sec-fetch-mode",
			"sec-fetch-user",
			"sec-fetch-dest",
			"referer",
			"accept-encoding",
			"accept-language",
			"cookie",
		)
	}

	headermap := make(map[string]string)
	//TODO: Shorten this
	headerorderkey := []string{}
	for _, key := range headerorder {
		for k, v := range request.Options.Headers {
			lowercasekey := strings.ToLower(k)
			if key == lowercasekey {
				headermap[k] = v
				headerorderkey = append(headerorderkey, lowercasekey)
			}
		}

	}
	headerOrder := parseUserAgent(request.Options.UserAgent).HeaderOrder

	//ordering the pseudo headers and our normal headers
	req.Header = http.Header{
		http.HeaderOrderKey: headerorderkey,
	}
	// Only set PHeaderOrderKey for HTTP/2, not HTTP/3
	// HTTP/3 requests are handled by dispatchHTTP3Request() which doesn't reach this code
	if !request.Options.ForceHTTP3 && request.Options.Protocol != "http3" {
		req.Header[http.PHeaderOrderKey] = headerOrder
	}
	//set our Host header
	u, err := url.Parse(request.Options.URL)
	if err != nil {
		panic(err)
	}

	//append our normal headers
	for k, v := range request.Options.Headers {
		if k != "Content-Length" {
			req.Header.Set(k, v)
		}
	}

	// Respect user-provided Host header for domain fronting; otherwise default to URL host
	if _, ok := request.Options.Headers["Host"]; !ok {
		if _, ok := request.Options.Headers["host"]; !ok {
			req.Header.Set("Host", u.Host)
		}
	}
	req.Header.Set("user-agent", request.Options.UserAgent)

	return fullRequest{
		req:     req,
		client:  client,
		options: request,
		ctx:     ctx,
		cancel:  cancel,
	}
}

// dispatchHTTP3Request handles HTTP/3 specific request processing
func dispatchHTTP3Request(request cycleTLSRequest, parentCtx context.Context) (result fullRequest) {
	ctx, cancel := context.WithCancel(parentCtx)

	// Create browser configuration for HTTP/3
	var browser = Browser{
		// TLS fingerprinting options
		JA3:              request.Options.Ja3,
		JA4r:             request.Options.Ja4r,
		HTTP2Fingerprint: request.Options.HTTP2Fingerprint,
		QUICFingerprint:  request.Options.QUICFingerprint,
		DisableGrease:    request.Options.DisableGrease,

		// Browser identification
		UserAgent: request.Options.UserAgent,

		// Connection options
		ServerName:         request.Options.ServerName,
		Cookies:            request.Options.Cookies,
		InsecureSkipVerify: request.Options.InsecureSkipVerify,
		ForceHTTP1:         false, // Force HTTP/3
		ForceHTTP3:         true,  // Force HTTP/3

		// TLS 1.3 specific options (HTTP/3 requires TLS 1.3)
		TLS13AutoRetry: request.Options.TLS13AutoRetry,

		// Header ordering
		HeaderOrder: request.Options.HeaderOrder,
	}

	// Default to true for connection reuse
	enableConnectionReuse := true
	if request.Options.EnableConnectionReuse == false {
		// Only disable if explicitly set to false
		enableConnectionReuse = false
	}

	client, err := newClientWithReuse(
		browser,
		request.Options.Timeout,
		request.Options.DisableRedirect,
		request.Options.UserAgent,
		enableConnectionReuse,
		request.Options.Proxy,
	)
	if err != nil {
		log.Fatal(err)
	}

	// Handle both string body and byte body
	var bodyReader io.Reader
	if len(request.Options.BodyBytes) > 0 {
		bodyReader = bytes.NewReader(request.Options.BodyBytes)
	} else {
		bodyReader = strings.NewReader(request.Options.Body)
	}
	req, err := http.NewRequestWithContext(ctx, strings.ToUpper(request.Options.Method), request.Options.URL, bodyReader)
	if err != nil {
		log.Fatal(err)
	}

	// Set headers for HTTP/3 request
	for k, v := range request.Options.Headers {
		if k != "Content-Length" {
			req.Header.Set(k, v)
		}
	}

	// Parse URL for Host header
	u, err := url.Parse(request.Options.URL)
	if err != nil {
		panic(err)
	}
	// Respect user-provided Host header for domain fronting; otherwise default to URL host
	if _, ok := request.Options.Headers["Host"]; !ok {
		if _, ok := request.Options.Headers["host"]; !ok {
			req.Header.Set("Host", u.Host)
		}
	}
	req.Header.Set("user-agent", request.Options.UserAgent)

	return fullRequest{
		req:     req,
		client:  client,
		options: request,
		ctx:     ctx,
		cancel:  cancel,
	}
}

// dispatchSSERequest handles SSE specific request processing
func dispatchSSERequest(request cycleTLSRequest, parentCtx context.Context) (result fullRequest) {
	ctx, cancel := context.WithCancel(parentCtx)

	// Create browser configuration for SSE
	var browser = Browser{
		// TLS fingerprinting options
		JA3:              request.Options.Ja3,
		JA4r:             request.Options.Ja4r,
		HTTP2Fingerprint: request.Options.HTTP2Fingerprint,
		QUICFingerprint:  request.Options.QUICFingerprint,
		DisableGrease:    request.Options.DisableGrease,

		// Browser identification
		UserAgent: request.Options.UserAgent,

		// Connection options
		ServerName:         request.Options.ServerName,
		Cookies:            request.Options.Cookies,
		InsecureSkipVerify: request.Options.InsecureSkipVerify,
		ForceHTTP1:         request.Options.ForceHTTP1,
		ForceHTTP3:         request.Options.ForceHTTP3,

		// TLS 1.3 specific options
		TLS13AutoRetry: request.Options.TLS13AutoRetry,

		// Header ordering
		HeaderOrder: request.Options.HeaderOrder,
	}

	// Default to true for connection reuse
	enableConnectionReuse := true
	if request.Options.EnableConnectionReuse == false {
		// Only disable if explicitly set to false
		enableConnectionReuse = false
	}

	client, err := newClientWithReuse(
		browser,
		request.Options.Timeout,
		request.Options.DisableRedirect,
		request.Options.UserAgent,
		enableConnectionReuse,
		request.Options.Proxy,
	)
	if err != nil {
		log.Fatal(err)
	}

	// Prepare headers for SSE
	headers := make(http.Header)
	for k, v := range request.Options.Headers {
		headers.Set(k, v)
	}

	// Create SSE client
	sseClient := NewSSEClient(&client, headers)

	// Create a placeholder request for consistency
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, request.Options.URL, nil)
	if err != nil {
		log.Fatal(err)
	}

	return fullRequest{
		req:       req,
		client:    client,
		ctx:       ctx,
		cancel:    cancel,
		options:   request,
		sseClient: sseClient,
	}
}

// dispatchWebSocketRequest handles WebSocket specific request processing
func dispatchWebSocketRequest(request cycleTLSRequest, parentCtx context.Context) (result fullRequest) {
	ctx, cancel := context.WithCancel(parentCtx)

	// Create browser configuration for WebSocket
	var browser = Browser{
		// TLS fingerprinting options
		JA3:              request.Options.Ja3,
		JA4r:             request.Options.Ja4r,
		HTTP2Fingerprint: request.Options.HTTP2Fingerprint,
		QUICFingerprint:  request.Options.QUICFingerprint,
		DisableGrease:    request.Options.DisableGrease,

		// Browser identification
		UserAgent: request.Options.UserAgent,

		// Connection options
		Cookies:            request.Options.Cookies,
		InsecureSkipVerify: request.Options.InsecureSkipVerify,
		ForceHTTP1:         request.Options.ForceHTTP1,
		ForceHTTP3:         false, // WebSocket doesn't support HTTP/3

		// TLS 1.3 specific options
		TLS13AutoRetry: request.Options.TLS13AutoRetry,

		// Header ordering
		HeaderOrder: request.Options.HeaderOrder,
	}

	// Get TLS config for WebSocket
	tlsConfig := &utls.Config{
		InsecureSkipVerify: browser.InsecureSkipVerify,
		ServerName:         request.Options.ServerName,
	}

	// Prepare headers for WebSocket
	headers := make(http.Header)
	for k, v := range request.Options.Headers {
		headers.Set(k, v)
	}

	// Create WebSocket client
	convertedHeaders := ConvertFhttpHeader(headers)
	wsClient := NewWebSocketClient(tlsConfig, convertedHeaders)

	// Create a placeholder request for consistency
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, request.Options.URL, nil)
	if err != nil {
		log.Fatal(err)
	}

	return fullRequest{
		req:      req,
		client:   http.Client{}, // Empty client as WebSocket uses its own dialer
		ctx:      ctx,
		cancel:   cancel,
		options:  request,
		wsClient: wsClient,
	}
}

func dispatcherAsync(res fullRequest, sender frameSender) {
	limiter := res.limiter

	// Handle SSE connections
	if res.sseClient != nil {
		dispatchSSEAsync(res, sender)
		return
	}

	// Handle WebSocket connections
	if res.wsClient != nil {
		dispatchWebSocketAsync(res, sender)
		return
	}

	defer res.cancel()

	// Extract host from URL for connection reuse tracking
	urlObj, _ := url.Parse(res.options.Options.URL)
	hostPort := urlObj.Host
	if !strings.Contains(hostPort, ":") {
		if urlObj.Scheme == "https" {
			hostPort = hostPort + ":443" // Default HTTPS port
		} else {
			hostPort = hostPort + ":80" // Default HTTP port
		}
	}

	// Don't close connections when finished - they'll be reused for the same host
	// Instead, tell the roundtripper to keep this connection but close others
	defer func() {
		// Use type assertion to access the roundTripper
		if transport, ok := res.client.Transport.(*roundTripper); ok {
			transport.CloseIdleConnections(hostPort)
		}
	}()

	resp, err := res.client.Do(res.req)

	if err != nil {
		parsedError := parseError(err)
		sender.send(buildErrorFrame(res.options.RequestID, parsedError.StatusCode, parsedError.ErrorMsg+"-> \n"+err.Error()))
		return
	}

	defer resp.Body.Close()

	finalUrl := res.options.Options.URL
	if resp != nil && resp.Request != nil && resp.Request.URL != nil {
		finalUrl = resp.Request.URL.String()
	}

	if !sender.send(buildResponseFrame(res.options.RequestID, resp.StatusCode, finalUrl, resp.Header)) {
		return
	}

	bufferSize := 8192
	chunkBuffer := make([]byte, bufferSize)

	for {
		select {
		case <-res.ctx.Done():
		case <-res.req.Context().Done():
			debugLogger.Printf("Request %s context canceled during processing", res.options.RequestID)
			return
		default:
			n, err := resp.Body.Read(chunkBuffer)

			if res.ctx.Err() != nil || res.req.Context().Err() != nil {
				debugLogger.Printf("Request %s was canceled during body read", res.options.RequestID)
				return
			}

			if err != nil && err != io.EOF {
				parsedError := parseError(err)
				if !sender.send(buildErrorFrame(res.options.RequestID, parsedError.StatusCode, parsedError.ErrorMsg)) {
					return
				}
				return
			}

			if err == io.EOF {
				if n > 0 {
					if limiter != nil {
						if werr := limiter.Acquire(int64(n), res.ctx); werr != nil {
							return
						}
					}
					if !sender.send(buildDataFrame(res.options.RequestID, chunkBuffer[:n])) {
						return
					}
				}

				sender.send(buildEndFrame(res.options.RequestID))
				return
			}

			if n == 0 {
				continue
			}

			if limiter != nil {
				if werr := limiter.Acquire(int64(n), res.ctx); werr != nil {
					return
				}
			}

			if !sender.send(buildDataFrame(res.options.RequestID, chunkBuffer[:n])) {
				return
			}
		}
	}
}

// dispatchSSEAsync handles SSE connections asynchronously
func dispatchSSEAsync(res fullRequest, sender frameSender) {
	defer res.cancel()
	limiter := res.limiter

	// Connect to SSE endpoint
	sseResp, err := res.sseClient.Connect(res.req.Context(), res.options.Options.URL)
	if err != nil {
		sender.send(buildErrorFrame(res.options.RequestID, 0, "SSE connection failed: "+err.Error()))
		return
	}
	defer sseResp.Close()

	finalUrl := res.options.Options.URL
	if sseResp.Response != nil && sseResp.Response.Request != nil && sseResp.Response.Request.URL != nil {
		finalUrl = sseResp.Response.Request.URL.String()
	}

	if !sender.send(buildResponseFrame(res.options.RequestID, sseResp.Response.StatusCode, finalUrl, sseResp.Response.Header)) {
		return
	}

	// Read SSE events
loop:
	for {
		select {
		case <-res.ctx.Done():
		case <-res.req.Context().Done():
			debugLogger.Printf("SSE request %s was canceled", res.options.RequestID)
			return

		default:
			event, err := sseResp.NextEvent()
			if err != nil {
				if err == io.EOF {
					// Normal end of stream
					break loop
				}
				debugLogger.Printf("SSE read error: %s", err.Error())
				break loop
			}

			if event == nil {
				continue
			}

			// Format SSE event as JSON for transmission
			eventData := map[string]interface{}{
				"event": event.Event,
				"data":  event.Data,
				"id":    event.ID,
				"retry": event.Retry,
			}

			eventBytes, err := json.Marshal(eventData)
			if err != nil {
				debugLogger.Printf("SSE event marshal error: %s", err.Error())
				continue
			}

			if limiter != nil {
				if err := limiter.Acquire(int64(len(eventBytes)), res.ctx); err != nil {
					break loop
				}
			}

			if !sender.send(buildDataFrame(res.options.RequestID, eventBytes)) {
				break loop
			}
		}
	}

	// Send end message
	sender.send(buildEndFrame(res.options.RequestID))
}

// dispatchWebSocketAsync handles WebSocket connections asynchronously
func dispatchWebSocketAsync(res fullRequest, sender frameSender) {
	defer res.cancel()
	limiter := res.limiter

	// Connect to WebSocket endpoint
	conn, resp, err := res.wsClient.Connect(res.options.Options.URL)
	if err != nil {
		statusCode := 0
		if resp != nil {
			statusCode = resp.StatusCode
		}
		sender.send(buildErrorFrame(res.options.RequestID, statusCode, "WebSocket connection failed: "+err.Error()))
		return
	}

	wsResp := &WebSocketResponse{
		Conn:     conn,
		Response: resp,
	}
	defer wsResp.Close()

	finalUrl := res.options.Options.URL
	if resp != nil && resp.Request != nil && resp.Request.URL != nil {
		finalUrl = resp.Request.URL.String()
	}

	// Send initial response with headers
	if !sender.send(buildResponseFrame(res.options.RequestID, resp.StatusCode, finalUrl, resp.Header)) {
		return
	}

	// Send initial connection success message
	connectedPayload, _ := json.Marshal(map[string]interface{}{
		"type":    "websocket",
		"status":  "connected",
		"message": "WebSocket connection established",
	})

	if limiter != nil {
		if err := limiter.Acquire(int64(len(connectedPayload)), res.ctx); err != nil {
			return
		}
	}
	sender.send(buildDataFrame(res.options.RequestID, connectedPayload))

	// If there's body data, send it as the first WebSocket message
	if res.options.Options.Body != "" {
		err := conn.WriteMessage(websocket.TextMessage, []byte(res.options.Options.Body))
		if err != nil {
			debugLogger.Printf("WebSocket write error: %s", err.Error())
		}
	}

	// Read WebSocket
loop:
	for {
		select {
		case <-res.ctx.Done():
		case <-res.req.Context().Done():
			debugLogger.Printf(
				"WebSocket request %s was canceled",
				res.options.RequestID,
			)
			return
		default:
			messageType, message, err := wsResp.Receive()
			if err != nil {
				if websocket.IsCloseError(err, websocket.CloseNormalClosure) {
					// Normal close
					break loop
				}
				debugLogger.Printf("WebSocket read error: %s", err.Error())
				break loop
			}

			// Format WebSocket message for transmission
			msgData := map[string]interface{}{
				"type":        "websocket",
				"messageType": messageType,
				"data":        string(message),
			}

			msgBytes, err := json.Marshal(msgData)
			if err != nil {
				debugLogger.Printf("WebSocket message marshal error: %s", err.Error())
				continue
			}

			if limiter != nil {
				if err := limiter.Acquire(int64(len(msgBytes)), res.ctx); err != nil {
					break loop
				}
			}

			if !sender.send(buildDataFrame(res.options.RequestID, msgBytes)) {
				break loop
			}
		}
	}

	// Send end message
	sender.send(buildEndFrame(res.options.RequestID))
}

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
}

// WSEndpoint exports the main cycletls function as a websocket connection that clients can connect to
func WSEndpoint(w nhttp.ResponseWriter, r *nhttp.Request) {
	upgrader.CheckOrigin = func(r *nhttp.Request) bool { return true }

	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		//Golang Received a non-standard request to this port, printing request
		var data map[string]interface{}
		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			log.Print("Invalid Request: Body Read Error" + err.Error())
		}
		err = json.Unmarshal(bodyBytes, &data)
		if err != nil {
			log.Print("Invalid Request: Json Conversion failed ")
		}
		body, err := PrettyStruct(data)
		if err != nil {
			log.Print("Invalid Request:", err)
		}
		headers, err := PrettyStruct(r.Header)
		if err != nil {
			log.Fatal(err)
		}
		log.Println(headers)
		log.Println(body)
		return
	}

	handleWSRequest(ws)
}

func setupRoutes() {
	nhttp.HandleFunc("/", WSEndpoint)
}

func main() {
	port, exists := os.LookupEnv("WS_PORT")
	var addr *string
	if exists {
		addr = flag.String("addr", ":"+port, "http service address")
	} else {
		addr = flag.String("addr", ":9112", "http service address")
	}

	runtime.GOMAXPROCS(runtime.NumCPU())

	setupRoutes()
	log.Fatal(nhttp.ListenAndServe(*addr, nil))
}

// Backward compatibility types and functions for integration tests
type Response struct {
	RequestID string            `json:"requestId"`
	Status    int               `json:"status"`
	Body      string            `json:"body"`
	BodyBytes []byte            `json:"bodyBytes"` // New field for binary response data
	Headers   map[string]string `json:"headers"`
	Cookies   []*nhttp.Cookie   `json:"cookies"`
	FinalUrl  string            `json:"finalUrl"`
}

// JSONBody parses the response body as JSON
func (r Response) JSONBody() map[string]interface{} {
	var result map[string]interface{}
	json.Unmarshal([]byte(r.Body), &result)
	return result
}

// Init creates a CycleTLS client with v1 default behavior (chan Response)
// Use WithRawBytes() option for performance enhancement with chan []byte
func Init(opts ...Option) CycleTLS {
	reqChan := make(chan fullRequest, 100)
	respChan := make(chan Response, 100)

	client := CycleTLS{
		ReqChan:  reqChan,
		RespChan: respChan,
	}

	// Apply options
	for _, opt := range opts {
		opt(&client)
	}

	return client
}

// Queue queues a request (simplified for integration tests)
func (client CycleTLS) Queue(URL string, options Options, Method string) {
	// This is a simplified implementation for integration tests
	// In a real implementation, this would queue the request
}

// Close closes the channels
func (client CycleTLS) Close() {
	if client.ReqChan != nil {
		close(client.ReqChan)
	}
	if client.RespChan != nil {
		close(client.RespChan)
	}
	if client.RespChanV2 != nil {
		close(client.RespChanV2)
	}
	// Clear all connections from the global pool
	clearAllConnections()
}

// Do creates a single HTTP request for integration tests
func (client CycleTLS) Do(URL string, options Options, Method string) (Response, error) {
	// Create browser from options
	browser := Browser{
		JA3:                options.Ja3,
		JA4r:               options.Ja4r,
		HTTP2Fingerprint:   options.HTTP2Fingerprint,
		QUICFingerprint:    options.QUICFingerprint,
		UserAgent:          options.UserAgent,
		Cookies:            options.Cookies,
		InsecureSkipVerify: options.InsecureSkipVerify,
		ForceHTTP1:         options.ForceHTTP1,
		ForceHTTP3:         options.ForceHTTP3,
		HeaderOrder:        options.HeaderOrder,
	}

	// Note: Don't automatically set HeaderOrder from UserAgent here as it can interfere with connection management
	// The pseudo-header order should be set through explicit HTTP2Fingerprint or Options.HeaderOrder

	// Create HTTP client with connection reuse
	// Default to true for connection reuse
	enableConnectionReuse := true
	if options.EnableConnectionReuse == false {
		// Only disable if explicitly set to false
		enableConnectionReuse = false
	}

	httpClient, err := newClientWithReuse(
		browser,
		options.Timeout,
		options.DisableRedirect,
		options.UserAgent,
		enableConnectionReuse,
		options.Proxy,
	)
	if err != nil {
		return Response{}, err
	}

	// Create request using fhttp
	var bodyReader io.Reader
	if len(options.BodyBytes) > 0 {
		bodyReader = bytes.NewReader(options.BodyBytes)
	} else {
		bodyReader = strings.NewReader(options.Body)
	}
	req, err := http.NewRequest(Method, URL, bodyReader)
	if err != nil {
		return Response{}, err
	}

	// Set pseudo-header order based on UserAgent - only for HTTP/2, not HTTP/3
	headerOrder := parseUserAgent(options.UserAgent).HeaderOrder
	req.Header = http.Header{}

	// Only set PHeaderOrderKey for HTTP/2, not HTTP/3
	if !options.ForceHTTP3 {
		req.Header[http.PHeaderOrderKey] = headerOrder
	}

	// Set headers
	for k, v := range options.Headers {
		req.Header.Set(k, v)
	}

	// Make request
	resp, err := httpClient.Do(req)
	if err != nil {
		parsedError := parseError(err)
		return Response{
			Status: parsedError.StatusCode,
			Body:   parsedError.ErrorMsg + " -> " + err.Error(),
		}, nil
	}
	defer resp.Body.Close()

	// Read body
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return Response{}, err
	}

	// Automatic decompression (axios-style) - check Content-Encoding header
	encoding := resp.Header["Content-Encoding"]
	content := resp.Header["Content-Type"]
	if len(encoding) > 0 {
		// Automatically decompress the body like axios does
		bodyBytes = DecompressBody(bodyBytes, encoding, content)
	}

	// Convert headers
	headers := make(map[string]string)
	for name, values := range resp.Header {
		if len(values) > 0 {
			headers[name] = values[0]
		}
	}

	// Get final URL
	finalUrl := URL
	if resp.Request != nil && resp.Request.URL != nil {
		finalUrl = resp.Request.URL.String()
	}

	// Convert fhttp cookies to net/http cookies
	var netCookies []*nhttp.Cookie
	for _, cookie := range resp.Cookies() {
		netCookie := &nhttp.Cookie{
			Name:       cookie.Name,
			Value:      cookie.Value,
			Path:       cookie.Path,
			Domain:     cookie.Domain,
			Expires:    cookie.Expires,
			RawExpires: cookie.RawExpires,
			MaxAge:     cookie.MaxAge,
			Secure:     cookie.Secure,
			HttpOnly:   cookie.HttpOnly,
			SameSite:   nhttp.SameSite(cookie.SameSite),
			Raw:        cookie.Raw,
			Unparsed:   cookie.Unparsed,
		}
		netCookies = append(netCookies, netCookie)
	}

	return Response{
		Status:    resp.StatusCode,
		Body:      string(bodyBytes),
		BodyBytes: bodyBytes, // Provide raw bytes for binary data
		Headers:   headers,
		Cookies:   netCookies,
		FinalUrl:  finalUrl,
	}, nil
}
