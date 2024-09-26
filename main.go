package main

import (
	"io"
	"log"
	"net"
	"net/http"
	"time"
)

func main() {
	server := &http.Server{
		Addr: ":8080",
		Handler: http.HandlerFunc(proxyHandler),
	}

	log.Println("Starting MITM proxy on port 8080")
	log.Fatal(server.ListenAndServe())
}

func proxyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		// handle https
		handleHttp(w, r)
	} else {
		// handle http
		handleHttps(w, r)
	}
}

// handles HTTP request by forwading them
func handleHttp(w http.ResponseWriter, r *http.Request) {
	log.Println(r.URL.String())
	client := &http.Client{}
	req, _ := http.NewRequest(r.Method, r.URL.String(), r.Body)
	copyHeaders(req.Header, r.Header)
	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, "Server Error", http.StatusInternalServerError)
		return
	}

	defer resp.Body.Close()
	copyHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func handleHttps(w http.ResponseWriter, r *http.Request) {
	// hijack the connection to handle the CONNECT
	hijaker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijaker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer clientConn.Close()

	serverConn, err := net.DialTimeout("tcp", r.Host, 10*time.Second)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer serverConn.Close()
	
	clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	go io.Copy(serverConn, clientConn)
	io.Copy(clientConn, serverConn)
}

func copyHeaders(dst, src http.Header) {
	for k, v := range src {
		dst[k] = v
	}
}