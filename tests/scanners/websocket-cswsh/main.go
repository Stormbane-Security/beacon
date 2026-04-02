package main

import (
	"fmt"
	"log"
	"net/http"

	"golang.org/x/net/websocket"
)

func echoHandler(ws *websocket.Conn) {
	// VULNERABLE: no Origin check — any website can open a WebSocket to this server
	var msg string
	for {
		if err := websocket.Message.Receive(ws, &msg); err != nil {
			break
		}
		websocket.Message.Send(ws, "echo: "+msg)
	}
}

func main() {
	http.Handle("/ws", websocket.Handler(echoHandler))
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		fmt.Fprint(w, `<html><body><h1>WebSocket Test</h1>
<script>
var ws = new WebSocket("ws://" + location.host + "/ws");
ws.onmessage = function(e) { document.body.innerHTML += "<p>" + e.data + "</p>"; };
ws.onopen = function() { ws.send("hello"); };
</script></body></html>`)
	})
	log.Fatal(http.ListenAndServe(":8080", nil))
}
