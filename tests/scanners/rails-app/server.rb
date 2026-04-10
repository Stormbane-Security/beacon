require "webrick"

server = WEBrick::HTTPServer.new(Port: 3000, BindAddress: "0.0.0.0")

server.mount_proc "/" do |req, res|
  # Rails-like fingerprints: X-Runtime header, X-Request-Id, Set-Cookie with _session_id
  res["X-Runtime"] = "0.042315"
  res["X-Request-Id"] = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
  res["Set-Cookie"] = "_app_session=dGVzdA==; path=/; HttpOnly"
  res["Content-Type"] = "text/html"
  res.body = <<~HTML
    <html>
    <head><title>Rails App</title>
    <meta name="csrf-param" content="authenticity_token" />
    <meta name="csrf-token" content="test-token" />
    </head>
    <body><h1>Welcome to Rails</h1></body>
    </html>
  HTML
end

trap("INT") { server.shutdown }
server.start
