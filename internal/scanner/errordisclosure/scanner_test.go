package errordisclosure

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stormbane-security/beacon/internal/module"
)

func TestStackTraceDetection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.WriteHeader(200)
			fmt.Fprint(w, "<html><body>OK</body></html>")
			return
		}
		w.WriteHeader(500)
		fmt.Fprint(w, `<html><body>
<h1>Internal Server Error</h1>
<pre>
Traceback (most recent call last):
  File "/app/views.py", line 42, in handle_request
    result = db.query(user_input)
  File "/app/database.py", line 15, in query
    cursor.execute(sql)
psycopg2.ProgrammingError: syntax error at or near "'"
</pre>
</body></html>`)
	}))
	defer srv.Close()

	s := New()
	asset := srv.Listener.Addr().String()
	findings, err := s.Run(context.Background(), asset, module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected stack trace finding, got none")
	}
	found := false
	for _, f := range findings {
		if f.CheckID == "web.error_info_leak" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected web.error_info_leak check ID, got: %v", findings)
	}
}

func TestDebugEndpointDetection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/debug/pprof/" {
			w.WriteHeader(200)
			fmt.Fprint(w, `<html>
<body>
<h1>pprof</h1>
goroutines: 42
memstats: {...}
cmdline: /app/server
</body>
</html>`)
			return
		}
		w.WriteHeader(404)
		fmt.Fprint(w, "not found")
	}))
	defer srv.Close()

	s := New()
	asset := srv.Listener.Addr().String()
	findings, err := s.Run(context.Background(), asset, module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected debug endpoint finding, got none")
	}
	found := false
	for _, f := range findings {
		if f.CheckID == "web.debug_endpoint" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected web.debug_endpoint check ID, got: %v", findings)
	}
}

func TestNoFalsePositiveOnCleanServer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.WriteHeader(200)
			fmt.Fprint(w, "<html><body>Welcome</body></html>")
			return
		}
		w.WriteHeader(404)
		fmt.Fprint(w, `{"error":"not found"}`)
	}))
	defer srv.Close()

	s := New()
	asset := srv.Listener.Addr().String()
	findings, err := s.Run(context.Background(), asset, module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings on clean server, got %d: %v", len(findings), findings)
	}
}

func TestJavaStackTrace(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.WriteHeader(200)
			return
		}
		w.WriteHeader(500)
		fmt.Fprint(w, `java.lang.NullPointerException
	at com.example.app.UserService.getUser(UserService.java:42)
	at com.example.app.Controller.handle(Controller.java:15)
	at org.springframework.web.servlet.FrameworkServlet.service(FrameworkServlet.java:897)`)
	}))
	defer srv.Close()

	s := New()
	asset := srv.Listener.Addr().String()
	findings, err := s.Run(context.Background(), asset, module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected Java stack trace finding, got none")
	}
}

func TestDotNetStackTrace(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.WriteHeader(200)
			return
		}
		w.WriteHeader(500)
		fmt.Fprint(w, `Server Error in '/' Application.
System.NullReferenceException: Object reference not set to an instance of an object.
   at MyApp.Controllers.HomeController.Index() in C:\Projects\MyApp\Controllers\HomeController.cs:15`)
	}))
	defer srv.Close()

	s := New()
	asset := srv.Listener.Addr().String()
	findings, err := s.Run(context.Background(), asset, module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected .NET stack trace finding, got none")
	}
}

func TestDjangoDebugMode(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.WriteHeader(200)
			return
		}
		w.WriteHeader(500)
		fmt.Fprint(w, `<!DOCTYPE html>
<html><head><title>Page not found at /test</title></head>
<body>
<div id="info">
Using the URLconf defined in <code>myproject.urls</code>, Django tried these URL patterns...
django.core.exceptions.ImproperlyConfigured
</div>
</body></html>`)
	}))
	defer srv.Close()

	s := New()
	asset := srv.Listener.Addr().String()
	findings, err := s.Run(context.Background(), asset, module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected Django debug mode finding, got none")
	}
}
