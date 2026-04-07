package paramdiscovery

import (
	"reflect"
	"testing"
)

// ── ExtractParams (HTML) ────────────────────────────────────────────────────

func TestExtractParams_BasicForm(t *testing.T) {
	html := `<form action="/login" method="POST">
		<input type="text" name="username" />
		<input type="password" name="password" />
		<input type="hidden" name="csrf_token" value="abc123" />
		<input type="submit" value="Login" />
	</form>`
	got := ExtractParams(html)
	want := []string{"csrf_token", "password", "username"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ExtractParams = %v, want %v", got, want)
	}
}

func TestExtractParams_SelectAndTextarea(t *testing.T) {
	html := `<form>
		<select name="country"><option>US</option></select>
		<textarea name="comment"></textarea>
	</form>`
	got := ExtractParams(html)
	want := []string{"comment", "country"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ExtractParams = %v, want %v", got, want)
	}
}

func TestExtractParams_Deduplication(t *testing.T) {
	html := `<input name="q" /><input name="q" /><input name="q" />`
	got := ExtractParams(html)
	want := []string{"q"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ExtractParams = %v, want %v", got, want)
	}
}

func TestExtractParams_Empty(t *testing.T) {
	got := ExtractParams(`<div>no forms here</div>`)
	if len(got) != 0 {
		t.Errorf("ExtractParams on no-form HTML = %v, want empty", got)
	}
}

func TestExtractParams_SingleQuotes(t *testing.T) {
	html := `<input name='email' type='text' />`
	got := ExtractParams(html)
	want := []string{"email"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ExtractParams = %v, want %v", got, want)
	}
}

// ── ExtractFromURLs ─────────────────────────────────────────────────────────

func TestExtractFromURLs_Basic(t *testing.T) {
	urls := []string{
		"https://example.com/search?q=test&page=1",
		"https://example.com/search?q=other&lang=en",
		"https://example.com/api/users?id=5&format=json",
	}
	got := ExtractFromURLs(urls)

	wantSearch := []string{"lang", "page", "q"}
	if !reflect.DeepEqual(got["/search"], wantSearch) {
		t.Errorf("/search params = %v, want %v", got["/search"], wantSearch)
	}

	wantAPI := []string{"format", "id"}
	if !reflect.DeepEqual(got["/api/users"], wantAPI) {
		t.Errorf("/api/users params = %v, want %v", got["/api/users"], wantAPI)
	}
}

func TestExtractFromURLs_NoQuery(t *testing.T) {
	urls := []string{"https://example.com/about", "https://example.com/contact"}
	got := ExtractFromURLs(urls)
	if len(got) != 0 {
		t.Errorf("ExtractFromURLs with no query = %v, want empty", got)
	}
}

func TestExtractFromURLs_MalformedURL(t *testing.T) {
	urls := []string{"://not-valid", "https://example.com/ok?a=1"}
	got := ExtractFromURLs(urls)
	if len(got) != 1 {
		t.Errorf("expected 1 path, got %d", len(got))
	}
}

func TestExtractFromURLs_EmptyPath(t *testing.T) {
	urls := []string{"https://example.com?foo=bar"}
	got := ExtractFromURLs(urls)
	want := []string{"foo"}
	if !reflect.DeepEqual(got["/"], want) {
		t.Errorf("/ params = %v, want %v", got["/"], want)
	}
}

// ── ExtractFromJSON ─────────────────────────────────────────────────────────

func TestExtractFromJSON_FlatObject(t *testing.T) {
	body := `{"username": "admin", "password": "secret", "remember": true}`
	got := ExtractFromJSON(body)
	want := []string{"password", "remember", "username"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ExtractFromJSON = %v, want %v", got, want)
	}
}

func TestExtractFromJSON_NestedObject(t *testing.T) {
	body := `{"user": {"name": "alice", "email": "a@b.com"}, "action": "login"}`
	got := ExtractFromJSON(body)
	want := []string{"action", "email", "name", "user"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ExtractFromJSON = %v, want %v", got, want)
	}
}

func TestExtractFromJSON_Array(t *testing.T) {
	body := `[{"id": 1, "name": "foo"}, {"id": 2, "tag": "bar"}]`
	got := ExtractFromJSON(body)
	want := []string{"id", "name", "tag"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ExtractFromJSON = %v, want %v", got, want)
	}
}

func TestExtractFromJSON_InvalidJSON(t *testing.T) {
	got := ExtractFromJSON(`not json at all`)
	if got != nil {
		t.Errorf("ExtractFromJSON(invalid) = %v, want nil", got)
	}
}

func TestExtractFromJSON_EmptyObject(t *testing.T) {
	got := ExtractFromJSON(`{}`)
	if len(got) != 0 {
		t.Errorf("ExtractFromJSON({}) = %v, want empty", got)
	}
}

// ── ExtractFromJS ───────────────────────────────────────────────────────────

func TestExtractFromJS_FetchBody(t *testing.T) {
	js := `fetch("/api/login", {
		method: "POST",
		body: { username: "admin", password: "pass123", remember_me: true }
	})`
	got := ExtractFromJS(js)
	assertContains(t, got, "username")
	assertContains(t, got, "password")
	assertContains(t, got, "remember_me")
}

func TestExtractFromJS_AxiosParams(t *testing.T) {
	js := `axios.get("/search", { params: { query: term, page: 1, limit: 20 } })`
	got := ExtractFromJS(js)
	assertContains(t, got, "query")
	assertContains(t, got, "page")
	assertContains(t, got, "limit")
}

func TestExtractFromJS_URLSearchParams(t *testing.T) {
	js := `var sp = new URLSearchParams();
	sp.append("search_term", value);
	sp.set("page_num", 1);`
	got := ExtractFromJS(js)
	assertContains(t, got, "search_term")
	assertContains(t, got, "page_num")
}

func TestExtractFromJS_QueryStringConcat(t *testing.T) {
	js := `var url = "/api?user_id=" + userId + "&token=" + tok;`
	got := ExtractFromJS(js)
	assertContains(t, got, "user_id")
	assertContains(t, got, "token")
}

func TestExtractFromJS_TemplateLiteral(t *testing.T) {
	js := "var url = `/api?item_id=${id}`;"
	got := ExtractFromJS(js)
	assertContains(t, got, "item_id")
}

func TestExtractFromJS_JQueryAjax(t *testing.T) {
	js := `$.post("/submit", { name: userName, email: userEmail })`
	got := ExtractFromJS(js)
	assertContains(t, got, "name")
	assertContains(t, got, "email")
}

func TestExtractFromJS_FiltersJSKeywords(t *testing.T) {
	js := `data = { var: 1, return: 2, action: "submit" }`
	got := ExtractFromJS(js)
	assertContains(t, got, "action")
	assertNotContains(t, got, "var")
	assertNotContains(t, got, "return")
}

func TestExtractFromJS_Empty(t *testing.T) {
	got := ExtractFromJS(`console.log("hello world");`)
	if len(got) != 0 {
		t.Errorf("ExtractFromJS on unrelated JS = %v, want empty", got)
	}
}

func TestIsLikelyParamName(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{"username", true},
		{"csrf_token", true},
		{"page-num", true},
		{"x", false},        // too short
		{"var", false},       // JS keyword
		{"return", false},    // JS keyword
		{"has space", false}, // contains space
		{"", false},          // empty
	}
	for _, tt := range tests {
		got := isLikelyParamName(tt.name)
		if got != tt.want {
			t.Errorf("isLikelyParamName(%q) = %v, want %v", tt.name, got, tt.want)
		}
	}
}

// ── helpers ─────────────────────────────────────────────────────────────────

func assertContains(t *testing.T, slice []string, val string) {
	t.Helper()
	for _, s := range slice {
		if s == val {
			return
		}
	}
	t.Errorf("expected %v to contain %q", slice, val)
}

func assertNotContains(t *testing.T, slice []string, val string) {
	t.Helper()
	for _, s := range slice {
		if s == val {
			t.Errorf("expected %v NOT to contain %q", slice, val)
			return
		}
	}
}
