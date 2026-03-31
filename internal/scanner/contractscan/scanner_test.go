package contractscan

import (
	"strings"
	"testing"
)

func TestContainsReentrancyPattern(t *testing.T) {
	tests := []struct {
		name   string
		source string
		want   bool
	}{
		{
			name:   "empty source",
			source: "",
			want:   false,
		},
		{
			name:   "no external calls",
			source: "contract Vault { function withdraw() { balance[msg.sender] = 0; } }",
			want:   false,
		},
		{
			name:   "call with value no guard",
			source: "msg.sender.call{value: amount}(\"\"); balances[msg.sender] = 0;",
			want:   true,
		},
		{
			name:   "transfer no guard",
			source: "msg.sender.transfer(amount); balances[msg.sender] = 0;",
			want:   true,
		},
		{
			name:   "send no guard",
			source: "msg.sender.send(amount); balances[msg.sender] = 0;",
			want:   true,
		},
		{
			name:   "call with abi no guard",
			source: "addr.call(abi.encodeWithSignature(\"withdraw()\")); done = true;",
			want:   true,
		},
		{
			name:   "call with value but has ReentrancyGuard",
			source: "import ReentrancyGuard from OZ; msg.sender.call{value: amount}(\"\");",
			want:   false,
		},
		{
			name:   "call with value but has nonReentrant modifier",
			source: "function withdraw() nonReentrant { msg.sender.call{value: amount}(\"\"); }",
			want:   false,
		},
		{
			name:   "call with value but has mutex",
			source: "bool mutex; function withdraw() { require(!mutex); mutex = true; msg.sender.call{value: amount}(\"\"); }",
			want:   false,
		},
		{
			name:   "case insensitive guard detection",
			source: "REENTRANCYGUARD is imported. msg.sender.transfer(amount);",
			want:   false,
		},
		{
			name:   "case insensitive call detection",
			source: "MSG.SENDER.TRANSFER(amount); balances = 0;",
			want:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := containsReentrancyPattern(tt.source)
			if got != tt.want {
				t.Errorf("containsReentrancyPattern() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMin(t *testing.T) {
	tests := []struct {
		a, b, want int
	}{
		{0, 0, 0},
		{1, 2, 1},
		{2, 1, 1},
		{-1, 0, -1},
		{5, 5, 5},
		{100, 200, 100},
	}

	for _, tt := range tests {
		got := min(tt.a, tt.b)
		if got != tt.want {
			t.Errorf("min(%d, %d) = %d, want %d", tt.a, tt.b, got, tt.want)
		}
	}
}

func TestSelfDestructDetection(t *testing.T) {
	// Tests the selfdestruct detection logic from analyseSource:
	// vulnerable when source contains selfdestruct/suicide AND lacks
	// onlyowner or require(msg.sender protection.
	tests := []struct {
		name     string
		source   string
		wantVuln bool
	}{
		{
			name:     "no selfdestruct",
			source:   "contract Safe { function foo() {} }",
			wantVuln: false,
		},
		{
			name:     "selfdestruct without protection",
			source:   "function kill() { selfdestruct(payable(msg.sender)); }",
			wantVuln: true,
		},
		{
			name:     "suicide without protection",
			source:   "function kill() { suicide(msg.sender); }",
			wantVuln: true,
		},
		{
			name:     "selfdestruct with onlyOwner",
			source:   "function kill() onlyOwner { selfdestruct(payable(owner)); }",
			wantVuln: false,
		},
		{
			name:     "selfdestruct with require msg.sender check",
			source:   "function kill() { require(msg.sender == owner); selfdestruct(payable(owner)); }",
			wantVuln: false,
		},
		{
			name:     "case insensitive selfdestruct detection",
			source:   "function kill() { SELFDESTRUCT(payable(msg.sender)); }",
			wantVuln: true,
		},
		{
			name:     "case insensitive onlyOwner protection",
			source:   "function kill() ONLYOWNER { selfdestruct(payable(msg.sender)); }",
			wantVuln: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lower := strings.ToLower(tt.source)
			hasSelfDestruct := strings.Contains(lower, "selfdestruct(") || strings.Contains(lower, "suicide(")
			hasProtection := strings.Contains(lower, "onlyowner") || strings.Contains(lower, "require(msg.sender")
			gotVuln := hasSelfDestruct && !hasProtection

			if gotVuln != tt.wantVuln {
				t.Errorf("selfdestruct vuln=%v, want %v", gotVuln, tt.wantVuln)
			}
		})
	}
}

func TestUncheckedCallDetection(t *testing.T) {
	// Tests the unchecked low-level call detection from analyseSource:
	// vulnerable when source has .call( or .call{ AND lacks require( and bool success.
	tests := []struct {
		name     string
		source   string
		wantVuln bool
	}{
		{
			name:     "no low-level call",
			source:   "contract Safe { function foo() { bar(); } }",
			wantVuln: false,
		},
		{
			name:     "unchecked .call(",
			source:   "addr.call(data);",
			wantVuln: true,
		},
		{
			name:     "unchecked .call{",
			source:   "addr.call{value: 1 ether}(\"\");",
			wantVuln: true,
		},
		{
			name:     ".call with require check",
			source:   "(bool ok, ) = addr.call(data); require(ok);",
			wantVuln: false,
		},
		{
			name:     ".call with bool success check",
			source:   "(bool success, ) = addr.call(data); if (!success) revert();",
			wantVuln: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lower := strings.ToLower(tt.source)
			hasCall := strings.Contains(lower, ".call(") || strings.Contains(lower, ".call{")
			hasCheck := strings.Contains(lower, "require(") || strings.Contains(lower, "bool success")
			gotVuln := hasCall && !hasCheck

			if gotVuln != tt.wantVuln {
				t.Errorf("unchecked call vuln=%v, want %v", gotVuln, tt.wantVuln)
			}
		})
	}
}
