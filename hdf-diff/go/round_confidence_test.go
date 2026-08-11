package diff

import "testing"

func TestRoundConfidence(t *testing.T) {
	cases := []struct {
		name string
		in   float64
		want float64
	}{
		{"noisy one third", 1 - 1.0/3.0, 0.6667},
		{"two thirds noise", 2.0 / 3.0, 0.6667},
		{"one third noise", 1.0 / 3.0, 0.3333},
		{"exact one", 1.0, 1.0},
		{"exact zero", 0.0, 0.0},
		{"half stays", 0.5, 0.5},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := roundConfidence(tc.in); got != tc.want {
				t.Fatalf("roundConfidence(%v) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}
