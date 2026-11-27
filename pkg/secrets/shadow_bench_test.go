package secrets

import (
	"fmt"
	"testing"
)

// BenchmarkGenerateShadowValue measures shadow generation at long lengths,
// for a real value of average density 6 bits per byte (base64-like).
func BenchmarkGenerateShadowValue(b *testing.B) {
	for _, n := range []int{1 << 10, 64 << 10, 1 << 20} {
		bits := prefixHuffmanBits + (n-len(ValuePrefix))*6
		b.Run(fmt.Sprintf("%dKiB", n>>10), func(b *testing.B) {
			b.SetBytes(int64(n))
			for b.Loop() {
				if _, err := generateShadowValue(n, bits); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
