package ebpf

import (
	"encoding/hex"
	"testing"
)

func hexBytes(t *testing.T, s string) [16]byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	var out [16]byte
	copy(out[:], b)
	return out
}

func TestGF128MulIdentity(t *testing.T) {
	// Identity in GHASH convention: 0x80, 0x00, ..., 0x00
	var identity [16]byte
	identity[0] = 0x80

	x := hexBytes(t, "0388dace60b6a392f328c2b971b2fe78")
	result := GF128Mul(identity, x)
	if result != x {
		t.Errorf("identity * x != x\ngot:  %x\nwant: %x", result, x)
	}

	result = GF128Mul(x, identity)
	if result != x {
		t.Errorf("x * identity != x\ngot:  %x\nwant: %x", result, x)
	}
}

func TestGF128MulZero(t *testing.T) {
	var zero, result [16]byte
	x := hexBytes(t, "0388dace60b6a392f328c2b971b2fe78")
	result = GF128Mul(zero, x)
	if result != zero {
		t.Errorf("zero * x != zero: got %x", result)
	}
}

func TestGF128MulCommutativity(t *testing.T) {
	a := hexBytes(t, "0388dace60b6a392f328c2b971b2fe78")
	b := hexBytes(t, "66e94bd4ef8a2c3b884cfa59ca342b2e")
	ab := GF128Mul(a, b)
	ba := GF128Mul(b, a)
	if ab != ba {
		t.Errorf("a*b != b*a\na*b: %x\nb*a: %x", ab, ba)
	}
}

func TestGF128MulAssociativity(t *testing.T) {
	a := hexBytes(t, "0388dace60b6a392f328c2b971b2fe78")
	b := hexBytes(t, "66e94bd4ef8a2c3b884cfa59ca342b2e")
	c := hexBytes(t, "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")

	ab := GF128Mul(a, b)
	ab_c := GF128Mul(ab, c)

	bc := GF128Mul(b, c)
	a_bc := GF128Mul(a, bc)

	if ab_c != a_bc {
		t.Errorf("(a*b)*c != a*(b*c)\n(a*b)*c: %x\na*(b*c): %x", ab_c, a_bc)
	}
}

func TestGF128HPower(t *testing.T) {
	h := hexBytes(t, "66e94bd4ef8a2c3b884cfa59ca342b2e")

	// H^1 = H
	r1 := GF128HPower(h, 1)
	if r1 != h {
		t.Errorf("H^1 != H\ngot:  %x\nwant: %x", r1, h)
	}

	// H^2 = H * H
	expected2 := GF128Mul(h, h)
	r2 := GF128HPower(h, 2)
	if r2 != expected2 {
		t.Errorf("H^2 mismatch\ngot:  %x\nwant: %x", r2, expected2)
	}

	// H^3 = H^2 * H
	expected3 := GF128Mul(expected2, h)
	r3 := GF128HPower(h, 3)
	if r3 != expected3 {
		t.Errorf("H^3 mismatch\ngot:  %x\nwant: %x", r3, expected3)
	}

	// H^5 = H^4 * H
	h4 := GF128Mul(expected2, expected2)
	expected5 := GF128Mul(h4, h)
	r5 := GF128HPower(h, 5)
	if r5 != expected5 {
		t.Errorf("H^5 mismatch\ngot:  %x\nwant: %x", r5, expected5)
	}
}

func TestComputeHPowerTable(t *testing.T) {
	h := hexBytes(t, "66e94bd4ef8a2c3b884cfa59ca342b2e")
	table := ComputeHPowerTable(h)

	// table[0] = H^1
	if table[0] != h {
		t.Errorf("table[0] != H")
	}
	// table[1] = H^2
	expected := GF128Mul(h, h)
	if table[1] != expected {
		t.Errorf("table[1] != H^2")
	}
	// table[2] = H^4 = (H^2)^2
	expected = GF128Mul(table[1], table[1])
	if table[2] != expected {
		t.Errorf("table[2] != H^4")
	}
}

func TestHPowerTableMatchesSlowPath(t *testing.T) {
	h := hexBytes(t, "66e94bd4ef8a2c3b884cfa59ca342b2e")
	table := ComputeHPowerTable(h)

	testPowers := []uint32{1, 2, 3, 5, 7, 10, 100, 1024}
	for _, power := range testPowers {
		slow := GF128HPower(h, power)

		// Fast path using table
		var fast [16]byte
		fast[0] = 0x80
		for i := 0; i < 11; i++ {
			if power&(1<<uint(i)) != 0 {
				fast = GF128Mul(fast, table[i])
			}
		}

		if slow != fast {
			t.Errorf("H^%d: slow path != fast path\nslow: %x\nfast: %x", power, slow, fast)
		}
	}
}

func BenchmarkGF128Mul(b *testing.B) {
	a := [16]byte{0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92,
		0xf3, 0x28, 0xc2, 0xb9, 0x71, 0xb2, 0xfe, 0x78}
	x := [16]byte{0x66, 0xe9, 0x4b, 0xd4, 0xef, 0x8a, 0x2c, 0x3b,
		0x88, 0x4c, 0xfa, 0x59, 0xca, 0x34, 0x2b, 0x2e}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		GF128Mul(a, x)
	}
}
