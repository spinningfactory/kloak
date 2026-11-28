package main

import (
	"fmt"

	"github.com/spf13/cobra"
	"k8s.io/apimachinery/pkg/api/resource"

	"github.com/spinningfactory/kloak/pkg/secrets"
)

// maxSecretLengthFlag registers --max-secret-length, the cluster's policy
// maximum for a kloak secret value's length, on the controller and the
// webhook (Helm: secrets.maxLength, which sets both). It returns where the
// flag's value is kept: parse it with parseMaxSecretLength.
func maxSecretLengthFlag(cmd *cobra.Command) *string {
	v := new(string)
	cmd.Flags().StringVar(v, "max-secret-length", fmt.Sprint(secrets.DefaultMaxLen),
		fmt.Sprintf("Longest kloak secret value accepted, in bytes (a Kubernetes quantity: 65536, 64Ki), at most %d (1Mi, Kubernetes' limit on a Secret). "+
			"The webhook rejects a Secret with a longer value; the controller leaves such a value out of the data plane (its placeholder is not rewritten). "+
			"The data plane takes values of at most %d bytes today, whatever this is set to.",
			secrets.MaxLenLimit, secrets.DataPlaneMaxLen))
	return v
}

// parseMaxSecretLength parses and checks --max-secret-length.
func parseMaxSecretLength(v string) (int, error) {
	n, err := parseByteQuantity(v)
	if err != nil {
		return 0, err
	}
	if n > secrets.MaxLenLimit {
		return 0, fmt.Errorf("%d bytes is more than %d", n, secrets.MaxLenLimit)
	}
	if err := secrets.ValidateMaxLen(int(n)); err != nil {
		return 0, err
	}
	return int(n), nil
}

// parseByteQuantity parses a whole number of bytes, written as a Kubernetes
// quantity ("16Mi", "65536").
func parseByteQuantity(v string) (int64, error) {
	q, err := resource.ParseQuantity(v)
	if err != nil {
		return 0, err
	}
	n, ok := q.AsInt64()
	if !ok || n < 0 {
		return 0, fmt.Errorf("%q is not a whole number of bytes", v)
	}
	return n, nil
}
