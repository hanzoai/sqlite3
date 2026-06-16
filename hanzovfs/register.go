package hanzovfs

import "github.com/luxfi/age"

// GenerateIdentity returns a fresh PQ-hybrid (ML-KEM-768 + X25519) identity and
// its recipient, ready for a Config. In production these come from KMS per HIP-0302.
func GenerateIdentity() (age.Identity, age.Recipient, error) {
	id, err := age.GenerateHybridIdentity()
	if err != nil {
		return nil, nil, err
	}
	return id, id.Recipient(), nil
}
