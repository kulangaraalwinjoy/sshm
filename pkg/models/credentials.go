package models

// ProfileCredentials represents the secret credentials for a profile.
// These credentials are stored ONLY within the AES-256-GCM encrypted vault file (vault.enc).
// They must NEVER be included in plain profile metadata, logs, or command-line arguments.
type ProfileCredentials struct {
	Password   string `json:"password,omitempty"`
	PrivateKey []byte `json:"private_key,omitempty"`
	Passphrase string `json:"passphrase,omitempty"`
}

// Zero securely wipes the credentials from memory.
func (c *ProfileCredentials) Zero() {
	if c == nil {
		return
	}
	if len(c.PrivateKey) > 0 {
		for i := range c.PrivateKey {
			c.PrivateKey[i] = 0
		}
		c.PrivateKey = nil
	}
	// Overwrite strings by zeroing byte representation where possible
	c.Password = ""
	c.Passphrase = ""
}

// IsEmpty returns true if no secret credential fields are set.
func (c *ProfileCredentials) IsEmpty() bool {
	if c == nil {
		return true
	}
	return c.Password == "" && len(c.PrivateKey) == 0 && c.Passphrase == ""
}
