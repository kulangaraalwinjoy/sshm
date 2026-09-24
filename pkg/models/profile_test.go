package models

import (
	"testing"
)

func TestSSHProfileValidation(t *testing.T) {
	tests := []struct {
		name    string
		profile *SSHProfile
		wantErr bool
	}{
		{
			name: "Valid profile",
			profile: &SSHProfile{
				Name:       "prod-server",
				Host:       "192.168.1.100",
				Port:       22,
				Username:   "root",
				AuthMethod: AuthMethodPassword,
			},
			wantErr: false,
		},
		{
			name: "Empty name",
			profile: &SSHProfile{
				Name:       "",
				Host:       "192.168.1.100",
				Port:       22,
				Username:   "root",
				AuthMethod: AuthMethodPassword,
			},
			wantErr: true,
		},
		{
			name: "Invalid name characters",
			profile: &SSHProfile{
				Name:       "prod server!",
				Host:       "192.168.1.100",
				Port:       22,
				Username:   "root",
				AuthMethod: AuthMethodPassword,
			},
			wantErr: true,
		},
		{
			name: "Empty host",
			profile: &SSHProfile{
				Name:       "valid",
				Host:       "",
				Port:       22,
				Username:   "root",
				AuthMethod: AuthMethodPassword,
			},
			wantErr: true,
		},
		{
			name: "Invalid port (0)",
			profile: &SSHProfile{
				Name:       "valid",
				Host:       "1.1.1.1",
				Port:       0,
				Username:   "root",
				AuthMethod: AuthMethodPassword,
			},
			wantErr: true,
		},
		{
			name: "Invalid port (70000)",
			profile: &SSHProfile{
				Name:       "valid",
				Host:       "1.1.1.1",
				Port:       70000,
				Username:   "root",
				AuthMethod: AuthMethodPassword,
			},
			wantErr: true,
		},
		{
			name: "Empty username",
			profile: &SSHProfile{
				Name:       "valid",
				Host:       "1.1.1.1",
				Port:       22,
				Username:   "",
				AuthMethod: AuthMethodPassword,
			},
			wantErr: true,
		},
		{
			name: "Invalid auth method",
			profile: &SSHProfile{
				Name:       "valid",
				Host:       "1.1.1.1",
				Port:       22,
				Username:   "user",
				AuthMethod: "invalid-auth",
			},
			wantErr: true,
		},
		{
			name: "Valid local forward rule",
			profile: &SSHProfile{
				Name:          "tunnel-profile",
				Host:          "1.1.1.1",
				Port:          22,
				Username:      "user",
				AuthMethod:    AuthMethodPassword,
				LocalForwards: []string{"8080:localhost:80"},
			},
			wantErr: false,
		},
		{
			name: "Invalid local forward rule",
			profile: &SSHProfile{
				Name:          "tunnel-profile",
				Host:          "1.1.1.1",
				Port:          22,
				Username:      "user",
				AuthMethod:    AuthMethodPassword,
				LocalForwards: []string{"bad_port_spec"},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.profile.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestParsePortForwardSpec(t *testing.T) {
	rule, err := ParsePortForwardSpec("8080:localhost:80")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rule.LocalPort != 8080 || rule.RemoteHost != "localhost" || rule.RemotePort != 80 {
		t.Errorf("unexpected rule values: %+v", rule)
	}

	rule2, err := ParsePortForwardSpec("3000:3000")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rule2.LocalPort != 3000 || rule2.RemotePort != 3000 || rule2.RemoteHost != "127.0.0.1" {
		t.Errorf("unexpected rule2 values: %+v", rule2)
	}

	rule3, err := ParsePortForwardSpec("0.0.0.0:8080:10.0.0.1:80")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rule3.BindHost != "0.0.0.0" || rule3.LocalPort != 8080 || rule3.RemoteHost != "10.0.0.1" || rule3.RemotePort != 80 {
		t.Errorf("unexpected rule3 values: %+v", rule3)
	}

	_, err = ParsePortForwardSpec("invalid")
	if err == nil {
		t.Errorf("expected error for invalid port spec")
	}
}

func TestProfileCredentialsZero(t *testing.T) {
	creds := &ProfileCredentials{
		Password:   "supersecret",
		PrivateKey: []byte("sensitive-key-data"),
		Passphrase: "keypassphrase",
	}

	creds.Zero()

	if creds.Password != "" {
		t.Errorf("expected password to be cleared")
	}
	if creds.Passphrase != "" {
		t.Errorf("expected passphrase to be cleared")
	}
	if len(creds.PrivateKey) != 0 {
		t.Errorf("expected private key to be nil or 0 length")
	}
	if !creds.IsEmpty() {
		t.Errorf("expected IsEmpty() to be true")
	}
}
