package carrier

import (
	"bytes"
	"testing"
)

func TestFrameMarshalUnmarshal(t *testing.T) {
	tests := []struct {
		name    string
		frame   Frame
		wantErr bool
	}{
		{
			name: "data frame with payload",
			frame: Frame{
				Version:      FrameVersion,
				Type:         FrameTypeData,
				Flags:        FrameFlagReliable,
				ConnectionID: 12345,
				StreamID:     67890,
				Padding:      nil,
				Payload:      []byte("hello world"),
			},
			wantErr: false,
		},
		{
			name: "control frame with padding",
			frame: Frame{
				Version:      FrameVersion,
				Type:         FrameTypeControl,
				Flags:        FrameFlagEncrypted,
				ConnectionID: 11111,
				StreamID:     0,
				Padding:      []byte{0x00, 0x01, 0x02, 0x03},
				Payload:      []byte("control"),
			},
			wantErr: false,
		},
		{
			name: "cover traffic frame",
			frame: Frame{
				Version:      FrameVersion,
				Type:         FrameTypeCover,
				Flags:        0,
				ConnectionID: 99999,
				StreamID:     1,
				Padding:      make([]byte, 100),
				Payload:      make([]byte, 200),
			},
			wantErr: false,
		},
		{
			name: "frame with all flags",
			frame: Frame{
				Version:      FrameVersion,
				Type:         FrameTypeData,
				Flags:        FrameFlagReliable | FrameFlagEncrypted | FrameFlagCompressed,
				ConnectionID: 1,
				StreamID:     2,
				Padding:      nil,
				Payload:      []byte("test"),
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Marshal
			data, err := tt.frame.Marshal()
			if (err != nil) != tt.wantErr {
				t.Errorf("Marshal() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
			}

			// Unmarshal
			var decoded Frame
			if err := decoded.Unmarshal(data); err != nil {
				t.Errorf("Unmarshal() error = %v", err)
				return
			}

			// Compare
			if decoded.Version != tt.frame.Version {
				t.Errorf("Version mismatch: got %d, want %d", decoded.Version, tt.frame.Version)
			}
			if decoded.Type != tt.frame.Type {
				t.Errorf("Type mismatch: got %d, want %d", decoded.Type, tt.frame.Type)
			}
			if decoded.Flags != tt.frame.Flags {
				t.Errorf("Flags mismatch: got %d, want %d", decoded.Flags, tt.frame.Flags)
			}
			if decoded.ConnectionID != tt.frame.ConnectionID {
				t.Errorf("ConnectionID mismatch: got %d, want %d", decoded.ConnectionID, tt.frame.ConnectionID)
			}
			if decoded.StreamID != tt.frame.StreamID {
				t.Errorf("StreamID mismatch: got %d, want %d", decoded.StreamID, tt.frame.StreamID)
			}
			if !bytes.Equal(decoded.Padding, tt.frame.Padding) {
				t.Errorf("Padding mismatch: got %v, want %v", decoded.Padding, tt.frame.Padding)
			}
			if !bytes.Equal(decoded.Payload, tt.frame.Payload) {
				t.Errorf("Payload mismatch: got %v, want %v", decoded.Payload, tt.frame.Payload)
			}
		})
	}
}

func TestFrameValidation(t *testing.T) {
	tests := []struct {
		name    string
		frame   Frame
		wantErr bool
	}{
		{
			name: "valid frame",
			frame: Frame{
				Version:      FrameVersion,
				Type:         FrameTypeData,
				Flags:        0,
				ConnectionID: 1,
				StreamID:     1,
				Padding:      nil,
				Payload:      []byte("test"),
			},
			wantErr: false,
		},
		{
			name: "invalid version",
			frame: Frame{
				Version:      0xFF,
				Type:         FrameTypeData,
				Flags:        0,
				ConnectionID: 1,
				StreamID:     1,
				Padding:      nil,
				Payload:      []byte("test"),
			},
			wantErr: true,
		},
		{
			name: "invalid type",
			frame: Frame{
				Version:      FrameVersion,
				Type:         0xFF,
				Flags:        0,
				ConnectionID: 1,
				StreamID:     1,
				Padding:      nil,
				Payload:      []byte("test"),
			},
			wantErr: true,
		},
		{
			name: "frame too large",
			frame: Frame{
				Version:      FrameVersion,
				Type:         FrameTypeData,
				Flags:        0,
				ConnectionID: 1,
				StreamID:     1,
				Padding:      make([]byte, MaxFrameSize),
				Payload:      []byte("test"),
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.frame.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestFrameFlags(t *testing.T) {
	frame := Frame{
		Version:      FrameVersion,
		Type:         FrameTypeData,
		Flags:        0,
		ConnectionID: 1,
		StreamID:     1,
	}

	// Test HasFlag
	if frame.HasFlag(FrameFlagReliable) {
		t.Error("HasFlag() returned true for unset flag")
	}

	// Test SetFlag
	frame.SetFlag(FrameFlagReliable)
	if !frame.HasFlag(FrameFlagReliable) {
		t.Error("HasFlag() returned false after SetFlag()")
	}

	// Test multiple flags
	frame.SetFlag(FrameFlagEncrypted)
	if !frame.HasFlag(FrameFlagReliable) || !frame.HasFlag(FrameFlagEncrypted) {
		t.Error("HasFlag() failed with multiple flags")
	}

	// Test ClearFlag
	frame.ClearFlag(FrameFlagReliable)
	if frame.HasFlag(FrameFlagReliable) {
		t.Error("HasFlag() returned true after ClearFlag()")
	}
	if !frame.HasFlag(FrameFlagEncrypted) {
		t.Error("ClearFlag() cleared wrong flag")
	}
}

func TestFrameSize(t *testing.T) {
	tests := []struct {
		name     string
		frame    Frame
		wantSize int
	}{
		{
			name: "header only",
			frame: Frame{
				Version:      FrameVersion,
				Type:         FrameTypeData,
				ConnectionID: 1,
				StreamID:     1,
			},
			wantSize: FrameHeaderSize,
		},
		{
			name: "with payload",
			frame: Frame{
				Version:      FrameVersion,
				Type:         FrameTypeData,
				ConnectionID: 1,
				StreamID:     1,
				Payload:      []byte("hello"),
			},
			wantSize: FrameHeaderSize + 5,
		},
		{
			name: "with padding and payload",
			frame: Frame{
				Version:      FrameVersion,
				Type:         FrameTypeData,
				ConnectionID: 1,
				StreamID:     1,
				Padding:      make([]byte, 10),
				Payload:      []byte("hello"),
			},
			wantSize: FrameHeaderSize + 10 + 5,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.frame.Size(); got != tt.wantSize {
				t.Errorf("Size() = %d, want %d", got, tt.wantSize)
			}
		})
	}
}

func TestFrameUnmarshalErrors(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		wantErr bool
	}{
		{
			name:    "too short",
			data:    []byte{0x01, 0x02},
			wantErr: true,
		},
		{
			name:    "truncated payload",
			data:    append(make([]byte, FrameHeaderSize), 0x00, 0x00, 0x00, 0x0A, 0x00, 0x64), // claims 100 byte payload but only 6 bytes
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var frame Frame
			err := frame.Unmarshal(tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("Unmarshal() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
