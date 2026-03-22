package models

// ConvertRequest represents the user's uploaded data for SSL conversion.
type ConvertRequest struct {
	CurrentFormat string
	TargetFormat  string

	// Raw file bytes uploaded by the user
	Certificate []byte
	PrivateKey  []byte
	Chain1      []byte
	Chain2      []byte

	// PFX password, if provided
	PfxPassword string
}

// ConvertResponse is returned by the service containing the converted file
type ConvertResponse struct {
	Filename    string `json:"filename"`
	Data        string `json:"data"` // Base64 encoded file content
	ContentType string `json:"contentType"`
}
