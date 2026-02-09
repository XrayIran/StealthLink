package warp

import "testing"

func TestRegisterWARPPlusLicenseValidation(t *testing.T) {
	c := NewRegistrationClient()
	if err := c.RegisterWARPPlusLicense("", "", ""); err == nil {
		t.Fatal("expected validation error")
	}
}
