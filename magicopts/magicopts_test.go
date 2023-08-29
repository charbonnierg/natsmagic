package magicopts_test

import (
	"encoding/json"
	"testing"

	magic "github.com/charbonnierg-dev/natsmagic/magicopts"
)

func TestMarshallMagicOptions(t *testing.T) {
	// Create new options
	opts, err := magic.New()
	if err != nil {
		t.Errorf(err.Error())
	}
	// Encode options
	encoded, err := json.Marshal(opts)
	if err != nil {
		t.Errorf(err.Error())
	}
	// Decode options
	decoded := &magic.NatsMagic{}
	decodeError := json.Unmarshal(encoded, decoded)
	if decodeError != nil {
		t.Errorf(err.Error())
	}
	// Encode options again
	encoded2, err2 := json.Marshal(decoded)
	if err2 != nil {
		t.Errorf(err2.Error())
	}
	// Check decoded options
	if decoded.LetsEncryptDnsProvider != magic.DigitalOcean {
		t.Errorf("Expected DigitalOcean but got %s", decoded.LetsEncryptDnsProvider)
	}
	if string(encoded) != string(encoded2) {
		t.Errorf("Expected %s but got %s", string(encoded), string(encoded2))
	}
}

func TestUnmarshallAzureDnsProvider(t *testing.T) {
	data := []byte(`{"letsencrypt_dns_provider":"azure"}`)
	decoded := &magic.NatsMagic{}
	err := json.Unmarshal(data, decoded)
	if err != nil {
		t.Errorf(err.Error())
	}
	if decoded.LetsEncryptDnsProvider != magic.Azure {
		t.Error("Expected azure but got", decoded.LetsEncryptDnsProvider)
	}
}

func TestUnmarshallDigitalOceanDnsProvider(t *testing.T) {
	data := []byte(`{"letsencrypt_dns_provider":"digitalocean"}`)
	decoded := &magic.NatsMagic{}
	err := json.Unmarshal(data, decoded)
	if err != nil {
		t.Errorf(err.Error())
	}
	if decoded.LetsEncryptDnsProvider != magic.DigitalOcean {
		t.Error("Expected digitalocean but got", decoded.LetsEncryptDnsProvider)
	}
}

func TestUnmarshallRoute53Provider(t *testing.T) {
	data := []byte(`{"letsencrypt_dns_provider":"route53"}`)
	decoded := &magic.NatsMagic{}
	err := json.Unmarshal(data, decoded)
	if err != nil {
		t.Errorf(err.Error())
	}
	if decoded.LetsEncryptDnsProvider != magic.Route53 {
		t.Error("Expected route53 but got", decoded.LetsEncryptDnsProvider)
	}
}
