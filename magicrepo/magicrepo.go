package magicrepo

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/nats-io/nkeys"
)

type MagicForm struct {
	SubmitUrl string `json:"submit_url"`
	Nonce     string `json:"nonce"`
}

type MagicFormReply struct {
	Signature string `json:"signature"`
	Nonce     string `json:"nonce"`
}

type MagicRepo interface {
	GetRawMagic() ([]byte, error)
}

type HttpMagicRepo struct {
	encoder *base64.Encoding

	Url    string
	Server string
}

func NewHttpMagicRepo(url string, server string) *HttpMagicRepo {
	return &HttpMagicRepo{
		encoder: base64.URLEncoding.WithPadding(base64.NoPadding),
		Url:     url,
		Server:  server,
	}
}

func (h HttpMagicRepo) getUnauthenticatedRawMagic() ([]byte, error) {
	url, error := url.Parse(h.Url)
	if error != nil {
		return nil, error
	}
	targetUrl := url.JoinPath(h.Server).String()
	response, err := http.Get(targetUrl)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	content, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	if response.StatusCode == http.StatusOK {
		return content, nil
	}
	return nil, fmt.Errorf("unexpected status code: %d", response.StatusCode)
}

func (h HttpMagicRepo) GetRawMagic() ([]byte, error) {
	nkey, err := nkeys.FromSeed([]byte(h.Server))
	if err != nil {
		return h.getUnauthenticatedRawMagic()
	}
	publicKey, err := nkey.PublicKey()
	if err != nil {
		return nil, err
	}
	url, err := url.Parse(h.Url)
	if err != nil {
		return nil, err
	}
	targetUrl := url.JoinPath(publicKey).String()
	response, err := http.Get(targetUrl)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	content, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	if response.StatusCode == http.StatusOK {
		return content, nil
	}
	form := &MagicForm{}
	if response.StatusCode == http.StatusAccepted {
		err := json.Unmarshal(content, form)
		if err != nil {
			return nil, err
		}
	} else {
		return nil, fmt.Errorf("invalid response from magic server %s: %d", response.Request.URL.String(), response.StatusCode)
	}
	signature, err := nkey.Sign([]byte(form.Nonce))
	if err != nil {
		return nil, err
	}
	reply := &MagicFormReply{
		Signature: h.encoder.EncodeToString(signature),
		Nonce:     form.Nonce,
	}
	payload, err := json.Marshal(reply)
	if err != nil {
		return nil, err
	}
	response, err = http.Post(form.SubmitUrl, "application/json", bytes.NewBuffer(payload))
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	content, err = io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	if response.StatusCode == http.StatusOK {
		return content, nil
	}
	return nil, fmt.Errorf("unexpected status code: %d", response.StatusCode)
}
