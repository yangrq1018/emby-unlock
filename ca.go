package main

import (
	"crypto/tls"
	"crypto/x509"
	_ "embed"

	"gopkg.in/elazarl/goproxy.v1"
)

var (
	//go:embed certs/ca.pem
	caCert []byte
	//go:embed certs/ca.key.pem
	caKey []byte
)

// SetCA sets the goproxy global CA
func SetCA(CaCert, CaKey []byte) error {
	Ca, err := tls.X509KeyPair(CaCert, CaKey)
	if err != nil {
		return err
	}
	if Ca.Leaf, err = x509.ParseCertificate(Ca.Certificate[0]); err != nil {
		return err
	}
	goproxy.GoproxyCa = Ca
	goproxy.OkConnect = &goproxy.ConnectAction{Action: goproxy.ConnectAccept, TLSConfig: goproxy.TLSConfigFromCA(&Ca)}
	goproxy.MitmConnect = &goproxy.ConnectAction{Action: goproxy.ConnectMitm, TLSConfig: goproxy.TLSConfigFromCA(&Ca)}
	goproxy.HTTPMitmConnect = &goproxy.ConnectAction{Action: goproxy.ConnectHTTPMitm, TLSConfig: goproxy.TLSConfigFromCA(&Ca)}
	goproxy.RejectConnect = &goproxy.ConnectAction{Action: goproxy.ConnectReject, TLSConfig: goproxy.TLSConfigFromCA(&Ca)}
	return nil
}

func initCA() error {
	setCAErr := SetCA(caCert, caKey)
	if setCAErr != nil {
		return setCAErr
	}
	return nil
}
