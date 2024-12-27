package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"time"
)

var uploadHTML = []byte(`<html lang="en">
<head>
  <link rel="shortcut icon" href="/favicon.ico">
  <meta charset="utf-8">
  <script src="https://cdn.tailwindcss.com?plugins=forms"></script>
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Updown</title>
</head>
<body>
  <form action="upload" method="post" enctype="multipart/form-data">
    <input type="file" name="file" />
    <button type="submit">Upload</button>
  </form>
</body>
</html>
`)

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /upload", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(uploadHTML)
	})
	mux.HandleFunc("POST /upload", func(w http.ResponseWriter, r *http.Request) {
		mr, err := r.MultipartReader()
		if err != nil {
			slog.Error("client error", "err", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		for {
			part, err := mr.NextPart()
			if err != nil {
				if errors.Is(err, io.EOF) {
					break
				}
				slog.Error("client error", "err", err)
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if part.FormName() != "file" {
				err = errors.New("not file form value")
				slog.Error("client error", "err", err.Error())
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if part.FileName() == "" {
				err = errors.New("empty file form value file name")
				slog.Error("client error", "err", err.Error())
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}

			file, err := os.Create(part.FileName())
			if err != nil {
				slog.Error("server error", "err", err)
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			size := int64(0)
			chunkSize := int64(20 * 1024 * 1024)
			slog.Info("start reading", "size", size)
			for {
				s, err := io.CopyN(file, part, chunkSize)
				size += s
				if err != nil {
					if errors.Is(err, io.EOF) {
						break
					}
					slog.Error("server error", "err", err)
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
				slog.Info("read chunk", "size", size, "chunk_size", chunkSize)
			}
			slog.Info("finished reading", "size", size)
		}
		w.WriteHeader(http.StatusNoContent)
	})

	tcpListener, err := net.Listen("tcp", "0.0.0.0:443")
	if err != nil {
		panic(err)
	}

	tlsConfig := tls.Config{}
	tlsConfig.NextProtos = []string{"http/1.1"}
	certPEMBlock, keyPEMBlock, err := newCertificate(nil)
	if err != nil {
		panic(err)
	}
	tlsConfig.Certificates = make([]tls.Certificate, 1)
	tlsConfig.Certificates[0], err = tls.X509KeyPair(certPEMBlock, keyPEMBlock)
	if err != nil {
		panic(err)
	}
	slog.Info("generated certificate", "fingerprint_sha256", certificateFingerprintSHA256(tlsConfig.Certificates[0]))
	tlsListener := tls.NewListener(tcpListener, &tlsConfig)

	err = http.Serve(tlsListener, mux)
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		panic(err)
	}
}

func certificateFingerprintSHA256(cert tls.Certificate) string {
	fingerprint := sha256.Sum256(cert.Leaf.Raw)
	return hex.EncodeToString(fingerprint[:])
}

func newCertificate(hosts []string) (certPEMBlock []byte, keyPEMBlock []byte, err error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	pub := &priv.PublicKey

	// RSA subject keys should have the DigitalSignature and KeyEncipherment
	// KeyUsage bits set in the x509.Certificate template.
	keyUsage := x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
	extKeyUsage := []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, err
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(24 * time.Hour)

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Acme Co"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              keyUsage,
		ExtKeyUsage:           extKeyUsage,
		BasicConstraintsValid: true,
	}

	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, pub, priv)
	if err != nil {
		return nil, nil, err
	}

	certBuf := new(bytes.Buffer)
	err = pem.Encode(certBuf, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	if err != nil {
		return nil, nil, err
	}

	keyBuf := new(bytes.Buffer)
	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, err
	}
	err = pem.Encode(keyBuf, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})
	if err != nil {
		return nil, nil, err
	}

	return certBuf.Bytes(), keyBuf.Bytes(), nil
}
