package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"

	"github.com/joshvanl/knet-stress/pkg/metrics"
)

type Server struct {
	*http.Server
}

func New(metrics *metrics.Metrics, address, keyPath, certPath, caPath string) (*Server, error) {
	var (
		tlsConfig *tls.Config
		err       error
	)

	if len(keyPath) > 0 || len(certPath) > 0 || len(caPath) > 0 {
		log.Infof("server: using TLS bundle using files [%s %s %s]",
			caPath, certPath, keyPath)

		tlsConfig, err = buildTLSConfig(keyPath, certPath, caPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load TLS configuration: %s", err)
		}

	} else {
		log.Infof("server: TLS disabled")
	}

	handler := http.NewServeMux()

	// Serve Prometheus metrics
	handler.Handle("/metrics", promhttp.Handler())

	handler.HandleFunc("/hello", func(w http.ResponseWriter, r *http.Request) {
		if r.TLS != nil {
			log.Infof("server: received request from %s [%s %s %s]",
				r.RemoteAddr, r.TLS.PeerCertificates[0].Issuer, r.TLS.PeerCertificates[0].DNSNames, r.TLS.PeerCertificates[0].Subject.String())
		} else {
			log.Infof("server: received request from %s", r.RemoteAddr)
		}
		metrics.ReceivedRequestInc()

		fmt.Fprintf(w, "%d", time.Now().UnixNano())
	})

	return &Server{
		Server: &http.Server{
			Addr:      address,
			TLSConfig: tlsConfig,
			Handler:   handler,
		},
	}, nil
}

func (s *Server) Listen(ctx context.Context, stopCh chan struct{}) {
	go func() {
		<-ctx.Done()

		if err := s.Shutdown(ctx); err != nil {
			log.Errorf("server: failed to shutdown server: %s", err)
		}

		stopCh <- struct{}{}
	}()

	if err := s.ListenAndServe(); err != nil {
		log.Errorf("server: failed to listen on %s: %s", s.Addr)
	}
}

func buildTLSConfig(keyPath, certPath, caPath string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, err
	}

	ca, err := ioutil.ReadFile(caPath)
	if err != nil {
		return nil, err
	}

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(ca)

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caCertPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    caCertPool,
	}
	tlsConfig.BuildNameToCertificate()

	return tlsConfig, nil
}
