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
	metrics *metrics.Metrics
}

type Options struct {
	KeyPath, CertPath, CAPath string

	ServingAddress string
	Response       []byte // if len == 0, return time.Now().UnixNano()
}

func New(metrics *metrics.Metrics, opts *Options) (*Server, error) {
	s := &Server{
		metrics: metrics,
	}

	httpServer, err := s.BuildHTTPServer(opts)
	if err != nil {
		return nil, err
	}
	s.Server = httpServer

	return s, nil
}

func (s *Server) BuildHTTPServer(opts *Options) (*http.Server, error) {
	var (
		tlsConfig *tls.Config
		err       error
	)

	if len(opts.KeyPath) > 0 || len(opts.CertPath) > 0 || len(opts.CAPath) > 0 {
		log.Infof("server: using TLS bundle using files [%s %s %s]",
			opts.CAPath, opts.CertPath, opts.KeyPath)

		tlsConfig, err = s.buildTLSConfig(opts)
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
		s.metrics.ReceivedRequestInc()

		if len(opts.Response) > 0 {
			fmt.Fprintf(w, "%s", opts.Response)
		} else {
			fmt.Fprintf(w, "%d", time.Now().UnixNano())
		}
	})

	return &http.Server{
		Addr:      opts.ServingAddress,
		TLSConfig: tlsConfig,
		Handler:   handler,
	}, nil
}

func (s *Server) Listen(ctx context.Context, stopCh chan<- struct{}) {
	go func() {
		<-ctx.Done()

		if err := s.Shutdown(ctx); err != nil {
			log.Errorf("server: failed to shutdown server: %s", err)
		}

		stopCh <- struct{}{}
	}()

	if err := s.ListenAndServe(); err != nil {
		log.Errorf("server: failed to listen on %s: %s", s.Addr, err)
	}
}

func (s *Server) buildTLSConfig(opts *Options) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(opts.CertPath, opts.KeyPath)
	if err != nil {
		return nil, err
	}

	ca, err := ioutil.ReadFile(opts.CAPath)
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
