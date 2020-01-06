package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
)

var options struct {
	caPath, certPath, keyPath string

	dns, connRate           string
	podCount                int
	serverPort, servingPort int

	instanceID string
}

var r *rand.Rand

func init() {
	flag.StringVar(&options.caPath, "ca", "", "Filepath to tls CA")
	flag.StringVar(&options.certPath, "cert", "", "Filepath to tls certificate")
	flag.StringVar(&options.keyPath, "key", "", "Filepath to tls private key")
	flag.StringVar(&options.dns, "dns", "default.go-knet-stress-%d.cluster.local", "DNS name to send traffic to. If %d is present then will be replaced with a random number between 0 and pod-count - 1.")
	flag.StringVar(&options.connRate, "connection-rate", "0.5s", "A golang duration time string to attempt a connection over the computed DNS")
	flag.IntVar(&options.podCount, "pod-count", 1, "Number of pods to be used to randomise DNS over.")

	flag.IntVar(&options.servingPort, "serving-port", 6443, "Port to serve traffic on.")
	flag.IntVar(&options.serverPort, "server-port", 6443, "Port to connect to the server.")

	flag.StringVar(&options.instanceID, "instance-id", "worker-0", "Instance ID to identify this instance in metrics.")

	r = rand.New(rand.NewSource(time.Now().Unix()))
}

func main() {
	flag.Parse()

	connDuration, err := time.ParseDuration(options.connRate)
	if err != nil {
		log.Fatalf("failed to parse connection rate: %s", err)
	}

	var enableTLS bool

	if len(options.caPath) == 0 ||
		len(options.certPath) == 0 ||
		len(options.keyPath) == 0 {

		log.Infof("TLS disabled, serving and requesting traffic on 80")

	} else {
		log.Infof("using TLS bundle using files [%s %s %s]",
			options.caPath, options.certPath, options.keyPath)

		enableTLS = true
	}

	go listenAndServe(enableTLS)

	if err := runClient(enableTLS, connDuration); err != nil {
		log.Fatal(err.Error())
	}

	log.Infof("listening on :%d with TLS:%t",
		options.servingPort, enableTLS)

	select {}
}

func runClient(enableTLS bool, tickRate time.Duration) error {
	ticker := time.NewTicker(tickRate)

	client := &http.Client{Transport: http.DefaultTransport}

	if enableTLS {
		tlsTransport, err := tlsClientConfig()
		if err != nil {
			return err
		}

		client = &http.Client{
			Transport: tlsTransport,
			Timeout:   time.Second * 10,
		}
	}

	go func() {
		for {
			<-ticker.C

			addr := serverAddr(enableTLS)

			log.Infof("sending request %s", addr)

			sentRequestMetrics.WithLabelValues(options.instanceID).Inc()

			resp, err := client.Get(addr)
			if err != nil {
				log.Error(err.Error())
			}

			now := time.Now()

			if resp != nil && resp.Body != nil {
				defer resp.Body.Close()

				body, err := ioutil.ReadAll(resp.Body)
				if err != nil {
					log.Errorf("failed to ready response body: %s", err)
					continue
				}

				n, err := strconv.ParseInt(string(body), 10, 64)
				if err != nil {
					log.Errorf("failed to parse body nanosecods (%s): %s", body, err)
					continue
				}

				t := time.Unix(0, n)
				diff := now.Sub(t)

				latencyMetrics.WithLabelValues(options.instanceID).Observe(float64(diff.Nanoseconds()))
			}
		}
	}()

	return nil
}

func serverAddr(enableTLS bool) string {
	addr := options.dns

	if strings.Contains(options.dns, "%d") {
		n := r.Int() % options.podCount
		addr = fmt.Sprintf(addr, n)
	}

	if enableTLS {
		addr = fmt.Sprintf("https://%s:%d/hello", addr, options.serverPort)
	} else {
		addr = fmt.Sprintf("http://%s:%d/hello", addr, options.serverPort)
	}

	return addr
}

func tlsClientConfig() (*http.Transport, error) {
	cert, err := tls.LoadX509KeyPair(options.certPath, options.keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load client cert/key: %s", err)
	}

	ca, err := ioutil.ReadFile(options.caPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA file: %s", err)
	}

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(ca)

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caCertPool,
	}
	tlsConfig.BuildNameToCertificate()

	return &http.Transport{TLSClientConfig: tlsConfig}, nil
}

func listenAndServe(enableTLS bool) {

	// Serve Prometheus metrics
	http.Handle("/metrics", promhttp.Handler())

	http.HandleFunc("/hello", func(w http.ResponseWriter, r *http.Request) {
		log.Infof("received request from %s", r.RemoteAddr)
		receivedRequestMetrics.WithLabelValues(options.instanceID).Inc()

		fmt.Fprintf(w, "%d", time.Now().UnixNano())
	})

	addr := fmt.Sprintf(":%d", options.servingPort)
	if enableTLS {

		err := http.ListenAndServeTLS(addr, options.certPath, options.keyPath, nil)
		if err != nil {
			log.Fatalf("failed to listen on :%d :%s",
				options.servingPort, err)
		}

	} else {

		err := http.ListenAndServe(addr, nil)
		if err != nil {
			log.Fatalf("failed to listen on :%d :%s",
				options.servingPort, err)
		}
	}
}
