package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/http"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

var options struct {
	caPath, certPath, keyPath string

	dns, connRate           string
	podCount                int
	serverPort, servingPort int
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
	go runClient(enableTLS, connDuration)

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

		client = &http.Client{Transport: tlsTransport}
	}

	go func() {
		for {
			<-ticker.C

			resp, err := client.Get(serverAddr(enableTLS))
			if err != nil {
				log.Error(err.Error())
			}

			if resp != nil && resp.Body != nil {
				resp.Body.Close()
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
		addr = fmt.Sprintf("https://%s:%d", addr, options.serverPort)
	} else {
		addr = fmt.Sprintf("http://%s:%d", addr, options.serverPort)
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
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		log.Infof("received request from %s", r.RemoteAddr)

		fmt.Fprintf(w, "Hello World %s", time.Now())
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
