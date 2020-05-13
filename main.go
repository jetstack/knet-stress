package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

var options struct {
	caPath, certPath, keyPath string

	endpointNamespace, endpointName string
	connRate                        time.Duration
	podCount                        int
	serverPort, servingPort         int
	servingAddress                  string

	instanceID string

	status bool
}

var r *rand.Rand

func init() {
	flag.StringVar(&options.caPath, "ca", "", "Filepath to tls CA")
	flag.StringVar(&options.certPath, "cert", "", "Filepath to tls certificate")
	flag.StringVar(&options.keyPath, "key", "", "Filepath to tls private key")
	flag.DurationVar(&options.connRate, "connection-rate", time.Second/2, "A golang duration time string to attempt a connection over the computed DNS")

	flag.StringVar(&options.endpointName, "endpoint-name", "knet-stress", "The endpoint name to get IP addresses.")
	flag.StringVar(&options.endpointNamespace, "endpoint-namespace", "knet-stress", "The endpoint namespace to get IP addresses.")

	flag.StringVar(&options.servingAddress, "serving-address", "0.0.0.0", "Address to serve traffic on.")
	flag.IntVar(&options.servingPort, "serving-port", 6443, "Port to serve traffic on.")

	flag.IntVar(&options.serverPort, "server-port", 6443, "Port to connect to the server.")

	flag.StringVar(&options.instanceID, "instance-id", "worker-0", "Instance ID to identify this instance in metrics.")

	flag.BoolVar(&options.status, "status", false, "Run single roundtrip ping.")

	r = rand.New(rand.NewSource(time.Now().Unix()))
}

func main() {
	flag.Parse()

	if id := os.Getenv("KNET_STRESS_INSTANCE_ID"); options.instanceID == "worker-0" && len(id) > 0 {
		options.instanceID = id
	}

	var enableTLS bool

	if len(options.caPath) == 0 ||
		len(options.certPath) == 0 ||
		len(options.keyPath) == 0 {

		log.Infof("TLS disabled")

	} else {
		log.Infof("using TLS bundle using files [%s %s %s]",
			options.caPath, options.certPath, options.keyPath)

		enableTLS = true
	}

	if !options.status {
		go listenAndServe(enableTLS)
	}

	if err := runClient(enableTLS, options.connRate); err != nil {
		log.Fatal(err.Error())
	}
}

func runClient(enableTLS bool, tickRate time.Duration) error {
	ticker := time.NewTicker(tickRate)

	client := &http.Client{Transport: http.DefaultTransport, Timeout: time.Second * 10}

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

	restConfig, err := rest.InClusterConfig()
	if err != nil {
		log.Fatalf("failed to get in cluster client config: %s", err)
	}

	kubeclient, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		log.Fatalf("failed to build in cluster kube client: %s", err)
	}

	for {

		if err := doRoundTrip(kubeclient, client, enableTLS); err != nil {
			log.Error(err)

			if options.status {
				os.Exit(1)
			}
		}

		if options.status {
			fmt.Fprint(os.Stdout, "STATUS OK\n")
			os.Exit(0)
		}

		<-ticker.C
	}
}

func doRoundTrip(kubeclient *kubernetes.Clientset, client *http.Client, enableTLS bool) error {
	log.Infof("looking up endpoint: %s/%s", options.endpointName, options.endpointNamespace)

	const timeout = 5 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	endpoint, err := kubeclient.CoreV1().Endpoints(options.endpointNamespace).Get(ctx, options.endpointName, metav1.GetOptions{})
	if err != nil {
		statusError, ok := err.(*apierrors.StatusError)
		if !ok {
			apiSentRequestsMetrics.WithLabelValues(options.instanceID, "0").Inc()
		} else {
			apiSentRequestsMetrics.WithLabelValues(options.instanceID, strconv.FormatInt(int64(statusError.Status().Code), 10)).Inc()
		}

		return fmt.Errorf("failed to find endpoint %s/%s: %s",
			options.endpointNamespace, options.endpointName, err)
	}

	apiSentRequestsMetrics.WithLabelValues(options.instanceID, "200").Inc()

	ips := addrsFromEndpoint(endpoint)

	for _, ip := range ips {
		addr := serverAddr(ip, enableTLS)

		if err := doRequest(client, addr); err != nil {
			return err
		}
	}

	return nil
}

func doRequest(client *http.Client, addr string) error {
	log.Infof("sending request %s", addr)

	req, err := http.NewRequest("GET", addr, strings.NewReader(""))
	if err != nil {
		log.Fatalf("failed to create request: %s", err)
	}

	start := time.Now()

	resp, err := client.Do(req)
	if err != nil {
		durationMetrics.WithLabelValues(options.instanceID, "0").Observe(time.Since(start).Seconds())
		return err
	}

	sentRequestMetrics.WithLabelValues(options.instanceID, strconv.Itoa(resp.StatusCode)).Inc()
	durationMetrics.WithLabelValues(options.instanceID, strconv.Itoa(resp.StatusCode)).Observe(time.Since(start).Seconds())
	log.Infof("got response status code: %d", resp.StatusCode)

	return nil
}

func addrsFromEndpoint(enp *corev1.Endpoints) []string {
	var ips []string
	for _, sub := range enp.Subsets {
		for _, addr := range sub.Addresses {
			ips = append(ips, addr.IP)
		}
	}

	return ips
}

func serverAddr(addr string, enableTLS bool) string {

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

	addr := fmt.Sprintf("%s:%d", options.servingAddress, options.servingPort)
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

	log.Infof("listening on :%d with TLS:%t",
		options.servingPort, enableTLS)

}
