package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/jetstack/knet-stress/pkg/metrics"
)

type Client struct {
	*http.Client

	metrics    *metrics.Metrics
	kubeclient *kubernetes.Clientset
	httpScheme string
}

func New(metrics *metrics.Metrics, useKube bool, keyPath, certPath, caPath string) (*Client, error) {
	client := &Client{
		metrics: metrics,
	}

	if len(keyPath) > 0 || len(certPath) > 0 || len(caPath) > 0 {
		log.Infof("client: using TLS bundle using files [%s %s %s]",
			caPath, certPath, keyPath)

		transport, err := tlsClientConfig(keyPath, certPath, caPath)
		if err != nil {
			return nil, err
		}

		client.Client = &http.Client{
			Transport: transport,
			Timeout:   time.Second * 10,
		}

		client.httpScheme = "https"

	} else {
		log.Infof("client: TLS disabled")

		client.Client = &http.Client{
			Transport: http.DefaultTransport,
			Timeout:   time.Second * 10,
		}

		client.httpScheme = "http"
	}

	if useKube {
		restConfig, err := rest.InClusterConfig()
		if err != nil {
			return nil, fmt.Errorf("failed to get in cluster client config: %s", err)
		}

		kubeclient, err := kubernetes.NewForConfig(restConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to build in cluster kube client: %s", err)
		}

		client.kubeclient = kubeclient
	}

	return client, nil
}

func (c *Client) EndpointRequest(ctx context.Context, endpointNamespace, endpointName string, port int) error {
	ctx, cancel := context.WithTimeout(ctx, time.Second*10)
	defer cancel()

	ips, err := c.endpointIPs(ctx, endpointNamespace, endpointName)
	if err != nil {
		return err
	}

	for _, ip := range ips {
		if err := c.Request(ctx, ip, port); err != nil {
			return err
		}
	}

	return nil
}

func (c *Client) endpointIPs(ctx context.Context, endpointNamespace, endpointName string) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, time.Second*5)
	defer cancel()

	endpoint, err := c.kubeclient.CoreV1().Endpoints(endpointNamespace).Get(ctx, endpointName, metav1.GetOptions{})
	if err != nil {
		statusError, ok := err.(*apierrors.StatusError)
		if !ok {
			c.metrics.APISentInc(0)
		} else {
			c.metrics.APISentInc(statusError.Status().Code)
		}

		return nil, fmt.Errorf("failed to find endpoint %s/%s: %s", endpointNamespace, endpointName, err)
	}

	c.metrics.APISentInc(200)

	var ips []string
	for _, sub := range endpoint.Subsets {
		for _, addr := range sub.Addresses {
			ips = append(ips, addr.IP)
		}
	}

	return ips, nil
}

func (c *Client) Request(ctx context.Context, host string, port int) error {
	addr := fmt.Sprintf("%s://%s:%d/hello", c.httpScheme, host, port)

	log.Infof("client: sending request %s", addr)

	req, err := http.NewRequest("GET", addr, strings.NewReader(""))
	if err != nil {
		return fmt.Errorf("failed to create request: %s", err)
	}

	var (
		statusCode = 0
		start      = time.Now()
	)

	ctx, cancel := context.WithTimeout(ctx, time.Second*10)
	defer cancel()

	resp, err := c.Client.Do(req.WithContext(ctx))
	if resp != nil {
		statusCode = resp.StatusCode
		log.Infof("client: got response status code: %d", resp.StatusCode)
	}

	c.metrics.DurationObserve(statusCode, start)
	c.metrics.SentRequestInc(statusCode)

	return err
}

func tlsClientConfig(keyPath, certPath, caPath string) (*http.Transport, error) {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load client cert/key: %s", err)
	}

	ca, err := ioutil.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA file: %s", err)
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

	return &http.Transport{TLSClientConfig: tlsConfig}, nil
}
