package app

import (
	"os"
	"time"

	"github.com/spf13/pflag"
)

type rootOptions struct {
	CAPath, CertPath, KeyPath string

	ServerPort int

	EndpointNamespace, EndpointName string
	DestinationAddress              string
	DestinationPort                 int

	InstanceID string
}

type serverOptions struct {
	ConnectionRate time.Duration
	ServingAddress string
	Response       string
}

func (o *rootOptions) AddFlags(fs *pflag.FlagSet) {
	fs.StringVar(&o.CAPath, "ca", "", "Filepath to tls CA")
	fs.StringVar(&o.CertPath, "cert", "", "Filepath to tls certificate")
	fs.StringVar(&o.KeyPath, "key", "", "Filepath to tls private key")

	fs.StringVar(&o.EndpointName, "endpoint-name", "knet-stress", "The endpoint name to get IP addresses.")
	fs.StringVar(&o.EndpointNamespace, "endpoint-namespace", "knet-stress", "The endpoint namespace to get IP addresses.")
	fs.StringVar(&o.DestinationAddress, "destination-address", "", "The destination to send traffic. Overrides endpoint options.")
	fs.IntVar(&o.DestinationPort, "destination-port", 6443, "Port to connect to the server.")

	fs.StringVar(&o.InstanceID, "instance-id", "", "Instance ID to identify this instance in metrics.")
}

func (o *serverOptions) AddFlags(fs *pflag.FlagSet) {
	fs.DurationVar(&o.ConnectionRate, "connection-rate", time.Second/2, "A golang duration time string to attempt a connection over the computed DNS")
	fs.StringVar(&o.ServingAddress, "serving-address", "0.0.0.0:6443", "Address to serve traffic on.")
	fs.StringVar(&o.Response, "serving-response", "", "Response to be made on the /hello endpoint. Empty will return the current Unix nanosecond time.")
}

func (o *rootOptions) Complete() {
	if id := os.Getenv("KNET_STRESS_INSTANCE_ID"); len(o.InstanceID) == 0 {
		o.InstanceID = id
	}
}
