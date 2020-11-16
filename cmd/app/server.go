package app

import (
	"context"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/jetstack/knet-stress/pkg/client"
	"github.com/jetstack/knet-stress/pkg/metrics"
	"github.com/jetstack/knet-stress/pkg/server"
)

func NewServerCmd(ctx context.Context, options *rootOptions) *cobra.Command {
	serverOptions := new(serverOptions)

	cmd := &cobra.Command{
		Use:   "server",
		Short: "Run the knet-stress server, and periodically round trip other servers.",
		RunE: func(cmd *cobra.Command, args []string) error {
			options.Complete()

			useKube := len(options.DestinationAddress) == 0
			metrics := metrics.New(options.InstanceID)

			client, err := client.New(metrics, useKube, options.KeyPath,
				options.CertPath, options.CAPath)
			if err != nil {
				return err
			}

			httpServerOptions := &server.Options{
				KeyPath:        options.KeyPath,
				CertPath:       options.CertPath,
				CAPath:         options.CAPath,
				ServingAddress: serverOptions.ServingAddress,
				Response:       []byte(serverOptions.Response),
			}

			server, err := server.New(metrics, httpServerOptions)
			if err != nil {
				return err
			}

			var roundTripFn func() error

			if len(options.DestinationAddress) > 0 {
				roundTripFn = func() error {
					return client.Request(ctx, options.DestinationAddress, options.DestinationPort)
				}
			} else {
				roundTripFn = func() error {
					return client.EndpointRequest(ctx, options.EndpointNamespace, options.EndpointName, options.DestinationPort)
				}
			}

			stopCh := make(chan struct{}, 2)

			go runClientRoundTrip(ctx, stopCh, roundTripFn, serverOptions.ConnectionRate)
			go server.Listen(ctx, stopCh)

			<-stopCh
			<-stopCh

			log.Info("knet-stress shutdown")

			return nil
		},
	}

	nfs := pflag.NewFlagSet("server", pflag.ExitOnError)
	serverOptions.AddFlags(nfs)
	cmd.Flags().AddFlagSet(nfs)

	return cmd
}

func runClientRoundTrip(ctx context.Context, stopCh chan struct{}, roundTripFn func() error, tickRate time.Duration) {
	ticker := time.NewTicker(tickRate)

	for {
		if err := roundTripFn(); err != nil {
			log.Errorf("client: %s", err)
		}

		select {
		case <-ticker.C:
		case <-ctx.Done():
			stopCh <- struct{}{}
		}
	}
}
