package app

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/jetstack/knet-stress/pkg/client"
	"github.com/jetstack/knet-stress/pkg/metrics"
)

func NewStatusCmd(ctx context.Context, options *rootOptions) *cobra.Command {
	must := func(err error) {
		if err != nil {
			fmt.Fprintf(os.Stderr, err.Error()+"\n")
			os.Exit(1)
		}
	}

	cmd := &cobra.Command{
		Use:   "status",
		Short: "Run a single status round trip ping to knet-stress servers",
		RunE: func(cmd *cobra.Command, args []string) error {
			options.Complete()
			useKube := len(options.DestinationAddress) == 0

			client, err := client.New(metrics.New(options.InstanceID), useKube, options.KeyPath, options.CertPath, options.CAPath)
			if err != nil {
				return err
			}

			defer fmt.Fprintf(os.Stdout, "STATUS OK\n")

			if useKube {
				must(client.EndpointRequest(ctx, options.EndpointNamespace, options.EndpointName, options.DestinationPort))
				return nil
			}

			must(client.Request(ctx, options.DestinationAddress, options.DestinationPort))

			return nil
		},
	}

	return cmd
}
