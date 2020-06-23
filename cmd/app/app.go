package app

import (
	"context"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

func NewRootCmd(ctx context.Context) *cobra.Command {
	o := new(rootOptions)

	cmd := &cobra.Command{
		Use:   "knet-stress",
		Short: "Simple client-server used to test inter pod connectivity. Can use TLS.",
	}

	nfs := pflag.NewFlagSet("knet-stress", pflag.ExitOnError)
	o.AddFlags(nfs)
	cmd.PersistentFlags().AddFlagSet(nfs)

	cmd.AddCommand(NewStatusCmd(ctx, o))
	cmd.AddCommand(NewServerCmd(ctx, o))

	return cmd
}
