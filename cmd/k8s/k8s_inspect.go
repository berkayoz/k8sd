package k8s

import (
	"time"

	cmdutil "github.com/canonical/k8sd/cmd/util"
	"github.com/canonical/k8sd/pkg/snap/util/inspect"
	"github.com/spf13/cobra"
)

func newInspectCmd(env cmdutil.ExecutionEnvironment) *cobra.Command {
	var opts struct {
		allNamespaces     bool
		numSnapLogEntries int
		timeout           time.Duration
		coreDumpDir       string
	}

	cmd := &cobra.Command{
		Use:   "inspect [output-file]",
		Short: "Generate inspection report",
		Long: `Generate an inspection report tarball containing diagnostics and relevant information from a Kubernetes node.

This command collects diagnostics from either a control-plane or worker node and compiles them into
a tarball report. The collected data includes service arguments, Kubernetes cluster info, SBOM, system
diagnostics, network diagnostics, and more. The command needs to be run with elevated permissions (sudo).

Arguments:
  output-file             (Optional) The full path and filename for the generated tarball.
                          If not provided, a default filename based on the current date
                          and time will be used.
  --all-namespaces        (Optional) Acquire detailed debugging information, including logs
                          from all Kubernetes namespaces.
  --num-snap-log-entries  (Optional) The maximum number of log entries to collect
                          from snap services. Default: 100000.
  --timeout               (Optional) The maximum time in seconds to wait for a command.
                          Default: 180s.
  --core-dump-dir         (Optional) Core dump location. Default: /var/crash.
`,
		Args:   cobra.MaximumNArgs(1),
		PreRun: chainPreRunHooks(hookRequireRoot(env)),
		Run: func(cmd *cobra.Command, args []string) {
			inspectOpts := inspect.InspectOpts{
				AllNamespaces:     opts.allNamespaces,
				NumSnapLogEntries: opts.numSnapLogEntries,
				Timeout:           opts.timeout,
				CoreDumpDir:       opts.coreDumpDir,
			}

			if len(args) > 0 {
				inspectOpts.OutputFile = args[0]
			}

			if err := inspect.Inspect(cmd.Context(), env.Snap, cmd.OutOrStdout(), inspectOpts); err != nil {
				cmd.PrintErrf("Error: Failed to generate inspection report.\n\nError: %v\n", err)
				env.Exit(1)
			}
		},
	}

	cmd.Flags().BoolVar(&opts.allNamespaces, "all-namespaces", false, "acquire detailed debugging information, including logs from all Kubernetes namespaces")
	cmd.Flags().IntVar(&opts.numSnapLogEntries, "num-snap-log-entries", 100000, "the maximum number of log entries to collect from snap services")
	cmd.Flags().DurationVar(&opts.timeout, "timeout", 180*time.Second, "the maximum time to wait for a command")
	cmd.Flags().StringVar(&opts.coreDumpDir, "core-dump-dir", "/var/crash", "core dump location")

	return cmd
}
