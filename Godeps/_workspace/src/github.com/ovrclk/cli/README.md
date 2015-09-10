# cli

CLI package for ovrclk's tools

## Usage 

See examples under [/examples](examples) for details

```go
root := &cobra.Command{
  Short: "Utility to manage your clusters and applications on ovrclk",
  Use:   "ovrclk COMMAND [<args>..] [options]",
  Run: func(cmd *cobra.Command, args []string) {
    cmd.Help()
  },
}

cli := cli.New(root)

apps := &cobra.Command{
  Use:   "apps",
  Short: "List apps",
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Printf("inside apps with Args: %v\n", args)
  },
}

cli.AddCommand(apps).
  AddTopic("apps", "create, deploy and manage applications", true)

appsCreate := &cobra.Command{
  Use:   "apps:create",
  Short: "Create an app",
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Printf("inside apps:create with Args: %v\n", args)
  },
}
cli.AddCommand(appsCreate)

clusters := &cobra.Command{
  Use:   "clusters",
  Short: "Manage clusters",
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Printf("inside clusters with Args: %v\n", args)
  },
}
cli.AddCommand(clusters).
  AddTopic("clusters", "create, teardown and manage clusters", false)

clusterLaunch := &cobra.Command{
  Use:   "clusters:launch",
  Short: "Launch a cluster",
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Printf("inside clusters:launch with Args: %v\n", args)
  },
}
cli.AddCommand(clusterLaunch)

// Global flags
var host string
cli.Flags().StringVarP(&host, "server", "s", "", "The address and port of the ovrclk API server")

cli.Execute()
```
