package cli

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"text/template"

	"github.com/spf13/cobra"
)

// UsageFunc provides usage information for topics and commands
func (cli *CLI) UsageFunc(c *cobra.Command) error {
	var ct *Topic
	for _, topic := range cli.Topics {
		if topic.Name == c.Name() {
			ct = topic
			// Search for subcomands for the topic.
			// apps should have apps:create, apps:destroy
			ct.Commands = make([]*cobra.Command, 0)
			for _, cmd := range c.Parent().Commands() {
				// Conditions for inclusion:
				// 1. Include if the command's name beings the topic name.
				//    Any commands that begin with auth:* will be part of the the auth topic
				// 2. The command's name is not topics'name. Do not include auth command under auth topic
				// 3. Is not a help command
				if strings.HasPrefix(cmd.Name(), ct.Name) && cmd.Name() != ct.Name && cmd.Name() != "help" {
					ct.Commands = append(ct.Commands, cmd)
				}
			}
		}
	}

	// Show help topics for root command
	if c.Name() == cli.Root().Name() {
		sort.Sort(ByName{cli.Topics})
		return tmpl(c.Out(), rootTemplate, cli)
	}

	// Print the regular help
	if err := tmpl(c.Out(), usageTemplate, c); err != nil {
		return err
	}

	// Print the topic help
	if ct != nil {
		return tmpl(c.Out(), topicTemplate, ct)
	}
	return nil
}

// rpad adds padding to the right of a string
func rpad(s string, padding int) string {
	template := fmt.Sprintf("%%-%ds", padding)
	return fmt.Sprintf(template, s)
}

// tmpl executes the given template text on data, writing the result to w.
func tmpl(w io.Writer, text string, data interface{}) error {
	t := template.New("top")
	t.Funcs(template.FuncMap{
		"trim": strings.TrimSpace,
		"rpad": rpad,
		"gt":   cobra.Gt,
		"eq":   cobra.Eq,
	})
	template.Must(t.Parse(text))
	return t.Execute(w, data)
}

const rootTemplate = `{{$pad := .Topics.TopicNamePadding}}
Usage: {{.Root.Use}}

Primary help topics, type "{{.Name}} help TOPIC" for more details:

  {{range .Topics}}{{if .Primary}}{{rpad .Name $pad}} {{.Desc}}
  {{end}}{{end}}
Additional topics:

  {{range .Topics}}{{if not .Primary}}{{rpad .Name $pad}} {{.Desc}}
  {{end}}{{end}}
`

const topicTemplate = `{{$pad := .NamePadding}}
Additional commands, type "ovrclk COMMAND --help" for more details:
{{range .Commands}}
  {{rpad .Use $pad}} {{.Short}}{{end}}
`

const usageTemplate = `{{ $cmd := . }}
Usage: {{if .Runnable}}{{.UseLine}}{{if .HasSubCommands}} COMMAND{{end}}{{if .HasFlags}} [options]{{end}}{{end}}{{if gt .Aliases 0}}

Aliases:

  {{.NameAndAliases}}{{end}}{{if .HasExample}}

Examples:

{{ .Example }}{{end}}{{ if .HasNonHelpSubCommands}}

Commands: 
{{range .Commands}}{{if (not .IsHelpCommand)}}
  {{rpad .Name .NamePadding }} {{.Short}}{{end}}{{end}}{{end}}{{ if .HasLocalFlags}}

Options:

{{.LocalFlags.FlagUsages}}{{end}}{{ if .HasInheritedFlags}}
General Options:

{{.InheritedFlags.FlagUsages}}{{end}}{{if .HasHelpSubCommands}}
Additional help topics: {{range .Commands}}{{if .IsHelpCommand}}
  {{rpad .CommandPath .CommandPathPadding}} {{.Short}}{{end}}}{{end}}{{end}}{{ if .HasSubCommands }}
Use "{{.CommandPath}} COMMAND --help" for more information about a command.
{{end}}`
