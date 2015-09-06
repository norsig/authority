package cli

import (
	"flag"
	"reflect"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

type CLI struct {
	Topics

	root  *cobra.Command
	flags *pflag.FlagSet
}

func New(root *cobra.Command) *CLI {
	return &CLI{root: root}
}

func (c *CLI) AddTopic(name, desc string, primary bool) *CLI {
	c.Topics = append(c.Topics, &Topic{name, desc, primary, nil})
	return c
}

func (c *CLI) SetRoot(root *cobra.Command) *CLI {
	c.root = root
	return c
}

func (c *CLI) AddCommand(cmd *cobra.Command) *CLI {
	c.Root().AddCommand(cmd)
	return c
}

// Name returns the first part of the cmd.Use
func (c *CLI) Name() string {
	return strings.Split(c.Root().Use, " ")[0]
}

// Root returns the command associated with the cli
func (c *CLI) Root() *cobra.Command {
	if c.root == nil {
		c.root = &cobra.Command{}
	}
	return c.root
}

func (c *CLI) Flags() *pflag.FlagSet {
	if c.flags == nil {
		c.flags = pflag.NewFlagSet("", pflag.ContinueOnError)
	}
	return c.flags
}

// Bind binds the usage function and global flags to the command
func (c *CLI) Execute() error {
	return c.Bind().Root().Execute()
}

func (c *CLI) Bind() *CLI {
	c.Root().SetUsageTemplate(usageTemplate)
	c.Root().SetUsageFunc(c.UsageFunc)
	c.BindFlags(c.Root().PersistentFlags())
	return c
}

// BindFlags binds the flags to the cli
func (c *CLI) BindFlags(flags *pflag.FlagSet) {
	AddPFlagSetToPFlagSet(pflag.CommandLine, flags)
	AddPFlagSetToPFlagSet(c.flags, flags)
}

// AddPFlagSetToPFlagSet merges the flags of fsFrom into fsTo.
func AddPFlagSetToPFlagSet(fsFrom *pflag.FlagSet, fsTo *pflag.FlagSet) {
	if fsFrom != nil && fsTo != nil {
		fsFrom.VisitAll(func(f *pflag.Flag) {
			if fsTo.Lookup(f.Name) == nil {
				fsTo.AddFlag(f)
			}
		})
	}
}

// AddFlagSetToPFlagSet adds all of the flags in a 'flag.FlagSet' package flags to a 'pflag.FlagSet'.
func AddFlagSetToPFlagSet(fsIn *flag.FlagSet, fsOut *pflag.FlagSet) {
	fsIn.VisitAll(func(f *flag.Flag) {
		addFlagToPFlagSet(f, fsOut)
	})
}

// Imports a 'flag.Flag' into a 'pflag.FlagSet'.  The "short" option is unset
// and the type is inferred using reflection.
func addFlagToPFlagSet(f *flag.Flag, fs *pflag.FlagSet) {
	if fs.Lookup(f.Name) == nil {
		fs.Var(wrapFlagValue(f.Value), f.Name, f.Usage)
	}
}

// flagValueWrapper implements pflag.Value around a flag.Value.  The main
// difference here is the addition of the Type method that returns a string
// name of the type.  As this is generally unknown, we approximate that with
// reflection.
type flagValueWrapper struct {
	inner    flag.Value
	flagType string
}

func (v *flagValueWrapper) String() string {
	return v.inner.String()
}

func (v *flagValueWrapper) Set(s string) error {
	return v.inner.Set(s)
}

func (v *flagValueWrapper) Type() string {
	return v.flagType
}

type boolFlag interface {
	flag.Value
	IsBoolFlag() bool
}

func (v *flagValueWrapper) IsBoolFlag() bool {
	if bv, ok := v.inner.(boolFlag); ok {
		return bv.IsBoolFlag()
	}
	return false
}

func wrapFlagValue(v flag.Value) pflag.Value {
	// If the flag.Value happens to also be a pflag.Value, just use it directly.
	if pv, ok := v.(pflag.Value); ok {
		return pv
	}

	pv := &flagValueWrapper{
		inner: v,
	}

	t := reflect.TypeOf(v)
	if t.Kind() == reflect.Interface || t.Kind() == reflect.Ptr {
		t = t.Elem()
	}

	pv.flagType = t.Name()
	pv.flagType = strings.TrimSuffix(pv.flagType, "Value")
	return pv
}
