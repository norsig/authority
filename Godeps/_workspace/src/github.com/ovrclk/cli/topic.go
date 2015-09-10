package cli

import (
	"github.com/spf13/cobra"
)

// Topic represents a command help topic
type Topic struct {
	// Name is the name of the topic
	Name string

	// Desc is the description of the topic
	Desc string

	// Primary indicates if the topic a primary topic
	Primary bool

	// Commands are commands associated with the topic
	Commands []*cobra.Command
}

type Topics []*Topic

func (t Topics) Len() int      { return len(t) }
func (t Topics) Swap(i, j int) { t[i], t[j] = t[j], t[i] }

// ByName implements sort.Interface by providing Less and using the Len and
// Swap methods of the embedded Topic value.
type ByName struct{ Topics }

func (t ByName) Less(i, j int) bool { return t.Topics[i].Name < t.Topics[j].Name }

// Returns the padding required for the name when rending topic usage
func (t *Topic) NamePadding() int {
	padding := 1
	if len(t.Commands) > 0 {
		for _, cmd := range t.Commands {
			if len(cmd.Use) > padding {
				padding = len(cmd.Use)
			}
		}
	}
	return padding
}

// Returns the padding required for the name when rendering main help
func (t Topics) TopicNamePadding() int {
	padding := 1
	for _, topic := range t {
		if len(topic.Name) > padding {
			padding = len(topic.Name)
		}
	}
	return padding
}
