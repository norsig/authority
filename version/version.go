package version

import (
	"fmt"
)

const (
	Version           = "0.2.5"
	VersionPrerelease = "dev"
)

var (
	GitCommit string
)

func GetVersion() string {
	return fmt.Sprintf("authority v%s%s-%s", Version, VersionPrerelease, GitCommit)
}
