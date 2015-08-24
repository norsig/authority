package authority

import (
	"errors"
)

var (
	ErrCertNotFound      = errors.New("authority: certificate not found")
	ErrCertAlreadyExists = errors.New("authority: certificate already exists")
	ErrConfigMissing     = errors.New("authority: cannot open configuraiton, or it does not exist")
)
