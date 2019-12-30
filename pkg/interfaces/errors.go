package interfaces

import (
	"errors"
)

var errUnimplemented = errors.New("unimplemented on this platform")

var errDriverNotFound = errors.New("driver not found")
