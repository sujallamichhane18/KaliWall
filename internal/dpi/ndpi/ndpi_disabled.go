//go:build !ndpi

package ndpi

import "errors"

// NewClassifier returns a disabled state when KaliWall is built without -tags ndpi.
func NewClassifier(cfg Config) (Classifier, error) {
	_ = cfg
	return nil, errors.New("advanced nDPI is unavailable: build with -tags ndpi")
}
