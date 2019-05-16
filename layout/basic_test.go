package layout

import (
	"testing"

	"github.com/appveen/go-log/levels"
	"github.com/stretchr/testify/assert"
)

func TestBasic(t *testing.T) {
	b := Basic()
	assert.NotNil(t, b)

	assert.Equal(t, b.Format(levels.DEBUG, "Test message"), "Test message")
	assert.Equal(t, b.Format(levels.DEBUG, "Test message %s", "test"), "Test message test")
}
