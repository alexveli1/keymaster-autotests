package main

import (
	"testing"

	"github.com/stretchr/testify/suite"
)

func TestKeyMaster(t *testing.T) {
	suite.Run(t, new(KeyMasterSuite))
}
