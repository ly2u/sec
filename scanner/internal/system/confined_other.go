//go:build !linux

package system

import (
	"errors"
	"os"
)

type confined struct{}

func openConfined(string) (*confined, error)    { return nil, errors.New("仅支持 Linux") }
func (*confined) open(string) (*os.File, error) { return nil, errors.New("仅支持 Linux") }
func (*confined) close()                        {}
