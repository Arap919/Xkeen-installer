// Package router provides authenticated transport and read-only discovery before installation.
package router

import (
	"context"
	"errors"
	"io/fs"
	"path"
	"strings"
)

type Result struct {
	Stdout   []byte `json:"-"`
	Stderr   []byte `json:"-"`
	ExitCode int
}
type Entry struct {
	Path string
	Mode fs.FileMode
	Size int64
}
type Transport interface {
	Run(context.Context, string) (Result, error)
	Read(context.Context, string) ([]byte, error)
	WriteAtomic(context.Context, string, []byte, fs.FileMode) error
	Stat(context.Context, string) (Entry, error) // Lstat: never follows the final symlink.
	ReadDir(context.Context, string) ([]Entry, error)
	MkdirAll(context.Context, string, fs.FileMode) error
	AvailableBytes(context.Context, string) (uint64, error)
}

var ErrUnsafePath = errors.New("unsafe remote path")

func safePath(p string) error {
	if !strings.HasPrefix(p, "/opt/") || path.Clean(p) != p || strings.ContainsAny(p, "\x00\r\n") {
		return ErrUnsafePath
	}
	return nil
}
