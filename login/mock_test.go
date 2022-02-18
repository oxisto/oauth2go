package login

import (
	"io"
	"io/fs"
	"time"
)

// mockFS is a mocked file system, used in tests that read from a file.
type mockFS struct {
	OpenError error

	File fs.File
}

func (e *mockFS) Open(name string) (fs.File, error) {
	if e.OpenError != nil {
		return nil, e.OpenError
	}

	return e.File, nil
}

type mockFile struct {
	content string

	finished bool
}

func (m *mockFile) Close() error { return nil }

func (m *mockFile) Read(b []byte) (int, error) {
	if m.finished {
		return 0, io.EOF
	}

	tmp := []byte(m.content)
	n := copy(b, tmp)

	m.finished = true

	return n, nil
}

func (m *mockFile) Stat() (fs.FileInfo, error) {
	return m, nil
}

func (m *mockFile) IsDir() bool {
	return false
}

func (m *mockFile) ModTime() time.Time {
	return time.Now()
}

func (m *mockFile) Mode() fs.FileMode {
	return 0600
}

func (m *mockFile) Name() string {
	return "Mock"
}

func (m *mockFile) Size() int64 {
	return int64(len(m.content))
}

func (m *mockFile) Sys() interface{} {
	return nil
}
