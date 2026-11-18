package bootstrap

import (
	"bytes"
	"context"
	"fmt"
	"github.com/Arap919/xkeen-installer/internal/catalog"
	"io"
	"os"
	"regexp"
	"strings"
)

const credentialName = ".xkeen-bootstrap-credential"

var credentialHash = regexp.MustCompile(`^\$6\$rounds=100000\$[./0-9A-Za-z]{16}\$[./0-9A-Za-z]{86}$`)
var credentialID = regexp.MustCompile(`^[a-f0-9]{32}$`)
var credentialUUID = regexp.MustCompile(`^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$`)
var credentialDigest = regexp.MustCompile(`^[a-f0-9]{64}$`)

func validCredentialPayload(data []byte) bool {
	if len(data) > 512 {
		return false
	}
	parts := strings.Split(string(data), "\n")
	return len(parts) == 7 && parts[0] == "XKEEN-BOOTSTRAP-V1" && credentialID.MatchString(parts[1]) &&
		credentialUUID.MatchString(parts[2]) && (parts[3] == "arm64" || parts[3] == "mips" || parts[3] == "mipsel") &&
		credentialDigest.MatchString(parts[4]) && credentialHash.MatchString(parts[5]) && parts[6] == ""
}
func (s *smbStore) PublishCredential(ctx context.Context, v Volume, a catalog.Artifact, data []byte) error {
	if !validCredentialPayload(data) {
		return errSMB
	}
	return s.operation(ctx, v, a, func(d bootstrapDisk) error { return publishCredentialDisk(d, data) })
}
func (s *smbStore) CheckCredential(ctx context.Context, v Volume, a catalog.Artifact, data []byte) error {
	return s.operation(ctx, v, a, func(d bootstrapDisk) error { return checkCredentialDisk(d, data) })
}
func checkCredentialDisk(d bootstrapDisk, data []byte) error {
	if !validCredentialPayload(data) {
		return errSMB
	}
	st, err := d.Lstat(credentialName)
	if err != nil || !st.Mode().IsRegular() || st.Size() != int64(len(data)) {
		return errSMB
	}
	f, err := d.OpenFile(credentialName, os.O_RDONLY, 0)
	if err != nil {
		return errSMB
	}
	defer f.Close()
	st, err = f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Size() != int64(len(data)) {
		return errSMB
	}
	got, err := io.ReadAll(io.LimitReader(f, 513))
	defer clear(got)
	if err != nil || !bytes.Equal(data, got) {
		return errSMB
	}
	return nil
}
func publishCredentialDisk(d bootstrapDisk, data []byte) error {
	if !validCredentialPayload(data) {
		return errSMB
	}
	if _, err := d.Lstat(credentialName); !os.IsNotExist(err) {
		return errSMB
	}
	// Exclusive creation prevents overwriting a foreign or partially published credential.
	temp := credentialName + ".tmp"
	if _, err := d.Lstat(temp); !os.IsNotExist(err) {
		return errSMB
	}
	f, err := d.OpenFile(temp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return errSMB
	}
	defer d.Remove(temp)
	if n, e := f.Write(data); e != nil || n != len(data) {
		f.Close()
		return errSMB
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return errSMB
	}
	if err = f.Close(); err != nil {
		return errSMB
	}
	if err = d.RenameNoReplace(temp, credentialName); err != nil {
		return errSMB
	}
	return checkCredentialDisk(d, data)
}
func makeCredential(id string, v Volume, a catalog.Artifact, hash string) ([]byte, error) {
	data := []byte(fmt.Sprintf("XKEEN-BOOTSTRAP-V1\n%s\n%s\n%s\n%s\n%s\n", id, v.UUID, a.Arch, a.Integrity.SHA256, hash))
	if !validCredentialPayload(data) {
		clear(data)
		return nil, ErrUnsafe
	}
	return data, nil
}
