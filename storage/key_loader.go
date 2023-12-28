package storage

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/user"
	"path/filepath"
	"strings"
)

const (
	// DefaultPrivateKeySaveOnCreate specifies whether a created private key
	// will be saved. This is useful to turn off in unit tests, where we only
	// want a temporary key.
	DefaultPrivateKeySaveOnCreate = true

	// DefaultPrivateKeyPassword is the default password to protect the private
	// key.
	DefaultPrivateKeyPassword = "changeme"

	// DefaultPrivateKeyPath is the default path for the private key.
	DefaultPrivateKeyPath = DefaultConfigDirectory + "/private.key"

	// DefaultConfigDirectory is the default path for the oauth2go
	// configuration, such as keys.
	DefaultConfigDirectory = "~/.oauth2go"
)

type keyLoader struct {
	path         string
	password     string
	saveOnCreate bool
}

// LoadSigningKeys implements a singing keys func for our internal authorization server
func LoadSigningKeys(path string, password string, saveOnCreate bool) map[int]*ecdsa.PrivateKey {
	// create a key loader with our arguments
	loader := keyLoader{
		path:         path,
		password:     password,
		saveOnCreate: saveOnCreate,
	}

	return map[int]*ecdsa.PrivateKey{
		0: loader.LoadKey(),
	}
}

func (l *keyLoader) LoadKey() (key *ecdsa.PrivateKey) {
	var (
		err error
	)

	// Try to load the key from the given path
	key, err = loadKeyFromFile(l.path, []byte(l.password))
	if err != nil {
		key = l.recoverFromLoadApiKeyError(err, l.path == DefaultPrivateKeyPath)
	}

	return
}

// recoverFromLoadApiKeyError tries to recover from an error during key loading.
// We treat different errors differently. For example if the path is the default
// path and the error is [os.ErrNotExist], this could be just the first start of
// Clouditor. So we only treat this as an information that we will create a new
// key, which we will save, based on the config.
//
// If the user specifies a custom path and this one does not exist, we will
// report an error here.
func (l *keyLoader) recoverFromLoadApiKeyError(err error, defaultPath bool) (key *ecdsa.PrivateKey) {
	// In any case, create a new temporary API key
	key, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	if defaultPath && errors.Is(err, os.ErrNotExist) {
		slog.Info("API key does not exist at the default location yet. We will create a new one")

		if l.saveOnCreate {
			// Also make sure that default config path exists
			err = ensureConfigFolderExistence()
			// Error while error handling, meh
			if err != nil {
				return
			}

			// Also save the key in this case, so we can load it next time
			err = saveKeyToFile(key, l.path, l.password)

			// Error while error handling, meh
			if err != nil {
				slog.Error("Error while saving the new API key", "err", err)
			}
		}
	} else if err != nil {
		slog.Error("Could not load key from file, continuing with a temporary key", "err", err)
	}

	return key
}

// loadKeyFromFile loads an ecdsa.PrivateKey from a path. The key must in PEM format and protected by
// a password using PKCS#8 with PBES2.
func loadKeyFromFile(path string, password []byte) (key *ecdsa.PrivateKey, err error) {
	var (
		keyFile string
	)

	keyFile, err = expandPath(path)
	if err != nil {
		return nil, fmt.Errorf("error while expanding path: %w", err)
	}

	if _, err = os.Stat(keyFile); os.IsNotExist(err) {
		return nil, fmt.Errorf("file does not exist (yet): %w", err)
	}

	// Check, if we already have a persisted API key
	data, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("error while reading key: %w", err)
	}

	key, err = ParseECPrivateKeyFromPEMWithPassword(data, password)
	if err != nil {
		return nil, fmt.Errorf("error while parsing private key: %w", err)
	}

	return key, nil
}

// saveKeyToFile saves an ecdsa.PrivateKey to a path. The key will be saved in
// PEM format and protected by a password using PKCS#8 with PBES2.
func saveKeyToFile(apiKey *ecdsa.PrivateKey, keyPath string, password string) (err error) {
	keyPath, err = expandPath(keyPath)
	if err != nil {
		return fmt.Errorf("error while expanding path: %w", err)
	}

	// Check, if we already have a persisted API key
	f, err := os.OpenFile(keyPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("error while opening the file: %w", err)
	}
	defer func() {
		_ = f.Close()
	}()

	data, err := MarshalECPrivateKeyWithPassword(apiKey, []byte(password))
	if err != nil {
		return fmt.Errorf("error while marshalling private key: %w", err)
	}

	_, err = f.Write(data)
	if err != nil {
		return fmt.Errorf("error while writing file content: %w", err)
	}

	return nil
}

// expandPath expands a path that possible contains a tilde (~) character into
// the home directory of the user
func expandPath(path string) (out string, err error) {
	var (
		u *user.User
	)

	// Fetch the current user home directory
	u, err = user.Current()
	if err != nil {
		return path, fmt.Errorf("could not find retrieve current user: %w", err)
	}

	if path == "~" {
		return u.HomeDir, nil
	} else if strings.HasPrefix(path, "~") {
		// We only allow ~ at the beginning of the path
		return filepath.Join(u.HomeDir, path[2:]), nil
	}

	return path, nil
}

// ensureConfigesFolderExistence ensures that the config folder exists.
func ensureConfigFolderExistence() (err error) {
	var configPath string

	// Expand the config directory, if it contains any ~ characters.
	configPath, err = expandPath(DefaultConfigDirectory)
	if err != nil {
		// Directly return the error here, no need for additional wrapping
		return err
	}

	// Create the directory, if it not exists
	_, err = os.Stat(configPath)
	if errors.Is(err, os.ErrNotExist) {
		err = os.Mkdir(configPath, os.ModePerm)
		if err != nil {
			// Directly return the error here, no need for additional wrapping
			return err
		}
	}

	return
}
