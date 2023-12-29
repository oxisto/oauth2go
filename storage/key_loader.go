package storage

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
)

type keyLoader struct {
	path         string
	password     string
	saveOnCreate bool
}

// LoadSigningKeys implements a singing keys func for our internal authorization
// server. Please note that [path] already needs to be an expanded path, e.g.,
// references to a home directory (~) already need to be expanded before-hand.
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
		key = l.recoverFromLoadKeyError(err)
	}

	return
}

// recoverFromLoadKeyError tries to recover from an error during key loading.
func (l *keyLoader) recoverFromLoadKeyError(err error) (key *ecdsa.PrivateKey) {
	// In any case, create a new temporary private key
	key, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	if errors.Is(err, os.ErrNotExist) && l.saveOnCreate {
		slog.Info("Private key does not exist at the location yet. We will create a new one")

		// Also make sure that the containing folder exists
		err = ensureFolderExistence(filepath.Dir(l.path))
		// Error while error handling, meh
		if err != nil {
			goto savingerr
		}

		// Also save the key in this case, so we can load it next time
		err = saveKeyToFile(key, l.path, l.password)

	savingerr:
		// Error while error handling, meh
		if err != nil {
			slog.Error("Error while saving the new private key", "err", err)
		}
	} else if err != nil {
		slog.Error("Could not load key from file, continuing with a temporary key", "err", err)
	}

	return key
}

// loadKeyFromFile loads an ecdsa.PrivateKey from a path. The key must in PEM
// format and protected by a password using PKCS#8 with PBES2.
//
// Note: This only supports ECDSA keys (for now) since we only support ECDSA
// keys in the authorization server (a limitation in the JWKS implementation).
// However, the underyling functions such as [ParsePKCS8PrivateKeyWithPassword]
// support all kind of private keys, so we might also support all private keys
// in the future here.
func loadKeyFromFile(path string, password []byte) (key *ecdsa.PrivateKey, err error) {
	var (
		k  crypto.PrivateKey
		ok bool
	)

	// Check, if we already have a persisted private key
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("error while reading key: %w", err)
	}

	k, err = ParsePKCS8PrivateKeyWithPassword(data, password)
	if err != nil {
		return nil, fmt.Errorf("error while parsing private key: %w", err)
	}

	key, ok = k.(*ecdsa.PrivateKey)
	if !ok {
		return nil, ErrNotECPrivateKey
	}

	return key, nil
}

// saveKeyToFile saves an [crypto.PrivateKey] to a path. The key will be saved
// in PEM format and protected by a password using PKCS#8 with PBES2.
func saveKeyToFile(key crypto.PrivateKey, path string, password string) (err error) {
	data, err := MarshalPKCS8PrivateKeyWithPassword(key, []byte(password))
	if err != nil {
		return fmt.Errorf("error while marshalling private key: %w", err)
	}

	err = os.WriteFile(path, data, 0600)
	if err != nil {
		return fmt.Errorf("error while writing file content: %w", err)
	}

	return nil
}

// ensureConfigesFolderExistence ensures that the config folder exists.
func ensureFolderExistence(path string) (err error) {
	// Create the directory, if it not exists
	_, err = os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		err = os.Mkdir(path, os.ModePerm)
		if err != nil {
			return err
		}
	}

	return
}
