package login

import "golang.org/x/crypto/bcrypt"

// PasswordHasher is an interface that can be used to support different password hashing
// algorithms in our login server. Basically, two functions need to be implemented, one for
// creating a hash out of a password and one for comparing a hash with a password.
type PasswordHasher interface {
	// CompareHashAndPassword compares a hash and a password. If successful, no error is returned.
	CompareHashAndPassword(hash string, password string) (err error)

	// GenerateFromPassword generates a hash out of a password. opts can be used to supply
	// implementation specific parameters.
	GenerateFromPassword(password string, opts ...interface{}) (hash string, err error)
}

// bcryptHasher is an implementation of PasswordHasher using the x/crypto/bcrypt package.
type bcryptHasher struct{}

// CompareHashAndPassword is an implementation of PasswordHasher using bcrypt.
func (bcryptHasher) CompareHashAndPassword(hash string, password string) (err error) {
	return bcrypt.CompareHashAndPassword([]byte(hash), ([]byte(password)))
}

// GenerateFromPassword is an implementation of PasswordHasher using bcrypt. If a single
// variadic option is supplied as integer, it is taken as the cost parameter.
func (bcryptHasher) GenerateFromPassword(password string, opts ...interface{}) (hash string, err error) {
	var cost = bcrypt.DefaultCost
	var ok bool
	var b []byte

	if len(opts) == 1 {
		if _, ok = opts[0].(int); ok {
			cost = opts[0].(int)
		}
	}

	b, err = bcrypt.GenerateFromPassword([]byte(password), cost)
	if err != nil {
		return "", err
	}

	return string(b), nil
}
