package login

import "golang.org/x/crypto/bcrypt"

// PasswordHasher is an interface that can be used to support different password hashing
// algorithms in our login server. Basically, two functions need to be implemented, one for
// creating a hash out of a password and one for comparing a hash with a password.
type PasswordHasher interface {
	// CompareHashAndPassword compares a hash and a password. If successful, no error is returned.
	CompareHashAndPassword(hash []byte, password []byte) (err error)

	// GenerateFromPassword generates a hash out of a password. opts can be used to supply
	// implementation specific parameters.
	GenerateFromPassword(password []byte, opts ...interface{}) (hash []byte, err error)
}

// bcryptHasher is an implementation of PasswordHasher using the x/crypto/bcrypt package.
type bcryptHasher struct{}

// CompareHashAndPassword is an implementation of PasswordHasher using bcrypt.
func (bcryptHasher) CompareHashAndPassword(hash []byte, password []byte) (err error) {
	return bcrypt.CompareHashAndPassword(hash, password)
}

// GenerateFromPassword is an implementation of PasswordHasher using bcrypt. If a single
// variadic option is supplied as integer, it is taken as the cost parameter.
func (bcryptHasher) GenerateFromPassword(password []byte, opts ...interface{}) (hash []byte, err error) {
	var (
		cost = bcrypt.DefaultCost
		ok   bool
	)

	if len(opts) == 1 {
		if _, ok = opts[0].(int); ok {
			cost = opts[0].(int)
		}
	}

	return bcrypt.GenerateFromPassword(password, cost)
}
