package oauth2

type Client struct {
	ClientID string

	ClientSecret string

	RedirectURI string
}

// Public returns true if this client is a public client. We enforce
// certain additional security measures for public clients, for example PKCE.
func (c *Client) Public() bool {
	return c.ClientSecret == ""
}
