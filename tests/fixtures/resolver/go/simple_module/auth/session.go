package auth

type Session struct {
	Token  string
	UserID int
}

func NewSession(token string) *Session {
	return &Session{Token: token}
}
