package service

func isValidLoginRequest(l Login) bool {
	if l.EmailAddress == "" || l.Password == "" {
		return false
	}

	return true
}
