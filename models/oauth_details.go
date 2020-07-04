package models

type GoogleUserDetails struct {
	ID            string `json:"sub"`
	Name          string `json:"name"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
}

type GithubUserDetails struct {
	ID    string `json:"node_id"`
	Name  string `json:"name"`
	Email string `json:"email"`
}

type OAuthUserDetails interface {
	GetEmail() string
	GetID() string
	GetUserName() string
	GetAuthProvider() string
}

func (gud GoogleUserDetails) GetEmail() string {
	return gud.Email
}
func (gud GoogleUserDetails) GetID() string {
	return gud.ID
}
func (gud GoogleUserDetails) GetAuthProvider() string {
	return GOOGLE
}
func (gud GoogleUserDetails) GetUserName() string {
	return gud.Name
}

func (gud GithubUserDetails) GetEmail() string {
	return gud.Email
}
func (gud GithubUserDetails) GetID() string {
	return gud.ID
}
func (gud GithubUserDetails) GetAuthProvider() string {
	return GITHUB
}
func (gud GithubUserDetails) GetUserName() string {
	return gud.Name
}
