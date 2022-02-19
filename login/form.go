package login

import (
	"html/template"
	"io/fs"
	"net/http"
)

// loginForm is a http.Handler that displays an HTML login form
type loginForm struct {
	// returnURL is an optional URL that specifies where our login server redirects
	// after a successfull login
	returnURL string

	// errorMessage is an optional error message to display in the login form
	errorMessage string

	// fs is the file system to retrieve the login html page from
	fs fs.FS
}

func (form loginForm) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var tmpl, err = template.ParseFS(form.fs, "login.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	err = tmpl.Execute(w, map[string]interface{}{
		"ErrorMessage": form.errorMessage,
		"ReturnURL":    form.returnURL,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}
