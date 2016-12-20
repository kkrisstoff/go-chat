package main

import (
	"flag"
	"html/template"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sync"

	"github.com/kkrisstoff/go-chat/trace"
	"github.com/stretchr/gomniauth"
	"github.com/stretchr/gomniauth/providers/facebook"
	"github.com/stretchr/gomniauth/providers/github"
	"github.com/stretchr/gomniauth/providers/google"
	"github.com/stretchr/objx"
)

// templ represents a single template
type templateHandler struct {
	once     sync.Once
	filename string
	templ    *template.Template
}

// ServeHTTP handles the HTTP request.
func (t *templateHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	t.once.Do(func() {
		t.templ = template.Must(template.ParseFiles(filepath.Join("templates", t.filename)))
	})
	data := map[string]interface{}{
		"Host": r.Host,
	}
	if authCookie, err := r.Cookie("auth"); err == nil {
		data["UserData"] = objx.MustFromBase64(authCookie.Value)
	}
	t.templ.Execute(w, data)
}

// use command-line flags to make host configurable
// and then use the injection capabilities of templates to make sure our JavaScript knows the right host
// To get the value of addr itself (and not the address of the value), we must use the pointer indirection operator, *.
var host = flag.String("addr", ":8080", "The addr of the  application.")

func main() {

	flag.Parse() // parse the flags and extracts the appropriate information

	// setup gomniauth
	gomniauth.SetSecurityKey("some-long-key-with-a-security-hash-or-phrase") //PUT YOUR AUTH KEY HERE
	gomniauth.WithProviders(
		facebook.New("key", "secret",
			"http://localhost:8080/auth/callback/facebook"),
		github.New("19fd7482563016e0d3aa", "7be18299c1e89b6e713a833b42a43f4e2474d23e",
			"http://localhost:8080/auth/callback/github"),
		google.New("1056164496517-qk95dvdsl910ef5rp4ghpribj3gbgf2t.apps.googleusercontent.com", "ZHkA2EEiP2MN1TpMPBaOVxm9",
			"http://localhost:8080/auth/callback/google"),
	)

	r := newRoom()
	r.tracer = trace.New(os.Stdout)

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "/chat")
		w.WriteHeader(http.StatusTemporaryRedirect)
	})
	http.Handle("/chat", MustAuth(&templateHandler{filename: "chat.html"}))
	http.Handle("/login", &templateHandler{filename: "login.html"})
	http.HandleFunc("/auth/", loginHandler)
	http.Handle("/room", r)

	// assets
	http.Handle("/assets/", http.StripPrefix("/assets", http.FileServer(http.Dir("../assets/"))))

	// get the room going
	go r.run()

	// start the web server
	log.Println("Starting web server on", *host)
	log.Println("Visit http://localhost:8080 to start chatting..")
	if err := http.ListenAndServe(*host, nil); err != nil {
		log.Fatal("ListenAndServe:", err)
	}
}
