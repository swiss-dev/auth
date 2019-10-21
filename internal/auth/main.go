package auth

import (
	"cloud.google.com/go/firestore"
	"context"
	"encoding/json"
	"fmt"
	"github.com/swiss-dev/swiss.dev/auth/internal/model"
	"github.com/duo-labs/webauthn/protocol"
	"github.com/duo-labs/webauthn/webauthn"
	"github.com/gorilla/mux"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"log"
	"net/http"
	"strings"
)

var (
	webAuthn *webauthn.WebAuthn
	err error
	fs *firestore.Client
)

// Your initialization function
func main() {
	webAuthn, err = webauthn.New(&webauthn.Config{
		RPDisplayName: "Swiss.dev Auth",                 // Display Name for your site
		RPID:          "swiss.dev",                  // Generally the FQDN for your site
		RPOrigin:      "https://auth.swiss.dev",    // The origin URL for WebAuthn requests
		RPIcon:        "https://swiss.dev/favicon.ico", // Optional icon URL for your site
	})
	if err != nil {
		fmt.Println(err)
	}
	ctx := context.Background()
	fs, err = firestore.NewClient(ctx, "swiss-dev")
	if err != nil {
		fmt.Println(err)
	}

	r := mux.NewRouter()

	r.HandleFunc("/register/{username}", BeginRegistration).Methods("GET")
	r.HandleFunc("/register/{username}", FinishRegistration).Methods("POST")
	r.HandleFunc("/login/{username}", BeginLogin).Methods("GET")
	r.HandleFunc("/login/{username}", FinishLogin).Methods("POST")

	r.PathPrefix("/").Handler(http.FileServer(http.Dir("./")))

	serverAddress := ":8080"
	log.Println("starting server at", serverAddress)
	log.Fatal(http.ListenAndServe(serverAddress, r))

}
func BeginRegistration(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	username, ok := vars["username"]
	if !ok {
		jsonResponse(w, fmt.Errorf("must supply a valid username i.e. foo@bar.com"), http.StatusBadRequest)
		return
	}

	// get user
	var user model.User
	ref := fs.Collection("users").Doc(username)
	ctx := context.Background()
	snapshot, err := ref.Get(ctx)

	if err != nil {
		if status.Code(err) != codes.NotFound {
			log.Fatal("uh-oh")
		} else {
			displayName := strings.Split(username, "@")[0]
			user = model.NewUser(username, displayName)
			_, err = ref.Set(ctx, user)
			if err != nil {
				log.Fatal("couldn't save user", err)
			}
		}
	} else {
		err = snapshot.DataTo(user)
		if err != nil {
			log.Fatal("couldn't parse user", err)
		}
	}
	// user doesn't exist, create new user
	if err != nil {
		displayName := strings.Split(username, "@")[0]
		user = NewUser(username, displayName)
		userDB.PutUser(user)
	}

	registerOptions := func(credCreationOpts *protocol.PublicKeyCredentialCreationOptions) {
		credCreationOpts.CredentialExcludeList = user.CredentialExcludeList()
	}

	// generate PublicKeyCredentialCreationOptions, session data
	options, sessionData, err := webAuthn.BeginRegistration(
		user,
		registerOptions,
	)

	if err != nil {
		log.Println(err)
		jsonResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// store session data as marshaled JSON
	err = sessionStore.SaveWebauthnSession("registration", sessionData, r, w)
	if err != nil {
		log.Println(err)
		jsonResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}

	jsonResponse(w, options, http.StatusOK)
}

func FinishRegistration(w http.ResponseWriter, r *http.Request) {
	user := datastore.GetUser() // Get the user
	// Get the session data stored from the function above
	// using gorilla/sessions it could look like this
	sessionData := store.Get(r, "registration-session")
	credential, err := web.FinishRegistration(&user, sessionData, r)
	// Handle validation or input errors
	// If creation was successful, store the credential object
	JSONResponse(w, "Registration Success", http.StatusOK) // Handle next steps
}

func BeginLogin(w http.ResponseWriter, r *http.Request) {
	user := datastore.GetUser() // Find the user
	options, sessionData, err := webauthn.BeginLogin(&user)
	// handle errors if present
	// store the sessionData values
	JSONResponse(w, options, http.StatusOK) // return the options generated
	// options.publicKey contain our registration options
}

func FinishLogin(w http.ResponseWriter, r *http.Request) {
	user := datastore.GetUser() // Get the user
	// Get the session data stored from the function above
	// using gorilla/sessions it could look like this
	sessionData := store.Get(r, "login-session")
	credential, err := webauthn.FinishLogin(&user, sessionData, r)
	// Handle validation or input errors
	// If login was successful, handle next steps
	JSONResponse(w, "Login Success", http.StatusOK)
}

func jsonResponse(w http.ResponseWriter, d interface{}, c int) {
	dj, err := json.Marshal(d)
	if err != nil {
		http.Error(w, "Error creating JSON response", http.StatusInternalServerError)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(c)
	fmt.Fprintf(w, "%s", dj)
}