package main

import (
	"database/sql"
	"encoding/json"
	"html/template"
	"log"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/dgrijalva/jwt-go"
	_ "github.com/go-sql-driver/mysql"
	"golang.org/x/crypto/bcrypt"
)

type SkillGroup struct {
	Id      int
	Name    string
	Class   string
	Enabled string
}

type SkillGroupHandlers struct {
	sync.Mutex
	store map[string]SkillGroup
}

type Skill struct {
	Id      int
	Name    string
	GroupId int
	Enabled string
}

type SkillEditor struct {
	Id         int
	Name       string
	GroupId    int
	Enabled    string
	GroupIDs   []int
	GroupNames []string
}

// Create a struct that models the structure of a user, both in the request body, and in the DB
type Credentials struct {
	Id        int
	Userrole  string
	Lastname  string
	Firstname string
	Email     string
	Password  string
	Cohort    string
	Enabled   string
}

type Claims struct {
	Email string `json:"email"`
	jwt.StandardClaims
}

// JWT
var jwtKey = []byte("my_secret_key")
var tmpl = template.Must(template.ParseGlob("form/*"))

func dbConn() (db *sql.DB) {
	dbDriver := "mysql"
	dbUser := "root"
	dbPass := "Fallout@99"
	dbName := "clinicalskills"
	db, err := sql.Open(dbDriver, dbUser+":"+dbPass+"@/"+dbName)
	if err != nil {
		panic(err.Error())
	}
	return db
}

func Index(w http.ResponseWriter, r *http.Request) {
	if !CheckSession(w, r) {
		log.Println("Cookie check failed.")
		Login(w, r)
		return
	}
	RefreshToken(w, r)
	if !HasPermission(r, "admin") {
		return
	}

	db := dbConn()
	// Load and display skill groups
	rows, err := db.Query("SELECT * FROM skillgroups")
	if err != nil {
		panic(err.Error())
	}
	group := SkillGroup{}
	res := []SkillGroup{}
	for rows.Next() {
		var id int
		var class, name, enabled string
		err = rows.Scan(&id, &name, &class, &enabled)
		if err != nil {
			panic(err.Error())
		}
		group.Id = id
		group.Class = class
		group.Name = name
		group.Enabled = enabled
		res = append(res, group)
	}
	// Load and display skills
	skilldata := struct {
		Id        int
		Skillname string
		Groupid   int
		Groupname string
		Enabled   string
	}{}
	sres := []struct {
		Id        int
		Skillname string
		Groupid   int
		Groupname string
		Enabled   string
	}{}

	rows, err = db.Query("select s.id, s.name as skillname, groupid, g.name as groupname, s.enabled from skills as s join skillgroups as g on s.groupid=g.id")
	if err != nil {
		panic(err.Error())
	}
	for rows.Next() {
		var id, groupid int
		var skillname, groupname, enabled string
		err = rows.Scan(&id, &skillname, &groupid, &groupname, &enabled)
		if err != nil {
			panic(err.Error())
		}
		skilldata.Id = id
		skilldata.Skillname = skillname
		skilldata.Groupid = groupid
		skilldata.Groupname = groupname
		skilldata.Enabled = enabled
		sres = append(sres, skilldata)
	}
	// Load and display users
	rows, err = db.Query("SELECT * FROM users")
	if err != nil {
		panic(err.Error())
	}
	cred := Credentials{}
	ures := []Credentials{}
	for rows.Next() {
		var id int
		var userrole, lastname, firstname, email, password, cohort, enabled string
		err = rows.Scan(&id, &userrole, &lastname, &firstname, &email, &password, &cohort, &enabled)
		if err != nil {
			panic(err.Error())
		}
		cred.Id = id
		cred.Userrole = userrole
		cred.Lastname = lastname
		cred.Firstname = firstname
		cred.Email = email
		cred.Password = password
		cred.Password = "It's a secret to everybody!"
		cred.Cohort = cohort
		cred.Enabled = enabled
		ures = append(ures, cred)
	}
	tmpl = template.Must(template.ParseGlob("form/*"))
	tmpl.ExecuteTemplate(w, "Groups", res)
	tmpl.ExecuteTemplate(w, "Skills", sres)
	tmpl.ExecuteTemplate(w, "Users", ures)
	tmpl.ExecuteTemplate(w, "Signoffs", nil)
	defer db.Close()
}

func HasPermission(r *http.Request, req string) bool {
	var creds = GetCredentials()
	c, err := r.Cookie("token")
	tknStr := c.Value
	claims := &Claims{}
	tkn, err := jwt.ParseWithClaims(tknStr, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})
	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			return false
		}
		return false
	}
	if !tkn.Valid {
		return false
	}

	var role string
	for i := 0; i < len(creds); i++ {
		if creds[i].Email == claims.Email {
			role = creds[i].Userrole
		}
	}
	if req == "admin" {
		if role != "admin" {
			log.Printf("Unauthorized attempt by %s to access admin level page.", claims.Email)
			return false
		}
	}
	if req == "instructor" {
		if role != "admin" && role != "instructor" {
			log.Printf("Unauthorized attempt by %s to access instructor level page.", claims.Email)
			return false
		}
	}
	return true
}

func ShowGroup(w http.ResponseWriter, r *http.Request) {
	log.Println(r.URL.Path)
	if !CheckSession(w, r) {
		Login(w, r)
		return
	}
	db := dbConn()
	nId := r.URL.Query().Get("id")
	rows, err := db.Query("SELECT * FROM skillgroups WHERE id=?", nId)
	if err != nil {
		panic(err.Error())
	}
	group := SkillGroup{}
	for rows.Next() {
		var id int
		var class, name, enabled string
		err = rows.Scan(&id, &name, &class, &enabled)
		if err != nil {
			panic(err.Error())
		}
		group.Id = id
		group.Class = class
		group.Name = name
		group.Enabled = enabled
	}
	tmpl.ExecuteTemplate(w, "ShowGroup", group)
	defer db.Close()
}

func NewGroup(w http.ResponseWriter, r *http.Request) {
	if !CheckSession(w, r) {
		Login(w, r)
		return
	}
	if !HasPermission(r, "admin") {
		return
	}
	tmpl.ExecuteTemplate(w, "NewGroup", nil)
}

func EditGroup(w http.ResponseWriter, r *http.Request) {
	if !CheckSession(w, r) {
		Login(w, r)
		return
	}
	if !HasPermission(r, "admin") {
		return
	}
	db := dbConn()
	nId := r.URL.Query().Get("id")
	rows, err := db.Query("SELECT * FROM skillgroups WHERE id=?", nId)
	if err != nil {
		panic(err.Error())
	}
	group := SkillGroup{}
	for rows.Next() {
		var id int
		var class, name, enabled string
		err = rows.Scan(&id, &name, &class, &enabled)
		if err != nil {
			panic(err.Error())
		}
		group.Id = id
		group.Class = class
		group.Name = name
		group.Enabled = enabled
	}
	tmpl.ExecuteTemplate(w, "EditGroup", group)
	defer db.Close()
}

func InsertGroup(w http.ResponseWriter, r *http.Request) {
	if !CheckSession(w, r) {
		Login(w, r)
		return
	}
	if !HasPermission(r, "admin") {
		return
	}
	db := dbConn()
	if r.Method == "POST" {
		name := r.FormValue("name")
		class := r.FormValue("class")
		enabled := r.FormValue("enabled")
		insForm, err := db.Prepare("INSERT INTO skillgroups(name, class, enabled) VALUES(?,?,?)")
		if err != nil {
			panic(err.Error())
		}
		insForm.Exec(name, class, enabled)
		log.Println("INSERT: Class: " + class + " | Name: " + name + " | Enabled: " + enabled)
	}
	defer db.Close()
	http.Redirect(w, r, "/", 301)
}

func UpdateGroup(w http.ResponseWriter, r *http.Request) {
	if !CheckSession(w, r) {
		Login(w, r)
		return
	}
	if !HasPermission(r, "admin") {
		return
	}
	db := dbConn()
	if r.Method == "POST" {
		name := r.FormValue("name")
		class := r.FormValue("class")
		enabled := r.FormValue("enabled")
		id := r.FormValue("uid")
		insForm, err := db.Prepare("UPDATE skillgroups SET name=?, class=?, enabled=? WHERE id=?")
		if err != nil {
			panic(err.Error())
		}
		insForm.Exec(name, class, enabled, id)
		log.Println("UPDATE: Class: " + class + " | Name: " + name + " | Enabled: " + enabled)
	}
	defer db.Close()
	http.Redirect(w, r, "/", 301)
}

func DeleteGroup(w http.ResponseWriter, r *http.Request) {
	if !CheckSession(w, r) {
		Login(w, r)
		return
	}
	if !HasPermission(r, "admin") {
		return
	}
	db := dbConn()
	emp := r.URL.Query().Get("id")
	delForm, err := db.Prepare("DELETE FROM skillgroups WHERE id=?")
	if err != nil {
		panic(err.Error())
	}
	delForm.Exec(emp)
	log.Println("DELETE Group")
	defer db.Close()
	http.Redirect(w, r, "/", 301)
}

// Function handlers for skills

func ShowSkill(w http.ResponseWriter, r *http.Request) {
	if !CheckSession(w, r) {
		Login(w, r)
		return
	}
	db := dbConn()
	nId := r.URL.Query().Get("id")
	rows, err := db.Query("SELECT * FROM skills WHERE id=?", nId)
	if err != nil {
		panic(err.Error())
	}
	skill := Skill{}
	for rows.Next() {
		var id, groupid int
		var name, enabled string
		err = rows.Scan(&id, &name, &groupid, &enabled)
		if err != nil {
			panic(err.Error())
		}
		skill.Id = id
		skill.Name = name
		skill.GroupId = groupid
		skill.Enabled = enabled
	}
	tmpl.ExecuteTemplate(w, "ShowSkill", skill)
	defer db.Close()
}

func NewSkill(w http.ResponseWriter, r *http.Request) {
	if !CheckSession(w, r) {
		Login(w, r)
		return
	}
	if !HasPermission(r, "admin") {
		return
	}
	db := dbConn()
	// Load and display skill groups
	rows, err := db.Query("SELECT * FROM skillgroups")
	if err != nil {
		panic(err.Error())
	}
	group := SkillGroup{}
	res := []SkillGroup{}
	for rows.Next() {
		var id int
		var class, name, enabled string
		err = rows.Scan(&id, &name, &class, &enabled)
		if err != nil {
			panic(err.Error())
		}
		group.Id = id
		group.Class = class
		group.Name = name
		group.Enabled = enabled
		res = append(res, group)
	}
	tmpl.ExecuteTemplate(w, "NewSkill", res)
}

func EditSkill(w http.ResponseWriter, r *http.Request) {
	if !CheckSession(w, r) {
		Login(w, r)
		return
	}
	if !HasPermission(r, "admin") {
		return
	}
	db := dbConn()
	nId := r.URL.Query().Get("id")
	rows, err := db.Query("SELECT * FROM skills WHERE id=?", nId)
	if err != nil {
		panic(err.Error())
	}
	ske := SkillEditor{}
	skill := Skill{}
	for rows.Next() {
		var id, groupid int
		var name, enabled string
		err = rows.Scan(&id, &name, &groupid, &enabled)
		if err != nil {
			panic(err.Error())
		}
		skill.Id = id
		skill.GroupId = groupid
		skill.Name = name
		skill.Enabled = enabled
	}
	group := SkillGroup{}
	rows, err = db.Query("SELECT * FROM skillgroups")
	if err != nil {
		panic(err.Error())
	}

	for rows.Next() {
		var id int
		var class, name, enabled string
		err = rows.Scan(&id, &name, &class, &enabled)
		if err != nil {
			panic(err.Error())
		}
		group.Id = id
		group.Class = class
		group.Name = name
		group.Enabled = enabled
		ske.GroupIDs = append(ske.GroupIDs, id)
		ske.GroupNames = append(ske.GroupNames, name)
	}
	ske.Id = skill.Id
	ske.GroupId = skill.Id
	ske.Name = skill.Name
	ske.Enabled = skill.Enabled
	tmpl.ExecuteTemplate(w, "EditSkill", ske)
	defer db.Close()
}

func InsertSkill(w http.ResponseWriter, r *http.Request) {
	if !CheckSession(w, r) {
		Login(w, r)
		return
	}
	if !HasPermission(r, "admin") {
		return
	}
	db := dbConn()
	if r.Method == "POST" {
		name := r.FormValue("name")
		groupid := r.FormValue("groupid")
		enabled := r.FormValue("enabled")
		insForm, err := db.Prepare("INSERT INTO skills(name, groupid, enabled) VALUES(?,?,?)")
		if err != nil {
			panic(err.Error())
		}
		insForm.Exec(name, groupid, enabled)
		log.Println("INSERT: Class: " + groupid + " | Name: " + name + " | Enabled: " + enabled)
	}
	defer db.Close()
	http.Redirect(w, r, "/", 301)
}

func UpdateSkill(w http.ResponseWriter, r *http.Request) {
	if !CheckSession(w, r) {
		Login(w, r)
		return
	}
	if !HasPermission(r, "admin") {
		return
	}
	db := dbConn()
	if r.Method == "POST" {
		name := r.FormValue("name")
		groupid := r.FormValue("groupid")
		enabled := r.FormValue("enabled")
		id := r.FormValue("uid")
		insForm, err := db.Prepare("UPDATE skills SET name=?, groupid=?, enabled=? WHERE id=?")
		if err != nil {
			panic(err.Error())
		}
		gid, _ := strconv.Atoi(groupid)
		gid = gid + 1
		insForm.Exec(name, gid, enabled, id)
		log.Println("UPDATE: Groupid: " + groupid + " | Name: " + name + " | Enabled: " + enabled)
	}
	defer db.Close()
	http.Redirect(w, r, "/", 301)
}

func DeleteSkill(w http.ResponseWriter, r *http.Request) {
	if !CheckSession(w, r) {
		Login(w, r)
		return
	}
	if !HasPermission(r, "admin") {
		return
	}
	db := dbConn()
	emp := r.URL.Query().Get("id")
	delForm, err := db.Prepare("DELETE FROM skills WHERE id=?")
	if err != nil {
		panic(err.Error())
	}
	delForm.Exec(emp)
	log.Println("DELETE Skill")
	defer db.Close()
	http.Redirect(w, r, "/", 301)
}

// User Pages
func GetSkillGroups(w http.ResponseWriter, r *http.Request) {
	db := dbConn()
	// Load and display skill groups
	rows, err := db.Query("SELECT * FROM skillgroups")
	if err != nil {
		panic(err.Error())
	}
	group := SkillGroup{}
	res := []SkillGroup{}
	for rows.Next() {
		var id int
		var class, name, enabled string
		err = rows.Scan(&id, &name, &class, &enabled)
		if err != nil {
			panic(err.Error())
		}
		group.Id = id
		group.Class = class
		group.Name = name
		group.Enabled = enabled
		res = append(res, group)
	}
	jsonBytes, err := json.Marshal(res)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(err.Error()))
	}
	w.Header().Add("content-type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(jsonBytes)
}

func GetSkills(w http.ResponseWriter, r *http.Request) {
	db := dbConn()
	// Load and display skill groups
	rows, err := db.Query("SELECT * FROM skills")
	if err != nil {
		panic(err.Error())
	}
	sgroup := Skill{}
	sres := []Skill{}
	for rows.Next() {
		var id, groupid int
		var name, enabled string
		err = rows.Scan(&id, &name, &groupid, &enabled)
		if err != nil {
			panic(err.Error())
		}
		sgroup.Id = id
		sgroup.GroupId = groupid
		sgroup.Name = name
		sgroup.Enabled = enabled
		sres = append(sres, sgroup)
	}
	jsonBytes, err := json.Marshal(sres)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(err.Error()))
	}
	w.Header().Add("content-type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(jsonBytes)
}

func GetUsers(w http.ResponseWriter, r *http.Request) {
	var webusers = GetCredentials()
	for i := 0; i < len(webusers); i++ {
		webusers[i].Password = "It's a secret to everybody!"
	}
	if !HasPermission(r, "instructor") {
		return
	}
	jsonBytes, err := json.Marshal(webusers)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(err.Error()))
	}
	w.Header().Add("content-type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(jsonBytes)
}

var users = map[string]string{}

//map[string]string{
//"user1": "password1",
//"user2": "password2",}

func GetCredentials() []Credentials {
	db := dbConn()
	// Load users from database
	rows, err := db.Query("SELECT * FROM users")
	if err != nil {
		panic(err.Error())
	}
	user := Credentials{}
	dbusers := []Credentials{}
	for rows.Next() {
		var id int
		var userrole, lastname, firstname, email, password, cohort, enabled string
		err = rows.Scan(&id, &userrole, &lastname, &firstname, &email, &password, &cohort, &enabled)
		if err != nil {
			panic(err.Error())
		}
		user.Id = id
		user.Userrole = userrole
		user.Lastname = lastname
		user.Firstname = firstname
		user.Email = email
		user.Password = password
		user.Cohort = cohort
		user.Enabled = enabled
		dbusers = append(dbusers, user)
	}
	return dbusers
}

func RefreshToken(w http.ResponseWriter, r *http.Request) {
	// (BEGIN) The code uptil this point is the same as the first part of the `Welcome` route
	c, err := r.Cookie("token")
	if err != nil {
		if err == http.ErrNoCookie {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	tknStr := c.Value
	claims := &Claims{}
	tkn, err := jwt.ParseWithClaims(tknStr, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})
	if !tkn.Valid {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusAlreadyReported)
		return
	}
	// (END) The code uptil this point is the same as the first part of the `Welcome` route

	// We ensure that a new token is not issued until enough time has elapsed
	// In this case, a new token will only be issued if the old token is within
	// 30 seconds of expiry. Otherwise, return a bad request status
	if time.Unix(claims.ExpiresAt, 0).Sub(time.Now()) > 30*time.Second {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Now, create a new token for the current use, with a renewed expiration time
	expirationTime := time.Now().Add(5 * time.Minute)
	claims.ExpiresAt = expirationTime.Unix()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Set the new token as the users `session_token` cookie
	http.SetCookie(w, &http.Cookie{
		Name:    "session_token",
		Value:   tokenString,
		Expires: expirationTime,
	})
}

func Signin(w http.ResponseWriter, r *http.Request) {
	log.Println("Sign in requested.")
	var creds Credentials
	if r.Method == "POST" {
		creds.Email = r.FormValue("Email")
		creds.Password = r.FormValue("Password")
	} else {
		// If the structure of the body is wrong, return an HTTP error
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	// Get the JSON body and decode into credentials
	/*err := json.NewDecoder(r.Body).Decode(&creds)
	if err != nil {
		// If the structure of the body is wrong, return an HTTP error
		//w.WriteHeader(http.StatusBadRequest)
		//return
	}*/

	// Get the expected password from our in memory map
	//expectedPassword, ok := users[creds.Email]
	expectedPassword := users[creds.Email]
	if err := bcrypt.CompareHashAndPassword([]byte(expectedPassword), []byte(creds.Password)); err != nil {
		//w.WriteHeader(http.StatusUnauthorized)
		//http.Redirect(w, r, "/login", 301)
		Login(w, r)
		return
	}
	// If a password exists for the given user
	// AND, if it is the same as the password we received, the we can move ahead
	// if NOT, then we return an "Unauthorized" status
	/*if !ok || expectedPassword != creds.Password {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}*/
	log.Println("Password accepted.")
	// Declare the expiration time of the token
	// here, we have kept it as 5 minutes
	expirationTime := time.Now().Add(15 * time.Minute)
	// Create the JWT claims, which includes the email and expiry time
	claims := &Claims{
		Email: creds.Email,
		StandardClaims: jwt.StandardClaims{
			// In JWT, the expiry time is expressed as unix milliseconds
			ExpiresAt: expirationTime.Unix(),
		},
	}

	// Declare the token with the algorithm used for signing, and the claims
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	// Create the JWT string
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		// If there is an error in creating the JWT return an internal server error
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Finally, we set the client cookie for "token" as the JWT we just generated
	// we also set an expiry time which is the same as the token itself
	http.SetCookie(w, &http.Cookie{
		Name:    "token",
		Value:   tokenString,
		Expires: expirationTime,
	})
	log.Println("Cookie set.")
	//tmpl.ExecuteTemplate(w, "Index", nil)
	//Index(w, r)
	http.Redirect(w, r, "/", 301)
}

func CheckSession(w http.ResponseWriter, r *http.Request) bool {
	// We can obtain the session token from the requests cookies, which come with every request
	c, err := r.Cookie("token")
	if err != nil {
		if err == http.ErrNoCookie {
			// If the cookie is not set, return an unauthorized status
			w.WriteHeader(http.StatusUnauthorized)
			return false
		}
		// For any other type of error, return a bad request status
		w.WriteHeader(http.StatusBadRequest)
		return false
	}

	// Get the JWT string from the cookie
	tknStr := c.Value

	// Initialize a new instance of `Claims`
	claims := &Claims{}

	// Parse the JWT string and store the result in `claims`.
	// Note that we are passing the key in this method as well. This method will return an error
	// if the token is invalid (if it has expired according to the expiry time we set on sign in),
	// or if the signature does not match
	tkn, err := jwt.ParseWithClaims(tknStr, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})
	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			w.WriteHeader(http.StatusUnauthorized)
			return false
		}
		w.WriteHeader(http.StatusBadRequest)
		return false
	}
	if !tkn.Valid {
		w.WriteHeader(http.StatusUnauthorized)
		return false
	}
	// Finally, return the welcome message to the user, along with their
	// email given in the token
	return true
}

func Login(w http.ResponseWriter, r *http.Request) {
	tmpl.ExecuteTemplate(w, "Login", nil)
}

func NewUser(w http.ResponseWriter, r *http.Request) {
	if !CheckSession(w, r) {
		Login(w, r)
		return
	}
	if !HasPermission(r, "admin") {
		return
	}
	tmpl.ExecuteTemplate(w, "NewUser", nil)
}

func ShowUser(w http.ResponseWriter, r *http.Request) {
	log.Println(r.URL.Path)
	if !CheckSession(w, r) {
		Login(w, r)
		return
	}
	if !HasPermission(r, "instructor") {
		return
	}
	db := dbConn()
	nId := r.URL.Query().Get("id")
	rows, err := db.Query("SELECT * FROM users WHERE id=?", nId)
	if err != nil {
		panic(err.Error())
	}
	cred := Credentials{}
	for rows.Next() {
		var id int
		var userrole, lastname, firstname, email, password, cohort, enabled string
		err = rows.Scan(&id, &userrole, &lastname, &firstname, &email, &password, &cohort, &enabled)
		if err != nil {
			panic(err.Error())
		}
		cred.Id = id
		cred.Userrole = userrole
		cred.Lastname = lastname
		cred.Firstname = firstname
		cred.Email = email
		cred.Password = password
		cred.Password = "It's a secret to everybody!"
		cred.Cohort = cohort
		cred.Enabled = enabled
	}
	tmpl.ExecuteTemplate(w, "ShowUser", cred)
	defer db.Close()
}

func EditUser(w http.ResponseWriter, r *http.Request) {
	if !CheckSession(w, r) {
		Login(w, r)
		return
	}
	if !HasPermission(r, "admin") {
		return
	}
	db := dbConn()
	nId := r.URL.Query().Get("id")
	rows, err := db.Query("SELECT * FROM users WHERE id=?", nId)
	if err != nil {
		panic(err.Error())
	}
	user := Credentials{}
	for rows.Next() {
		var id int
		var userrole, lastname, firstname, email, password, cohort, enabled string
		err = rows.Scan(&id, &userrole, &lastname, &firstname, &email, &password, &cohort, &enabled)
		if err != nil {
			panic(err.Error())
		}
		user.Id = id
		user.Userrole = userrole
		user.Lastname = lastname
		user.Firstname = firstname
		user.Email = email
		user.Password = password
		user.Password = "It's a secret to everybody!"
		user.Cohort = cohort
		user.Enabled = enabled
	}
	tmpl.ExecuteTemplate(w, "EditUser", user)
	defer db.Close()
}

func InsertUser(w http.ResponseWriter, r *http.Request) {
	if !CheckSession(w, r) {
		Login(w, r)
		return
	}
	if !HasPermission(r, "admin") {
		return
	}
	db := dbConn()
	if r.Method == "POST" {
		userrole := r.FormValue("userrole")
		lastname := r.FormValue("lastname")
		firstname := r.FormValue("firstname")
		email := r.FormValue("email")
		password := r.FormValue("password")
		cohort := r.FormValue("cohort")
		enabled := "True"
		hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			log.Fatal(err)
		}
		insForm, err := db.Prepare("INSERT INTO users(userrole, lastname, firstname, email, password, cohort, enabled) VALUES(?,?,?,?,?,?,?)")
		if err != nil {
			panic(err.Error())
		}
		insForm.Exec(userrole, lastname, firstname, email, hash, cohort, enabled)
		log.Println("INSERT: User: " + lastname + ", " + firstname)
	}
	defer db.Close()
	http.Redirect(w, r, "/", 301)
}

func UpdateUser(w http.ResponseWriter, r *http.Request) {
	if !CheckSession(w, r) {
		Login(w, r)
		return
	}
	if !HasPermission(r, "admin") {
		return
	}
	db := dbConn()
	if r.Method == "POST" {
		id := r.FormValue("uid")
		userrole := r.FormValue("userrole")
		lastname := r.FormValue("lastname")
		firstname := r.FormValue("firstname")
		email := r.FormValue("email")
		oldemail := r.FormValue("oldemail")
		password := r.FormValue("password")
		cohort := r.FormValue("cohort")
		enabled := "True"
		checked := r.FormValue("updatepw")
		log.Println(checked)
		if checked == "checked" {
			hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
			insForm, err := db.Prepare("UPDATE users SET userrole=?, lastname=?, firstname=?, email=?, password=?, cohort=?, enabled=? WHERE id=?")
			if err != nil {
				panic(err.Error())
			}
			insForm.Exec(userrole, lastname, firstname, email, hash, cohort, enabled, id)
			delete(users, oldemail)
			users[email] = string(hash[:])
			log.Println("UPDATE: User: " + lastname + ", " + firstname)
		} else {
			Password := users[oldemail]
			delete(users, oldemail)
			users[email] = Password
			insForm, err := db.Prepare("UPDATE users SET userrole=?, lastname=?, firstname=?, email=?, cohort=?, enabled=? WHERE id=?")
			if err != nil {
				panic(err.Error())
			}
			insForm.Exec(userrole, lastname, firstname, email, cohort, enabled, id)
			log.Println("UPDATE: User: " + lastname + ", " + firstname)

		}

	}
	defer db.Close()
	http.Redirect(w, r, "/", 301)
}

func DeleteUser(w http.ResponseWriter, r *http.Request) {
	if !CheckSession(w, r) {
		Login(w, r)
		return
	}
	if !HasPermission(r, "admin") {
		return
	}
}

func ListSkills(w http.ResponseWriter, r *http.Request) {
	// Load and display skills
	skilldata := struct {
		Id        int
		Skillname string
		Groupid   int
		Groupname string
		Enabled   string
	}{}
	sres := []struct {
		Id        int
		Skillname string
		Groupid   int
		Groupname string
		Enabled   string
	}{}

	db := dbConn()
	rows, err := db.Query("select s.id, s.name as skillname, groupid, g.name as groupname, s.enabled from skills as s join skillgroups as g on s.groupid=g.id")
	if err != nil {
		panic(err.Error())
	}
	for rows.Next() {
		var id, groupid int
		var skillname, groupname, enabled string
		err = rows.Scan(&id, &skillname, &groupid, &groupname, &enabled)
		if err != nil {
			panic(err.Error())
		}
		skilldata.Id = id
		skilldata.Skillname = skillname
		skilldata.Groupid = groupid
		skilldata.Groupname = groupname
		skilldata.Enabled = enabled
		sres = append(sres, skilldata)
	}
	tmpl.ExecuteTemplate(w, "ListSkills", sres)
	defer db.Close()
}
func main() {
	var creds = GetCredentials()
	for i := 0; i < len(creds); i++ {
		users[creds[i].Email] = creds[i].Password
	}
	log.Println("Server started on: http://localhost")
	http.HandleFunc("/", Index)
	http.HandleFunc("/showgroup", ShowGroup)
	http.HandleFunc("/newgroup", NewGroup)
	http.HandleFunc("/editgroup", EditGroup)
	http.HandleFunc("/insertgroup", InsertGroup)
	http.HandleFunc("/updategroup", UpdateGroup)
	http.HandleFunc("/deletegroup", DeleteGroup)

	http.HandleFunc("/showskill", ShowSkill)
	http.HandleFunc("/newskill", NewSkill)
	http.HandleFunc("/editskill", EditSkill)
	http.HandleFunc("/insertskill", InsertSkill)
	http.HandleFunc("/updateskill", UpdateSkill)
	http.HandleFunc("/deleteskill", DeleteSkill)

	http.HandleFunc("/showuser", ShowUser)
	http.HandleFunc("/newuser", NewUser)
	http.HandleFunc("/edituser", EditUser)
	http.HandleFunc("/insertuser", InsertUser)
	http.HandleFunc("/updateuser", UpdateUser)
	http.HandleFunc("/deleteuser", DeleteUser)

	http.HandleFunc("/getgroups", GetSkillGroups)
	http.HandleFunc("/getskills", GetSkills)
	http.HandleFunc("/getusers", GetUsers)

	http.HandleFunc("/listskills", ListSkills)

	http.HandleFunc("/login", Login)
	http.HandleFunc("/signin", Signin)
	http.Handle("/assets/", http.StripPrefix("/assets/", http.FileServer(http.Dir("./assets"))))
	http.ListenAndServe(":80", nil)
}
