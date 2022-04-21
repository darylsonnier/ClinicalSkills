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

// User map
var users = map[string]string{}

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
	CORSEnabledFunction(&w, r)
	if !CheckSession(w, r) {
		log.Println("Cookie check failed.")
		Login(w, r)
		return
	}
	RefreshToken(w, r)
	if !HasPermission(r, "instructor") {
		tmpl.ExecuteTemplate(w, "Unauthorized", nil)
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

	signoffdata := struct {
		Id          int
		Slastname   string
		Sfirstname  string
		Ilastname   string
		Ifirstname  string
		Skillname   string
		Groupname   string
		Signofftype string
		Signoffdate string
	}{}
	snres := []struct {
		Id          int
		Slastname   string
		Sfirstname  string
		Ilastname   string
		Ifirstname  string
		Skillname   string
		Groupname   string
		Signofftype string
		Signoffdate string
	}{}
	rows, err = db.Query(`
		select signoffs.id as id, student.lastname as student_lastname, student.firstname as student_firstname, instructor.lastname as instuctor_lastname, 
		instructor.firstname as instructor_firstname, skills.name as skillname, skillgroups.name as groupname, signofftype, signoffdate 
		from signoffs 
		join users as student on signoffs.studentid=student.id
		join users as instructor on signoffs.instructorid=instructor.id
		join skills on signoffs.skillid=skills.id
		join skillgroups on skills.groupid=skillgroups.id
	`)
	if err != nil {
		panic(err.Error())
	}
	for rows.Next() {
		var id int
		var student_lastname, student_firstname, instructor_lastname, instructor_firstname, skillname, groupname, signofftype, signoffdate string
		err = rows.Scan(&id, &student_lastname, &student_firstname, &instructor_lastname, &instructor_firstname, &skillname, &groupname, &signofftype, &signoffdate)
		if err != nil {
			panic(err.Error())
		}
		signoffdata.Id = id
		signoffdata.Slastname = student_lastname
		signoffdata.Sfirstname = student_firstname
		signoffdata.Ilastname = instructor_lastname
		signoffdata.Ifirstname = instructor_firstname
		signoffdata.Skillname = skillname
		signoffdata.Groupname = groupname
		signoffdata.Signofftype = signofftype
		signoffdata.Signoffdate = signoffdate
		snres = append(snres, signoffdata)
	}
	tmpl.ExecuteTemplate(w, "Groups", res)
	tmpl.ExecuteTemplate(w, "Skills", sres)
	tmpl.ExecuteTemplate(w, "Users", ures)
	tmpl.ExecuteTemplate(w, "Signoffs", snres)
	defer db.Close()
}

func HasPermission(r *http.Request, req string) bool {
	var creds = GetCredentials()
	c, err := r.Cookie("token")
	if err != nil {
		log.Println("No access")
	}
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

func GetRequester(r *http.Request) int {
	var creds = GetCredentials()
	c, err := r.Cookie("token")
	tknStr := c.Value
	claims := &Claims{}
	tkn, err := jwt.ParseWithClaims(tknStr, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})
	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			return -1
		}
		return -1
	}
	if !tkn.Valid {
		return -1
	}

	id := -1
	for i := 0; i < len(creds); i++ {
		if creds[i].Email == claims.Email {
			id = creds[i].Id
		}
	}
	return id
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
		tmpl.ExecuteTemplate(w, "Unauthorized", nil)
		return
	}
	db := dbConn()
	if r.Method == "POST" {
		name := r.FormValue("name")
		class := r.FormValue("class")
		enabled := r.FormValue("enabled")
		insertFormData, err := db.Prepare("INSERT INTO skillgroups(name, class, enabled) VALUES(?,?,?)")
		if err != nil {
			panic(err.Error())
		}
		insertFormData.Exec(name, class, enabled)
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
		tmpl.ExecuteTemplate(w, "Unauthorized", nil)
		return
	}
	db := dbConn()
	if r.Method == "POST" {
		name := r.FormValue("name")
		class := r.FormValue("class")
		enabled := r.FormValue("enabled")
		id := r.FormValue("uid")
		insertFormData, err := db.Prepare("UPDATE skillgroups SET name=?, class=?, enabled=? WHERE id=?")
		if err != nil {
			panic(err.Error())
		}
		insertFormData.Exec(name, class, enabled, id)
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
		tmpl.ExecuteTemplate(w, "Unauthorized", nil)
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
	rows, err := db.Query("select s.id, s.name as skillname, groupid, g.name as groupname, s.enabled from skills as s join skillgroups as g on s.groupid=g.id WHERE s.id=?", nId)
	if err != nil {
		panic(err.Error())
	}
	skilldata := struct {
		Id        int
		Skillname string
		Groupid   int
		Groupname string
		Enabled   string
	}{}
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
	}
	tmpl.ExecuteTemplate(w, "ShowSkill", skilldata)
	defer db.Close()
}

func NewSkill(w http.ResponseWriter, r *http.Request) {
	if !CheckSession(w, r) {
		Login(w, r)
		return
	}
	if !HasPermission(r, "admin") {
		tmpl.ExecuteTemplate(w, "Unauthorized", nil)
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
		tmpl.ExecuteTemplate(w, "Unauthorized", nil)
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
		tmpl.ExecuteTemplate(w, "Unauthorized", nil)
		return
	}
	db := dbConn()
	if r.Method == "POST" {
		name := r.FormValue("name")
		groupid := r.FormValue("groupid")
		enabled := r.FormValue("enabled")
		insertFormData, err := db.Prepare("INSERT INTO skills(name, groupid, enabled) VALUES(?,?,?)")
		if err != nil {
			panic(err.Error())
		}
		insertFormData.Exec(name, groupid, enabled)
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
		tmpl.ExecuteTemplate(w, "Unauthorized", nil)
		return
	}
	db := dbConn()
	if r.Method == "POST" {
		name := r.FormValue("name")
		groupid := r.FormValue("groupid")
		enabled := r.FormValue("enabled")
		id := r.FormValue("uid")
		insertFormData, err := db.Prepare("UPDATE skills SET name=?, groupid=?, enabled=? WHERE id=?")
		if err != nil {
			panic(err.Error())
		}
		gid, _ := strconv.Atoi(groupid)
		gid = gid + 1
		insertFormData.Exec(name, gid, enabled, id)
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
		tmpl.ExecuteTemplate(w, "Unauthorized", nil)
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
	CORSEnabledFunction(&w, r)

	if !CheckSession(w, r) {
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
	jsonBytes, err := json.Marshal(res)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(err.Error()))
	}
	w.Header().Add("content-type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(jsonBytes)
	defer db.Close()
}

func GetSkills(w http.ResponseWriter, r *http.Request) {
	CORSEnabledFunction(&w, r)

	if !CheckSession(w, r) {
		return
	}
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
	defer db.Close()
}

func GetStudents(w http.ResponseWriter, r *http.Request) {
	CORSEnabledFunction(&w, r)

	if !CheckSession(w, r) {
		return
	}
	if !HasPermission(r, "instructor") {
		return
	}

	var webusers = GetCredentials()
	var students []Credentials
	for i := 0; i < len(webusers); i++ {
		webusers[i].Password = "It's a secret to everybody!"
		if webusers[i].Userrole == "student" {
			students = append(students, webusers[i])
		}
	}
	jsonBytes, err := json.Marshal(students)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(err.Error()))
	}
	w.Header().Add("content-type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(jsonBytes)
}

func GetStudents2(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "http://localhost:3000")
	w.Header().Add("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
	w.Header().Add("Access-Control-Allow-Headers", "Content-Type")
	w.Header().Add("Access-Control-Max-Age", "3600")
	w.Header().Add("Access-Control-Allow-Credentials", "true")
	w.Header().Add("Access-Control-Expose-Headers", "true")
	w.Header().Add("Exposed-Headers", "set-cookie")
	w.Header().Add("Debug", "True")
	var creds Credentials
	if r.Method == "POST" {
		creds.Email = r.FormValue("Email")
		creds.Password = r.FormValue("Password")
	} else {
		// If the structure of the body is wrong, return an HTTP error
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	expectedPassword := users[creds.Email]
	if err := bcrypt.CompareHashAndPassword([]byte(expectedPassword), []byte(creds.Password)); err != nil {
		log.Println("Password error")
		return
	}

	/*if !CheckSession(w, r) {
		log.Println("Cookie check failed.")
		Login(w, r)
		return
	}*/
	var webusers = GetCredentials()
	var students []Credentials
	for i := 0; i < len(webusers); i++ {
		webusers[i].Password = "It's a secret to everybody!"
		if webusers[i].Userrole == "student" {
			students = append(students, webusers[i])
		}
	}
	/*if !HasPermission(r, "instructor") {
		tmpl.ExecuteTemplate(w, "Unauthorized", nil)
		return
	}*/

	var allcreds = GetCredentials()
	var role string
	for i := 0; i < len(allcreds); i++ {
		if allcreds[i].Email == creds.Email {
			role = allcreds[i].Userrole
		}
	}
	log.Println(role)
	if role != "admin" && role != "instructor" {
		if role != "admin" {
			log.Printf("Unauthorized attempt by %s to access admin level page.", creds.Email)
			return
		}
	}

	jsonBytes, err := json.Marshal(students)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(err.Error()))
	}
	w.Header().Add("content-type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(jsonBytes)
}

func GetSignoffsByID(w http.ResponseWriter, r *http.Request) {
	if !CheckSession(w, r) {
		Login(w, r)
		return
	}
	isAdmin := false
	if HasPermission(r, "admin") || HasPermission(r, "instructor") {
		log.Println("Instructor access approved.")
		isAdmin = true
	}
	currentuser := GetRequester(r)
	uid := r.URL.Query().Get("id")
	id, err := strconv.Atoi(uid)
	if err != nil {
		panic(err)
	}
	log.Println(id)
	if !isAdmin && id != currentuser {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	db := dbConn()
	// Load signoffs
	signoffdata := struct {
		Id          int
		Signofftype string
		Signofdate  string
		Ilastname   string
		Ifirstname  string
		Skillname   string
		Groupname   string
	}{}
	sres := []struct {
		Id          int
		Signofftype string
		Signofdate  string
		Ilastname   string
		Ifirstname  string
		Skillname   string
		Groupname   string
	}{}
	rows, err := db.Query(`select signoffs.id as sid, signofftype, signoffdate, instructor.lastname as ilastname, instructor.firstname as ifirstname, skills.name as skillname, skillgroups.name as groupname
	from signoffs 
	join users as student on signoffs.studentid=student.id
	join users as instructor on signoffs.instructorid=instructor.id 
	join skills on signoffs.skillid=skills.id
	join skillgroups on skills.groupid=skillgroups.id
	where student.id=?`, id)
	if err != nil {
		panic(err.Error())
	}
	for rows.Next() {
		var sid int
		var signofftype, signoffdate, ilastname, ifirstname, skillname, groupname string
		err = rows.Scan(&sid, &signofftype, &signoffdate, &ilastname, &ifirstname, &skillname, &groupname)
		if err != nil {
			panic(err.Error())
		}
		signoffdata.Id = sid
		signoffdata.Signofftype = signofftype
		signoffdata.Signofdate = signoffdate
		signoffdata.Skillname = skillname
		signoffdata.Ilastname = ilastname
		signoffdata.Ifirstname = ifirstname
		signoffdata.Groupname = groupname
		sres = append(sres, signoffdata)
	}
	jsonBytes, err := json.Marshal(sres)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(err.Error()))
	}
	w.Header().Add("content-type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(jsonBytes)
	defer db.Close()
}

func SignoffStudent(w http.ResponseWriter, r *http.Request) {
	if !CheckSession(w, r) {
		Login(w, r)
		return
	}
	if !HasPermission(r, "instructor") {
		tmpl.ExecuteTemplate(w, "Unauthorized", nil)
		return
	}
	var creds = GetCredentials()
	c, err := r.Cookie("token")
	tknStr := c.Value
	claims := &Claims{}
	tkn, err := jwt.ParseWithClaims(tknStr, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})
	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			return
		}
		return
	}
	if !tkn.Valid {
		return
	}

	var instructorid int
	for i := 0; i < len(creds); i++ {
		if creds[i].Email == claims.Email {
			instructorid = creds[i].Id
		}
	}

	db := dbConn()
	var result sql.Result
	if r.Method == "POST" {
		sid := r.FormValue("studentid")
		studentid, err := strconv.Atoi(sid)
		if err != nil {
			panic(err)
		}
		sid = r.FormValue("skillid")
		skillid, err := strconv.Atoi(sid)
		if err != nil {
			panic(err)
		}
		signofftype := r.FormValue("signofftype")
		now := time.Now()

		insertFormData, err := db.Prepare("INSERT INTO signoffs(studentid, instructorid, skillid, signofftype, signoffdate) VALUES(?,?,?,?,?)")
		if err != nil {
			panic(err.Error())
		}
		result, err = insertFormData.Exec(studentid, instructorid, skillid, signofftype, now)
		if err != nil {
			w.WriteHeader(http.StatusRequestedRangeNotSatisfiable)
		} else {
			w.WriteHeader(http.StatusAccepted)
		}

		log.Println("INSERT Signoff - StudentID: " + strconv.Itoa(studentid) + " | InstructorID: " + strconv.Itoa(instructorid) + " | SkillID: " + strconv.Itoa(skillid))
	}
	defer db.Close()
	log.Println(result.RowsAffected())
	return
}

func GetCredentials() []Credentials {
	tmpl = template.Must(template.ParseGlob("form/*"))
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
	defer db.Close()
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
		Name:     "token",
		Value:    tokenString,
		Expires:  expirationTime,
		SameSite: http.SameSiteNoneMode,
	})
}

func CORSEnabledFunction(w *http.ResponseWriter, r *http.Request) {
	// Set CORS headers for the preflight request
	(*w).Header().Set("Access-Control-Allow-Origin", "http://localhost:3000")
	(*w).Header().Add("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
	(*w).Header().Add("Access-Control-Allow-Headers", "Content-Type, Content-Length, Set-Cookie, API-Key")
	(*w).Header().Add("Access-Control-Max-Age", "3600")
	(*w).Header().Add("Access-Control-Allow-Credentials", "true")
	(*w).Header().Add("Access-Control-Expose-Headers", "Content-Length, Set-Cookie, API-Key")
	(*w).Header().Add("Exposed-Headers", "Set-Cookie, Content-Length, API-Key")
	(*w).Header().Add("Debug", "True")
}

func Signin(w http.ResponseWriter, r *http.Request) {
	CORSEnabledFunction(&w, r)

	log.Println("Sign in requested.")
	var creds Credentials
	log.Println(r.Method)
	if r.Method == "POST" {
		creds.Email = r.FormValue("Email")
		creds.Password = r.FormValue("Password")
	} else {
		// If the structure of the body is wrong, return an HTTP error
		w.WriteHeader(http.StatusBadRequest)
		// create response binary data
		data := []byte("Not happenin buddy!") // slice of bytes    // write `data` to response
		w.Write(data)
		log.Println("Not happenin' buddy.")
		return
	}

	expectedPassword := users[creds.Email]
	if err := bcrypt.CompareHashAndPassword([]byte(expectedPassword), []byte(creds.Password)); err != nil {
		log.Println("Password error")
		Login(w, r)
		return
	}

	log.Println("Password accepted.")
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
		Name:     "token",
		Value:    tokenString,
		Expires:  expirationTime,
		SameSite: http.SameSiteNoneMode,
		Secure:   true,
	})
	log.Println("Cookie set.")
	//tmpl.ExecuteTemplate(w, "Index", nil)
	//Index(w, r)
	http.Redirect(w, r, "/", 301)
	return
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
		insertFormData, err := db.Prepare("INSERT INTO users(userrole, lastname, firstname, email, password, cohort, enabled) VALUES(?,?,?,?,?,?,?)")
		if err != nil {
			panic(err.Error())
		}
		insertFormData.Exec(userrole, lastname, firstname, email, hash, cohort, enabled)
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
			insertFormData, err := db.Prepare("UPDATE users SET userrole=?, lastname=?, firstname=?, email=?, password=?, cohort=?, enabled=? WHERE id=?")
			if err != nil {
				panic(err.Error())
			}
			insertFormData.Exec(userrole, lastname, firstname, email, hash, cohort, enabled, id)
			delete(users, oldemail)
			users[email] = string(hash[:])
			log.Println("UPDATE: User: " + lastname + ", " + firstname)
		} else {
			Password := users[oldemail]
			delete(users, oldemail)
			users[email] = Password
			insertFormData, err := db.Prepare("UPDATE users SET userrole=?, lastname=?, firstname=?, email=?, cohort=?, enabled=? WHERE id=?")
			if err != nil {
				panic(err.Error())
			}
			insertFormData.Exec(userrole, lastname, firstname, email, cohort, enabled, id)
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
	http.HandleFunc("/getstudents", GetStudents)
	http.HandleFunc("/bob", GetStudents)
	http.HandleFunc("/getsignoffsbyid", GetSignoffsByID)

	http.HandleFunc("/login", Login)
	http.HandleFunc("/signin", Signin)
	http.HandleFunc("/signoffstudent", SignoffStudent)
	http.Handle("/assets/", http.StripPrefix("/assets/", http.FileServer(http.Dir("./assets"))))
	//log.Fatal(http.ListenAndServe(":80", nil))
	s := &http.Server{
		ReadTimeout:       1 * time.Second,
		WriteTimeout:      10 * time.Second,
		ReadHeaderTimeout: 20 * time.Second,
		Addr:              ":9000",
	}
	s.ListenAndServeTLS("certs\\server.crt", "certs\\server.key")
}
