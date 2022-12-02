// main.go

package main

import (
	"errors"
	"log"
	"math/rand"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
)

// Create the router
var router *gin.Engine

/*
Configures the router to load HTML templates
Sets the lower memory limit
Initializes the routes for the router
Hard codes the port for hosting
*/
func main() {
	gin.SetMode(gin.ReleaseMode)
	router = gin.Default()
	router.Static("/static", "./static")
	router.LoadHTMLGlob("templates/*")
	router.MaxMultipartMemory = 8 << 20
	initializeRoutes()
	router.Run(":5000")
}

func render(c *gin.Context, data gin.H, templateName string) {
	switch c.Request.Header.Get("Accept") {
	case "application/json":
		// Respond with JSON
		c.JSON(http.StatusOK, data["payload"])
	case "application/xml":
		// Respond with XML
		c.XML(http.StatusOK, data["payload"])
	default:
		// Respond with HTML
		c.HTML(http.StatusOK, templateName, data)
	}
}

// routes.go

/*
Initializes the routes for the entire project
*/
func initializeRoutes() {

	// Use the setUserStatus middleware for every route to set a flag
	// indicating whether the request was from an authenticated user or not
	router.Use(setUserStatus())

	// Handle the index route
	router.GET("/", ensureNotLoggedIn(), showLoginPage)

	// Group user related routes together
	userRoutes := router.Group("/u")
	{
		// Handle the GET requests at /u/login, ensure user is not logged in using middleware
		// Render the login page
		userRoutes.GET("/login", ensureNotLoggedIn(), showLoginPage)

		// Handle POST requests at /u/login, ensure user is not logged in using middleware
		// Login the user
		userRoutes.POST("/login", ensureNotLoggedIn(), performLogin)

		// Handle GET requests at /u/logout, ensure user is logged in using middleware
		// Logout the user
		userRoutes.GET("/logout", ensureLoggedIn(), logout)

		// Handle GET requests at /u/logout, ensure user is logged in using middleware
		// Display the logout modal
		userRoutes.GET("/logout_modal", ensureLoggedIn(), display_logout_modal)

		// Handle GET requests at /u/add_layer_modal, ensure user is logged in using middleware
		// Display the add layer modal
		userRoutes.GET("/add_layer_modal", ensureLoggedIn(), display_add_layer_modal)

		// Handle POST requests at /u/add_layer, ensure user is logged in using middleware
		// Add the layer
		userRoutes.POST("/add_layer", ensureLoggedIn(), addLayer)

		// Handle POST requests at /u/view_layer, ensure user is logged in using middleware
		// Render the image to map
		userRoutes.POST("/view_layer", ensureLoggedIn(), viewLayer)

		// Handle GET requests at /u/register, ensure user is not logged in using middleware
		//Render the registration page
		userRoutes.GET("/register", ensureNotLoggedIn(), showRegistrationPage)

		// Handle POST requests at /u/register, ensure user is not logged in using middleware
		//Register the user
		userRoutes.POST("/register", ensureNotLoggedIn(), register)
	}
	// Handle GET requests at /map, ensure user is logged in using middleware
	// Render the index page
	router.GET("/map", ensureLoggedIn(), showMap)
}

// middle auth .go

/*
If a request comes from the user when not logged in, it will be aborted with an error
*/
func ensureLoggedIn() gin.HandlerFunc {
	return func(c *gin.Context) {
		loggedInInterface, _ := c.Get("is_logged_in")
		loggedIn := loggedInInterface.(bool)
		if !loggedIn {
			c.AbortWithStatus(http.StatusUnauthorized)
		}
	}
}

/*
If a request comes from the user when logged in, it will be aborted with an error
*/
func ensureNotLoggedIn() gin.HandlerFunc {
	return func(c *gin.Context) {
		loggedInInterface, _ := c.Get("is_logged_in")
		loggedIn := loggedInInterface.(bool)
		if loggedIn {
			c.AbortWithStatus(http.StatusUnauthorized)
		}
	}
}

/*
Sets whether the user is logged in with gin context
*/
func setUserStatus() gin.HandlerFunc {
	return func(c *gin.Context) {
		if token, err := c.Cookie("token"); err == nil || token != "" {
			c.Set("is_logged_in", true)
		} else {
			c.Set("is_logged_in", false)
		}
	}
}

// handlers.map.go

/*
Renders the index with updated layer values
*/
func showMap(c *gin.Context) {
	floors := getAllFloors()

	render(c, gin.H{
		"title":   "Map",
		"payload": floors,
	}, "index.html")
}

/*
Adds a layer with a layer name inputted from the user
Saves uploaded image to static/assets folder
Creates a new floor and adds it to the list of floors, calls showMap to render the map with updates
*/
func addLayer(c *gin.Context) {
	layer_name := c.PostForm("layer_name")

	file, err := c.FormFile("layer_image")
	if err != nil {
		log.Println(err)
	}

	err = c.SaveUploadedFile(file, "static/assets/"+file.Filename)
	if err != nil {
		log.Println(err)
	}

	createNewFloor(layer_name, "static/assets/"+file.Filename)
	showMap(c)
}

/*
Gets the proper floor from the list of floors based on its name
Renders the proper floor image onto the map
*/
func viewLayer(c *gin.Context) {
	name := c.PostForm("l_name")
	floors := getAllFloors()
	for i := 0; i < len(floors); i++ {
		if floors[i].Name == name {
			render(c, gin.H{
				"title":   "Map",
				"payload": floors,
				"Image":   "../" + floors[i].ImageFile,
			}, "index.html")
		}
	}
}

// user handlers .go

/*
Renders the login page
*/
func showLoginPage(c *gin.Context) {
	render(c, gin.H{
		"title": "Login",
	}, "login.html")
}

/*
Obtains user inputted username and password
Checks if the username/password combination is valid
If valid, setss token in a cookie
Renders successful login
If invalid, renders an error
*/
func performLogin(c *gin.Context) {
	username := c.PostForm("username")
	password := c.PostForm("password")

	if isUserValid(username, password) {
		token := generateSessionToken()
		c.SetCookie("token", token, 3600, "", "", false, true)
		c.Set("is_logged_in", true)

		render(c, gin.H{
			"title": "Successful Login"}, "login-successful.html")
	} else {
		c.HTML(http.StatusBadRequest, "login.html", gin.H{
			"ErrorTitle":   "Login Failed",
			"ErrorMessage": "Invalid credentials provided"})
	}
}

/*
Generates a random 16 character string as the session token
*/
func generateSessionToken() string {
	return strconv.FormatInt(rand.Int63(), 16)
}

/*
Renders the Logout Modal when the user presses the logout button
*/
func display_logout_modal(c *gin.Context) {
	c.HTML(http.StatusOK, "index.html", gin.H{
		"LogoutModal": "Logout Modal",
	})
}

/*
Renders the Add Layer Modal when the user presses the add layer button
*/
func display_add_layer_modal(c *gin.Context) {
	c.HTML(http.StatusOK, "index.html", gin.H{
		"AddLayerModal": "Add Layer Modal",
	})
}

/*
Clears the cookie and redirects to the home page
*/
func logout(c *gin.Context) {
	c.SetCookie("token", "", -1, "", "", false, true)
	c.Redirect(http.StatusTemporaryRedirect, "/")
}

/*
Renders the registration page
*/
func showRegistrationPage(c *gin.Context) {
	render(c, gin.H{
		"title": "Register"}, "register.html")
}

/*
Obtains user inputted username and password
If the user is properly created, set the token in a cookie
Log the user in by rendering successful login
If the user created is invalid, renders an error
*/
func register(c *gin.Context) {
	username := c.PostForm("username")
	password := c.PostForm("password")

	if _, err := registerNewUser(username, password); err == nil {
		token := generateSessionToken()
		c.SetCookie("token", token, 3600, "", "", false, true)
		c.Set("is_logged_in", true)

		render(c, gin.H{
			"title": "Successful Login"}, "login-successful.html")
	} else {
		c.HTML(http.StatusBadRequest, "register.html", gin.H{
			"ErrorTitle":   "Registration Failed",
			"ErrorMessage": err.Error()})
	}
}

// floor .go

/*
floor struct has a name and a file where its image is stored
*/
type floor struct {
	Name      string `json:"Name"`
	ImageFile string `json:"Devices"`
}

/*
List of floors
*/
var floorList = []floor{
	floor{Name: "Floor 1", ImageFile: "static/assets/floor1.png"},
	floor{Name: "Floor 2", ImageFile: "static/assets/floor2.png"},
}

/*
Return a list of all the floors
*/
func getAllFloors() []floor {
	return floorList
}

/*
Creates a new floor and adds it to the list
*/
func createNewFloor(name, file string) (*floor, error) {
	f := floor{Name: name, ImageFile: file}
	floorList = append(floorList, f)
	return &f, nil
}

// user .go

/*
user struct has a username and a password
*/
type user struct {
	Username string `json:"username"`
	Password string `json:"-"`
}

/*
List of users
*/
var userList = []user{
	user{Username: "user1", Password: "pass1"},
	user{Username: "user2", Password: "pass2"},
	user{Username: "user3", Password: "pass3"},
}

/*
Checks if the username and password combination is valid
*/
func isUserValid(username, password string) bool {
	for _, u := range userList {
		if u.Username == username && u.Password == password {
			return true
		}
	}
	return false
}

/*
Registers a new user with given username/password by adding to list
*/
func registerNewUser(username, password string) (*user, error) {
	if strings.TrimSpace(password) == "" {
		return nil, errors.New("The password can't be empty")
	} else if !isUsernameAvailable(username) {
		return nil, errors.New("The username isn't available")
	}

	u := user{Username: username, Password: password}
	userList = append(userList, u)

	return &u, nil
}

/*
Check if the inputted username is available
*/
func isUsernameAvailable(username string) bool {
	for _, u := range userList {
		if u.Username == username {
			return false
		}
	}
	return true
}
