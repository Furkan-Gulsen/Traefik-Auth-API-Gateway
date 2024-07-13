package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt"
	"github.com/joho/godotenv"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
)

var (
	client      *mongo.Client
	redisClient *redis.Client
	jwtKey      []byte
	mongodbURL  string
	redisAddr   string
	port        string
	mongodbDB   = "auth"
	usersColl   = "users"
)

type User struct {
	Email    string `json:"email" bson:"email"`
	Password string `json:"password" bson:"password"`
}

func init() {
	godotenv.Load()

	jwtKey = []byte(os.Getenv("JWT_KEY"))
	if len(jwtKey) == 0 {
		log.Fatal("JWT_KEY environment variable not set")
	}

	mongodbURL = os.Getenv("MONGODB_URL")
	if mongodbURL == "" {
		log.Fatal("MONGODB_URL environment variable not set")
	}

	redisAddr = os.Getenv("REDIS_ADDR")
	if redisAddr == "" {
		log.Fatal("REDIS_ADDR environment variable not set")
	}

	port = os.Getenv("PORT")
	if port == "" {
		log.Fatal("PORT environment variable not set")
	}
}

func connectToMongoDB() error {
	clientOptions := options.Client().ApplyURI(mongodbURL)

	var err error
	client, err = mongo.Connect(context.Background(), clientOptions)
	if err != nil {
		return err
	}

	err = client.Ping(context.Background(), nil)
	if err != nil {
		return err
	}

	fmt.Println("Connected to MongoDB!")
	return nil
}

func connectToRedis() error {
	redisClient = redis.NewClient(&redis.Options{
		Addr: redisAddr,
	})

	_, err := redisClient.Ping(context.Background()).Result()
	if err != nil {
		return err
	}

	fmt.Println("Connected to Redis!")
	return nil
}

func closeMongoDBConnection() {
	err := client.Disconnect(context.Background())
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Connection to MongoDB closed.")
}

func closeRedisConnection() {
	err := redisClient.Close()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Connection to Redis closed.")
}

func registerHandler(c *fiber.Ctx) error {
	user := new(User)
	if err := c.BodyParser(user); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "Bad Request"})
	}

	// check if user already exists
	collection := client.Database(mongodbDB).Collection(usersColl)
	result := collection.FindOne(context.Background(), bson.M{"email": user.Email})
	if result.Err() == nil {
		return c.Status(http.StatusConflict).JSON(fiber.Map{"error": "Conflict - User already exists"})
	}

	// hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to hash password"})
	}

	// insert user into MongoDB
	user.Password = string(hashedPassword)
	_, err = collection.InsertOne(context.Background(), user)
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to insert user"})
	}

	return c.Status(http.StatusCreated).JSON(fiber.Map{"message": "User registered successfully"})
}

func loginHandler(c *fiber.Ctx) error {
	user := new(User)
	if err := c.BodyParser(user); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "Bad Request"})
	}

	// check if user exists in MongoDB
	collection := client.Database(mongodbDB).Collection(usersColl)
	result := collection.FindOne(context.Background(), bson.M{"email": user.Email})
	if result.Err() != nil {
		return c.Status(http.StatusUnauthorized).JSON(fiber.Map{"error": "User not found"})
	}

	// decode stored password hash
	storedUser := new(User)
	err := result.Decode(storedUser)
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to decode user"})
	}

	// compare the stored hashed password with the input password
	err = bcrypt.CompareHashAndPassword([]byte(storedUser.Password), []byte(user.Password))
	if err != nil {
		return c.Status(http.StatusUnauthorized).JSON(fiber.Map{"error": "Incorrect password"})
	}

	// generate JWT token
	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)
	claims["email"] = user.Email
	claims["exp"] = time.Now().Add(time.Minute * 15).Unix()

	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "Internal Server Error"})
	}

	// generate Refresh Token
	refreshToken := jwt.New(jwt.SigningMethodHS256)
	rtClaims := refreshToken.Claims.(jwt.MapClaims)
	rtClaims["email"] = user.Email
	rtClaims["exp"] = time.Now().Add(24 * time.Hour).Unix() // Refresh token expiry time

	refreshTokenString, err := refreshToken.SignedString(jwtKey)
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "Internal Server Error"})
	}

	// store Refresh Token in Redis
	err = redisClient.Set(context.Background(), user.Email+"_refresh", refreshTokenString, 24*time.Hour).Err()
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to store refresh token in Redis"})
	}

	// set access token and refresh token in cookies
	c.Cookie(&fiber.Cookie{
		Name:     "access_token",
		Value:    tokenString,
		Expires:  time.Now().Add(time.Minute * 15),
		HTTPOnly: true,
		Secure:   true,
	})

	c.Cookie(&fiber.Cookie{
		Name:     "refresh_token",
		Value:    refreshTokenString,
		Expires:  time.Now().Add(24 * time.Hour),
		HTTPOnly: true,
		Secure:   true,
	})

	return c.Status(http.StatusOK).JSON(fiber.Map{"message": "Logged in successfully"})
}

func validateHandler(c *fiber.Ctx) error {
	authHeader := c.Get("Authorization")
	if authHeader == "" {
		return c.Status(http.StatusUnauthorized).JSON(fiber.Map{"error": "Unauthorized"})
	}

	authHeaderParts := strings.Split(authHeader, " ")
	if len(authHeaderParts) != 2 || authHeaderParts[0] != "Bearer" {
		return c.Status(http.StatusUnauthorized).JSON(fiber.Map{"error": "Unauthorized"})
	}

	tokenString := authHeaderParts[1]

	// parse JWT token
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// check signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return jwtKey, nil
	})
	if err != nil {
		return c.Status(http.StatusUnauthorized).JSON(fiber.Map{"error": "Unauthorized"})
	}

	// validate token
	if !token.Valid {
		return c.Status(http.StatusUnauthorized).JSON(fiber.Map{"error": "Unauthorized"})
	}

	// extract claims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return c.Status(http.StatusUnauthorized).JSON(fiber.Map{"error": "Unauthorized"})
	}

	// get email from claims
	email, ok := claims["email"].(string)
	if !ok {
		return c.Status(http.StatusUnauthorized).JSON(fiber.Map{"error": "Unauthorized"})
	}

	// respond with OK
	return c.Status(http.StatusOK).JSON(fiber.Map{"email": email, "message": "OK"})
}

func refreshHandler(c *fiber.Ctx) error {
	refreshTokenCookie := c.Cookies("refresh_token")
	if refreshTokenCookie == "" {
		return c.Status(http.StatusUnauthorized).JSON(fiber.Map{"error": "Unauthorized"})
	}

	// parse Refresh JWT token
	refreshToken, err := jwt.Parse(refreshTokenCookie, func(token *jwt.Token) (interface{}, error) {
		// check signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return jwtKey, nil
	})
	if err != nil {
		return c.Status(http.StatusUnauthorized).JSON(fiber.Map{"error": "Unauthorized"})
	}

	// validate refresh token
	if !refreshToken.Valid {
		return c.Status(http.StatusUnauthorized).JSON(fiber.Map{"error": "Unauthorized"})
	}

	// extract claims
	rtClaims, ok := refreshToken.Claims.(jwt.MapClaims)
	if !ok {
		return c.Status(http.StatusUnauthorized).JSON(fiber.Map{"error": "Unauthorized"})
	}

	// get email from claims
	email, ok := rtClaims["email"].(string)
	if !ok {
		return c.Status(http.StatusUnauthorized).JSON(fiber.Map{"error": "Unauthorized"})
	}

	// check if refresh token exists in Redis
	storedRefreshToken, err := redisClient.Get(context.Background(), email+"_refresh").Result()
	if err != nil {
		if err == redis.Nil {
			return c.Status(http.StatusUnauthorized).JSON(fiber.Map{"error": "Unauthorized"})
		}
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to retrieve token"})
	}

	// check if stored refresh token matches the provided token
	if storedRefreshToken != refreshTokenCookie {
		return c.Status(http.StatusUnauthorized).JSON(fiber.Map{"error": "Unauthorized"})
	}

	// generate new access token
	newToken := jwt.New(jwt.SigningMethodHS256)
	newClaims := newToken.Claims.(jwt.MapClaims)
	newClaims["email"] = email
	newClaims["exp"] = time.Now().Add(time.Minute * 30).Unix()

	newTokenString, err := newToken.SignedString(jwtKey)
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "Internal Server Error"})
	}

	// set new access token in cookie
	c.Cookie(&fiber.Cookie{
		Name:     "access_token",
		Value:    newTokenString,
		Expires:  time.Now().Add(time.Minute * 30),
		HTTPOnly: true,
		Secure:   true,
	})

	return c.Status(http.StatusOK).JSON(fiber.Map{"message": "Access token refreshed"})
}

func main() {
	err := connectToMongoDB()
	if err != nil {
		log.Fatalf("Failed to connect to MongoDB: %v", err)
	}
	defer closeMongoDBConnection()

	err = connectToRedis()
	if err != nil {
		log.Fatalf("Failed to connect to Redis: %v", err)
	}
	defer closeRedisConnection()

	app := fiber.New()

	app.Post("/register", registerHandler)
	app.Post("/login", loginHandler)
	app.Get("/validate", validateHandler)
	app.Post("/refresh", refreshHandler)

	log.Fatal(app.Listen(":" + port))
}
