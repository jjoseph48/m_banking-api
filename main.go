package main

import (
	"log"

	"github.com/gin-gonic/gin"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

var (
	db *gorm.DB
)

func main() {
	dsn := "username:password@tcp(127.0.0.1:3307)/m_banking?charset=utf8mb4&paresTime=True&loc=Local"
	var err error
	db, err = gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatal("Failed to connect to database : ", err)
	}

	r := gin.Default()

	r.POST("/users/register", RegisterUser)
	r.POST("/users/login", LoginUser)
	r.PUT("/users/:userId", UpdateUser)
	r.DELETE("/users/:userId", DeleteUser)

	r.POST("/photos", CreatePhoto)
	r.GET("/photos", GetPhotos)
	r.PUT("/photos/:photoId", UpdatePhoto)
	r.DELETE("/photos/:photoId", DeletePhoto)

	r.Run(":8080")
}
