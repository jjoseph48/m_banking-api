package main

import "time"

type User struct {
	ID        uint   `gorm:"primaryKey"`
	Username  string `gorm:"unique;not null"`
	Email     string `gorm:"unique, not null"`
	Password  string `gorm:"not null"`
	CreatedAt time.Time
	UpdatedAt time.Time
	Photos    []Photo `gorm:"foreignKey:UserID;constraint:OnDelete:CASCADE;"`
}

type Photo struct {
	ID       uint `gorm:"primaryKey"`
	Title    string
	Caption  string
	PhotoUrl string
	UserID   uint
	User     User `gorm:"constraint:OnDelete:CASCADE;"`
}
