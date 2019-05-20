package model

import (
	"time"
	"path/filepath"
	"strconv"

	// relies on github.com/mattn/go-sqlite3
	_ "github.com/jinzhu/gorm/dialects/sqlite"
	"github.com/jinzhu/gorm"
)

const (
	ItemImageDir = "imgs"
)

type User struct {
	gorm.Model
	Name string
	Email string
	Password string
}

type Category struct {
	gorm.Model
	Name string
	Items []Item
}

type Item struct {
	gorm.Model
	Title string
	Description string
	CategoryID uint
	Category Category
	LastUpdate *time.Time
}

// todo: gorm-imageattach (prior art: sqlalchemy-imageattach)
func (i *Item) GetImageFilepath() string {
	return filepath.Join(ItemImageDir, strconv.Itoa(int(i.ID)))
}

func ConnDB() (*gorm.DB, error) {
	db, err := gorm.Open("sqlite3", "test.db")
	if err != nil {
		return nil, err
	}
	db.AutoMigrate(&User{})
	db.AutoMigrate(&Category{})
	db.AutoMigrate(&Item{})
	return db, nil
}

func LotsOfItems() error {
	db, err := ConnDB()
	if err != nil {
		return err
	}

	defer db.Close()

	categorySoccer := Category{Name: "Soccer"}
	categoryBasketball := Category{Name: "Basketball"}
	categoryBaseball := Category{Name: "Baseball"}
	categoryFrisbee := Category{Name: "Frisbee"}
	categorySnowboarding := Category{Name: "Snowboarding"}
	categoryRockClimbing := Category{Name: "Rock Climbing"}
	categoryFoosball := Category{Name: "Foosball"}
	categorySkating := Category{Name: "Skating"}
	categoryHockey := Category{Name: "Hockey"}

	db.Create(&categorySoccer)
	db.Create(&categoryBasketball)
	db.Create(&categoryBaseball)
	db.Create(&categoryFrisbee)
	db.Create(&categorySnowboarding)
	db.Create(&categoryRockClimbing)
	db.Create(&categoryFoosball)
	db.Create(&categorySkating)
	db.Create(&categoryHockey)

	var item Item

	item = Item{
		Title: "Stick",
		Description: "A hockey stick",
		CategoryID: categoryHockey.ID}
	db.Create(&item)

	item = Item{
		Title: "Goggles",
		Description: "Keep the snow out of your eyes",
		CategoryID: categorySnowboarding.ID}
	db.Create(&item)

	item = Item{
		Title: "Snowboard",
		Description: "Type-A vintage",
		CategoryID: categorySnowboarding.ID}
	db.Create(&item)

	item = Item{
		Title: "Two shinguards",
		Description: "Prevent injuries resulting from kicks to the shin",
		CategoryID: categorySoccer.ID}
	db.Create(&item)

	item = Item{
		Title: "Shinguards",
		Description: "Prevent injuries resulting from kicks to the shin",
		CategoryID: categorySoccer.ID}
	db.Create(&item)

	item = Item{
		Title: "Frisbee",
		Description: "A flying disc",
		CategoryID: categoryFrisbee.ID}
	db.Create(&item)

	item = Item{
		Title: "Bat",
		Description: "Louisville slugger",
		CategoryID: categoryBaseball.ID}
	db.Create(&item)

	item = Item{
		Title: "Jersey",
		Description: "World Cup 2014 commemorative jersy",
		CategoryID: categorySoccer.ID}
	db.Create(&item)

	item = Item{
		Title: "Soccer Cleats",
		Description: "Nike cleats",
		CategoryID: categorySoccer.ID}
	db.Create(&item)

	return nil
}

// todo: sqlite <-> json dumps
//   that is, read a file into the db and write the db as a file
