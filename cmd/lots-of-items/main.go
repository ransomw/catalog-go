package main

import (
	"fmt"

	"sand/go-catalog/model"
)

func main() {
	fmt.Println("hey")
	err := model.LotsOfItems()
	fmt.Println("ran LotsOfItems")
	if err == nil {
		fmt.Println("created db")
	} else {
		fmt.Printf("error creating db: %v\n", err)
	}
}
