package main

import (
	"log"
	"wd_auth/service"
	"wd_auth/store/postgres"

	"go.uber.org/zap"
)

func main() {
	l, err := zap.NewProduction()
	if err != nil {
		log.Fatal(err)
	}
	// l, err := zap.NewProduction() //set up logger first
	// if err != nil {
	// 	log.Fatal(err)
	// }

	l = l.Named("wd_authService")

	pg, err := postgres.New()
	if err != nil {
		l.Fatal("cannot connect to the database", zap.Error(err)) //log.fatal doesn't have to return, you need to fix this error, to return service and error
		//zap.Error is going to print out error as, "Error" as json key, and actual err for json value.
		//every zap.(something), if you hover that function, it's going to ask you to set the json key and the value.
		//e.g. zap.String() takes in two values, one is gonna be a key, the other a value.
	}

	svc := service.New(pg, l)

	svc.Run()
}
