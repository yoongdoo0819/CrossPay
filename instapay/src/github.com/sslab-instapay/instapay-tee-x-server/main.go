package main

/*
#cgo CPPFLAGS: -I/home/yoongdoo0819/sgxsdk/include -I/home/yoongdoo0819/instapay3.0/instapay/src/github.com/sslab-instapay/instapay-tee-x-server
#cgo LDFLAGS: -L/home/yoongdoo0819/instapay3.0/instapay/src/github.com/sslab-instapay/instapay-tee-x-server -ltee

#include "app.h"
*/
import "C"

import (
	//"fmt"
	"flag"
	"os"
	"github.com/gin-gonic/gin"
	"github.com/sslab-instapay/instapay-tee-x-server/router"
	"github.com/sslab-instapay/instapay-tee-x-server/config"
	serverGrpc "github.com/sslab-instapay/instapay-tee-x-server/grpc"
)

func StartWebServer() {
	defaultRouter := gin.Default()
	//fmt.Println(gin.Default())
	defaultRouter.LoadHTMLGlob("templates/*")

	router.RegisterViewRouter(defaultRouter)
	defaultRouter.Run(":" + os.Getenv("port"))
}

func main() {
	portNum := flag.String("port", "3004", "port number")
	grpcPortNum := flag.String("grpc_port", "50001", "grpc_port number")
	flag.Parse()

	os.Setenv("port", *portNum)
	os.Setenv("grpc_port", *grpcPortNum)

	C.initialize_enclave()

	config.GetContract()
	go serverGrpc.StartGrpcServer()

	StartWebServer()
}