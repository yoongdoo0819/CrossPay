package main

/*
#cgo CPPFLAGS: -I/home/xiao/sgxsdk/include -I/home/yoongdoo0819/instapay3.0/instapay/src/github.com/sslab-instapay/instapay-tee-server
#cgo LDFLAGS: -L/home/yoongdoo0819/instapay3.0/instapay/src/github.com/sslab-instapay/instapay-tee-server -ltee

#include "app.h"
*/

import "C"

import (
	"flag"
	"os"
	"github.com/gin-gonic/gin"
	"github.com/sslab-instapay/instapay-tee-server/router"
	"github.com/sslab-instapay/instapay-tee-server/config"
	serverGrpc "github.com/sslab-instapay/instapay-tee-server/grpc"
)

func StartWebServer() {
	defaultRouter := gin.Default()
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

	fPrintln("asdfasdf");
	config.GetContract()
	go serverGrpc.StartGrpcServer()

	StartWebServer()
}
