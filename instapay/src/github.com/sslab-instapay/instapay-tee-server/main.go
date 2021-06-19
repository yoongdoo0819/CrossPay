package main


//#cgo CPPFLAGS: -I/home/yoongdoo0819/sgxsdk/include -I/home/yoongdoo0819/instapay3.0/instapay/src/github.com/sslab-instapay/instapay-tee-server
//#cgo LDFLAGS: -L/home/yoongdoo0819/instapay3.0/instapay/src/github.com/sslab-instapay/instapay-tee-server -ltee

//#cgo CFLAGS: -I /home/yoongdoo0819/instapay3.0/instapay/src/github.com/sslab-instapay/instapay-tee-server 

//#include "app.h"
//#include "secp256k1.h"



import "C"

import (
	"fmt"
	"flag"
	"os"
	"github.com/gin-gonic/gin"
	"github.com/sslab-instapay/instapay-tee-server/router"
	"github.com/sslab-instapay/instapay-tee-server/config"
	serverGrpc "github.com/sslab-instapay/instapay-tee-server/grpc"


	//"sync"
	"sync/atomic"
	"time"
	//"github.com/panjf2000/ants"
)

var sum int32

func myFunc(i interface{}) {
	n := i.(int32)
	atomic.AddInt32(&sum, n)
	fmt.Printf("run with %d\n", n)
}

func demoFunc() {
	time.Sleep(10 * time.Millisecond)
	fmt.Println("Hello World!")
}

func StartWebServer() {
	defaultRouter := gin.Default()
	//fmt.Println(gin.Default())
	defaultRouter.LoadHTMLGlob("templates/*")

	router.RegisterViewRouter(defaultRouter)
	router.RegisterRestRouter(defaultRouter)
	defaultRouter.Run(":" + os.Getenv("port"))
}

func main() {
/*
	defer ants.Release()

	runTimes := 1000

	// Use the common pool.
	var wg sync.WaitGroup
	syncCalculateSum := func() {
		demoFunc()
		wg.Done()
	}
	for i := 0; i < runTimes; i++ {
		wg.Add(1)
		_ = ants.Submit(syncCalculateSum)
	}
	wg.Wait()
	fmt.Printf("running goroutines: %d\n", ants.Running())
	fmt.Printf("finish all tasks.\n")

	// Use the pool with a function,
	// set 10 to the capacity of goroutine pool and 1 second for expired duration.
	p, _ := ants.NewPoolWithFunc(10, func(i interface{}) {
		myFunc(i)
		wg.Done()
	})
	defer p.Release()
	// Submit tasks one by one.
	for i := 0; i < runTimes; i++ {
		wg.Add(1)
		_ = p.Invoke(int32(i))
	}
	wg.Wait()
	fmt.Printf("running goroutines: %d\n", p.Running())
	fmt.Printf("finish all tasks, result is %d\n", sum)

	time.Sleep(100)
*/


	portNum := flag.String("port", "3004", "port number")
	grpcPortNum := flag.String("grpc_port", "50001", "grpc_port number")
	flag.Parse()

	os.Setenv("port", *portNum)
	os.Setenv("grpc_port", *grpcPortNum)

	//C.initialize_enclave()

	config.GetContract()
	go serverGrpc.StartGrpcServer()

	StartWebServer()
}
