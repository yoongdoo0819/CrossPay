package router

import (
	"github.com/gin-gonic/gin"
	"github.com/sslab-instapay/instapay-tee-x-server/controller"
)

func RegisterRestRouter(router *gin.Engine) {

	xPaymentRequestRouter := router.Group("cross-payments")
	{
		xPaymentRequestRouter.POST("cross-server", controller.CrossPaymentToServerChannelHandler)
	}

}

