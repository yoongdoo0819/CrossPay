package router
  
import (
	"github.com/gin-gonic/gin"
	"github.com/sslab-instapay/instapay-tee-server/controller"
)

func RegisterRestRouter(router *gin.Engine) {

	PaymentRequestRouter := router.Group("payments")
	{
		PaymentRequestRouter.POST("server", controller.PaymentToServerChannelHandler)
	}

}

