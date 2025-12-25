package routes

import (
	_ "github.com/KuramaSyu/WerSu-Rest/docs" // load docs
	"github.com/KuramaSyu/WerSu-Rest/src/controllers"
	"github.com/gin-gonic/gin"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
)

// SetupRouter configures all application routes
func SetupRouter(
	r *gin.Engine,
	authController *controllers.AuthController,
	noteController *controllers.NoteController,
) {

	// API routes
	api := r.Group("/api")
	{
		// Test route
		api.GET("/ping", func(c *gin.Context) {
			c.JSON(200, gin.H{"message": "pong"})
		})

		// route for swagger API docs
		api.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

		// Note routes
		notes := api.Group("/notes")
		{
			notes.GET("/:id", noteController.GetNote)
		}
	}

	// Auth routes
	auth := api.Group("/auth")
	{
		auth.GET("/discord", authController.Login)
		auth.GET("/discord/callback", authController.Callback)
		auth.GET("/user", authController.GetUser)
		auth.GET("/logout", authController.Logout)
	}
}
