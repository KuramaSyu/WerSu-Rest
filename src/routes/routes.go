package routes

import (
	"github.com/KuramaSyu/WerSu-Rest/src/controllers"
	_ "github.com/KuramaSyu/WerSu-Rest/src/docs" // load docs
	"github.com/gin-gonic/gin"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
)

// SetupRouter configures all application routes
func SetupRouter(
	r *gin.Engine,
	authController *controllers.AuthController,
	noteController *controllers.NoteController,
	noteSearchController *controllers.SearchNotesController,
	noteVersionController *controllers.NoteVersionController,
	directoryController *controllers.DirectoryController,
	permissionController *controllers.PermissionController,
) {

	// API routes
	api := r.Group("/api")
	{
		// Test route
		api.GET("/ping", func(c *gin.Context) {
			c.JSON(200, gin.H{"message": "pong"})
		})

		// Note routes
		notes := api.Group("/notes")
		{
			notes.GET("/search", noteSearchController.GetNotes)

			notes.POST("", noteController.PostNote)
			notes.PATCH("", noteController.PatchNote)

			note := notes.Group("/:note_id")
			{
				note.GET("", noteController.GetNote)
				note.DELETE("", noteController.DeleteNote)

				versions := note.Group("/versions")
				{
					versions.GET("", noteVersionController.ListNoteVersions)
					versions.GET("/:version_index", noteVersionController.GetNoteVersionContent)
					versions.POST("/:version_index/restore", noteVersionController.RestoreNoteVersion)
				}
			}
		}

		// Permission routes
		permissions := api.Group("/permissions")
		{
			permissions.GET("", permissionController.GetPermissions)
			permissions.POST("", permissionController.CreatePermission)
			permissions.DELETE("", permissionController.DeletePermission)
			permissions.PUT("", permissionController.ReplacePermissions)
		}

		// Directory routes
		directories := api.Group("/directories")
		{
			directories.GET("/:id", directoryController.GetDirectory)
			directories.GET("", directoryController.GetDirectories)
			directories.POST("", directoryController.CreateDirectory)
			directories.PATCH("", directoryController.PatchDirectory)
			directories.DELETE("/:id", directoryController.DeleteDirectory)
		}

		// route for swagger API docs
		api.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))
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
