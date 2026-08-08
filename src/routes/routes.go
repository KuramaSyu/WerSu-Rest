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
	attachmentController *controllers.AttachmentController,
	attachmentLinkController *controllers.AttachmentLinkController,
	sharingController *controllers.SharingController,
	activityController *controllers.ActivityController,
	migrationController *controllers.ThirdpartyMigrationController,
	statusController *controllers.StatusController,
) {

	// API routes
	api := r.Group("/api")
	{
		// Test route
		api.GET("/ping", func(c *gin.Context) {
			c.JSON(200, gin.H{"message": "pong"})
		})

		// Service reachability status
		api.GET("/status", statusController.GetStatus)

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

		// Attachments
		attachments := api.Group("/attachments")
		{
			// ! don't use :key but query parameter since it handles the slashes in
			// the attachment path more reliably
			attachments.POST("", attachmentController.PostAttachment)
			attachments.GET("/", attachmentController.GetAttachment)
			attachments.GET("/image", attachmentController.GetImage)
			attachments.GET("/metadata/", attachmentController.GetAttachmentMetadata)
			attachments.PATCH("/metadata/", attachmentController.PatchAttachmentMetadata)
			attachments.DELETE("/", attachmentController.DeleteAttachment)

		}

		// attachment link routes
		attachmentLinks := api.Group("/attachment-links")
		{
			attachmentLinks.POST("", attachmentLinkController.PostAttachmentLink)
			attachmentLinks.DELETE("", attachmentLinkController.DeleteAttachmentLink)
		}

		// Directory routes
		directories := api.Group("/directories")
		{
			directories.GET("", directoryController.GetDirectories)
			directories.POST("", directoryController.CreateDirectory)
			directories.PATCH("", directoryController.PatchDirectory)
			directories.GET("/activity", noteVersionController.GetDirectoryActivity)

			directory := directories.Group("/:id")
			{
				directory.GET("", directoryController.GetDirectory)
				directory.DELETE("", directoryController.DeleteDirectory)
				directory.GET("/activity", noteVersionController.GetDirectoryActivity)
				directory.GET("/notes", directoryController.GetNotesOfDirectory)
			}
		}

		// share link routes
		shares := api.Group("/shares")
		{
			shares.POST("", sharingController.CreateShare)
			shares.GET("", sharingController.GetShares)
			shares.GET("/public/", sharingController.AccessShare)
			shares.DELETE("", sharingController.DeleteShares)
			shares.PATCH("", sharingController.UpdateShare)
		}

		// activity history routes
		api.GET("/history", activityController.GetActivityHistory)

		// third-party migrations
		migrations := api.Group("/migrations")
		{
			migrations.POST(
				"/import_bookstack_book",
				migrationController.ImportBookstackBook,
			)
		}

		// route for swagger API docs
		api.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))
	}

	// Auth routes
	auth := api.Group("/auth")
	{
		auth.GET("/access-token", authController.GetAccessToken)
		auth.POST("/public-access-token", authController.GetPublicAccessToken)

		// Discord OAuth
		auth.GET("/discord", authController.Login)
		auth.GET("/discord/callback", authController.Callback)

		// Google OAuth
		auth.GET("/google", authController.GoogleLogin)
		auth.GET("/google/callback", authController.GoogleCallback)

		// Password + passkey login (unified entry point)
		auth.POST("/login", authController.PostLogin)
		auth.POST("/signup", authController.PostSignup)

		// Passkey endpoints
		auth.POST("/passkey/register/begin", authController.PostPasskeyRegisterBegin)
		auth.POST("/passkey/register/finish", authController.PostPasskeyRegisterFinish)
		auth.POST("/passkey/login/begin", authController.PostPasskeyLoginBegin)
		auth.POST("/passkey/login/finish", authController.PostPasskeyLoginFinish)

		// Account linking (must be authenticated)
		auth.POST("/link/discord", authController.PostLinkDiscord)
		auth.POST("/link/google", authController.PostLinkGoogle)
		auth.POST("/link/password", authController.PostLinkPassword)
		auth.POST("/link/passkey/begin", authController.PostLinkPasskeyBegin)
		auth.POST("/link/passkey/finish", authController.PostLinkPasskeyFinish)

		// Linked-credentials summary
		auth.GET("/me/credentials", authController.GetLinkedCredentials)

		auth.GET("/user", authController.GetUser)
		auth.GET("/logout", authController.Logout)
	}
}
