package utils

import (
	"context"
	"log"

	v1 "github.com/authzed/authzed-go/proto/authzed/api/v1"
	"github.com/authzed/authzed-go/v1"
)

// Helper function to call SpiceDB with format resource:id#permission@subjectType:subjectId
func HasPermission(client *authzed.Client, resourceType, resourceID, permission, subjectType, subjectID string) (bool, error) {
	log.Printf("resourceType=%q resourceID=%q", resourceType, resourceID)
	resp, err := client.CheckPermission(
		context.Background(),
		&v1.CheckPermissionRequest{
			Resource: &v1.ObjectReference{
				ObjectType: resourceType,
				ObjectId:   resourceID,
			},
			Permission: permission,
			Subject: &v1.SubjectReference{
				Object: &v1.ObjectReference{
					ObjectType: subjectType,
					ObjectId:   subjectID,
				},
			},
		},
	)
	if err != nil {
		return false, err
	}
	return resp.Permissionship == v1.CheckPermissionResponse_PERMISSIONSHIP_HAS_PERMISSION, nil
}
