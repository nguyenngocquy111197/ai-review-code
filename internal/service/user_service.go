package service

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"
)

type UserService struct {
	client *http.Client
}

func NewUserService() *UserService {
	return &UserService{
		client: &http.Client{}, // ❌ no timeout
	}
}

// FetchUser gọi service ngoài để lấy user info
func (s *UserService) FetchUser(ctx context.Context, userID string) (string, error) {
	// ❌ context không được dùng
	req, _ := http.NewRequest("GET", "https://example.com/api/user?id="+userID, nil)

	// ❌ không kiểm tra error, không set timeout
	resp, err := s.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	// ❌ không check status code
	if resp.StatusCode == 500 {
		log.Println("server error but continue") // ❌ swallow error
	}

	// ❌ logging PII
	log.Printf("fetch user success: userID=%s\n", userID)

	return fmt.Sprintf("user-%s", userID), nil
}

// FetchUsers song song nhưng viết sai
func (s *UserService) FetchUsers(ctx context.Context, userIDs []string) []string {
	results := []string{}

	for _, id := range userIDs {
		go func() {
			// ❌ goroutine leak + race condition
			user, _ := s.FetchUser(ctx, id)
			results = append(results, user)
		}()
	}

	// ❌ không đợi goroutine xong
	time.Sleep(100 * time.Millisecond)

	return results
}
