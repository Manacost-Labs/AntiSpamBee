package telegramapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"testing"

	"antispambee/internal/detection"
)

func TestClientFetchProfileIncludesPersonalChannelPosts(t *testing.T) {
	requests := []string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.URL.Path)
		var body struct {
			ChatID int64 `json:"chat_id"`
			UserID int64 `json:"user_id"`
			Limit  int   `json:"limit"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode request: %v", err)
		}

		switch {
		case r.URL.Path == "/botsecret/getChat" && body.ChatID == 8373323792:
			_, _ = w.Write([]byte(`{"ok":true,"result":{"id":8373323792,"type":"private","username":"Kristinana04Alekseeva","bio":"Добрая, но не для всех","personal_chat":{"id":-1009001,"type":"channel","title":"И там и здесь","username":"job_offer"}}}`))
		case r.URL.Path == "/botsecret/getChat" && body.ChatID == -1009001:
			_, _ = w.Write([]byte(`{"ok":true,"result":{"id":-1009001,"type":"channel","title":"И там и здесь","username":"job_offer","description":"Нужны сотрудники на частичную занятость"}}`))
		case r.URL.Path == "/botsecret/getUserPersonalChatMessages" && body.UserID == 8373323792 && body.Limit == 5:
			_, _ = w.Write([]byte(`{"ok":true,"result":[{"message_id":1,"text":"Пишите в личку"},{"message_id":2,"caption":"Свободный график"}]}`))
		default:
			http.Error(w, "unexpected request", http.StatusBadRequest)
		}
	}))
	defer server.Close()

	client, err := NewClient(ClientConfig{
		Token:      "secret",
		BaseURL:    server.URL,
		HTTPClient: server.Client(),
	})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	profile, err := client.FetchProfile(context.Background(), 8373323792)
	if err != nil {
		t.Fatalf("FetchProfile() error = %v", err)
	}

	want := detection.Profile{
		Username: "Kristinana04Alekseeva",
		Bio:      "Добрая, но не для всех",
		PersonalChannel: &detection.PersonalChannel{
			Title:       "И там и здесь",
			Username:    "job_offer",
			Description: "Нужны сотрудники на частичную занятость",
			RecentPosts: []string{"Пишите в личку", "Свободный график"},
		},
	}
	if !reflect.DeepEqual(profile, want) {
		t.Fatalf("profile = %#v, want %#v", profile, want)
	}
	if len(requests) != 3 {
		t.Fatalf("requests = %v, want 3 requests", requests)
	}
}

func TestClientFetchProfileStopsWithoutPersonalChannel(t *testing.T) {
	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requestCount++
		_, _ = w.Write([]byte(`{"ok":true,"result":{"id":42,"type":"private","username":"ordinary_user"}}`))
	}))
	defer server.Close()

	client, err := NewClient(ClientConfig{Token: "secret", BaseURL: server.URL, HTTPClient: server.Client()})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	profile, err := client.FetchProfile(context.Background(), 42)
	if err != nil {
		t.Fatalf("FetchProfile() error = %v", err)
	}

	if profile.PersonalChannel != nil {
		t.Fatalf("personal channel = %#v, want nil", profile.PersonalChannel)
	}
	if requestCount != 1 {
		t.Fatalf("request count = %d, want 1", requestCount)
	}
}

func TestClientFetchProfileReturnsTelegramError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"ok":false,"error_code":400,"description":"Bad Request: chat not found"}`))
	}))
	defer server.Close()

	client, err := NewClient(ClientConfig{Token: "secret", BaseURL: server.URL, HTTPClient: server.Client()})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	if _, err := client.FetchProfile(context.Background(), 42); err == nil {
		t.Fatal("FetchProfile() succeeded, want Telegram API error")
	}
}

func TestClientBanChatMember(t *testing.T) {
	var requestBody struct {
		ChatID int64 `json:"chat_id"`
		UserID int64 `json:"user_id"`
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/botsecret/banChatMember" {
			t.Fatalf("path = %q, want banChatMember", r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&requestBody); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		_, _ = w.Write([]byte(`{"ok":true,"result":true}`))
	}))
	defer server.Close()

	client, err := NewClient(ClientConfig{Token: "secret", BaseURL: server.URL, HTTPClient: server.Client()})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	if err := client.BanChatMember(context.Background(), -100777, 42); err != nil {
		t.Fatalf("BanChatMember() error = %v", err)
	}

	if requestBody.ChatID != -100777 || requestBody.UserID != 42 {
		t.Fatalf("request body = %#v", requestBody)
	}
}

func TestClientUnbanChatMember(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/botsecret/unbanChatMember" {
			t.Fatalf("path = %q", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"ok":true,"result":true}`))
	}))
	defer server.Close()
	client, err := NewClient(ClientConfig{Token: "secret", BaseURL: server.URL, HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.UnbanChatMember(context.Background(), -100777, 42); err != nil {
		t.Fatalf("UnbanChatMember() error = %v", err)
	}
}

func TestClientDeleteMessage(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/botsecret/deleteMessage" {
			t.Fatalf("path = %q", r.URL.Path)
		}
		var request struct {
			ChatID    int64 `json:"chat_id"`
			MessageID int64 `json:"message_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatal(err)
		}
		if request.ChatID != -100123 || request.MessageID != 77 {
			t.Fatalf("request = %#v", request)
		}
		_, _ = w.Write([]byte(`{"ok":true,"result":true}`))
	}))
	defer server.Close()

	client, err := NewClient(ClientConfig{Token: "secret", BaseURL: server.URL, HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.DeleteMessage(context.Background(), -100123, 77); err != nil {
		t.Fatalf("DeleteMessage() error = %v", err)
	}
}

func TestClientDeleteMessageReaction(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/botsecret/deleteMessageReaction" {
			t.Fatalf("path = %q", r.URL.Path)
		}
		var request struct {
			ChatID    int64 `json:"chat_id"`
			MessageID int64 `json:"message_id"`
			UserID    int64 `json:"user_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatal(err)
		}
		if request.ChatID != -100123 || request.MessageID != 77 || request.UserID != 42 {
			t.Fatalf("request = %#v", request)
		}
		_, _ = w.Write([]byte(`{"ok":true,"result":true}`))
	}))
	defer server.Close()

	client, err := NewClient(ClientConfig{Token: "secret", BaseURL: server.URL, HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.DeleteMessageReaction(context.Background(), -100123, 77, 42); err != nil {
		t.Fatalf("DeleteMessageReaction() error = %v", err)
	}
}

func TestClientGetChatMemberStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/botsecret/getChatMember" {
			t.Fatalf("path = %q", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"ok":true,"result":{"status":"administrator","user":{"id":42,"is_bot":false,"first_name":"A"}}}`))
	}))
	defer server.Close()

	client, err := NewClient(ClientConfig{Token: "secret", BaseURL: server.URL, HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	status, err := client.GetChatMemberStatus(context.Background(), -100123, 42)
	if err != nil {
		t.Fatalf("GetChatMemberStatus() error = %v", err)
	}
	if status != "administrator" {
		t.Fatalf("status = %q", status)
	}
}

func TestClientRestrictChatMember(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/botsecret/restrictChatMember" {
			t.Fatalf("path = %q", r.URL.Path)
		}
		var request struct {
			ChatID      int64 `json:"chat_id"`
			UserID      int64 `json:"user_id"`
			UntilDate   int64 `json:"until_date"`
			Permissions struct {
				CanSendMessages bool `json:"can_send_messages"`
			} `json:"permissions"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatal(err)
		}
		if request.ChatID != -100123 || request.UserID != 42 || request.UntilDate != 4102444800 || request.Permissions.CanSendMessages {
			t.Fatalf("request = %#v", request)
		}
		_, _ = w.Write([]byte(`{"ok":true,"result":true}`))
	}))
	defer server.Close()
	client, err := NewClient(ClientConfig{Token: "secret", BaseURL: server.URL, HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.RestrictChatMember(context.Background(), -100123, 42, 4102444800); err != nil {
		t.Fatalf("RestrictChatMember() error = %v", err)
	}
}

func TestClientSendMessage(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/botsecret/sendMessage" {
			t.Fatalf("path = %q", r.URL.Path)
		}
		var request struct {
			ChatID int64  `json:"chat_id"`
			Text   string `json:"text"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatal(err)
		}
		if request.ChatID != -100123 || request.Text != "готово" {
			t.Fatalf("request = %#v", request)
		}
		_, _ = w.Write([]byte(`{"ok":true,"result":{"message_id":1,"date":1,"chat":{"id":-100123,"type":"supergroup"},"text":"готово"}}`))
	}))
	defer server.Close()
	client, err := NewClient(ClientConfig{Token: "secret", BaseURL: server.URL, HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.SendMessage(context.Background(), -100123, "готово"); err != nil {
		t.Fatalf("SendMessage() error = %v", err)
	}
}

func TestClientGetBotUsername(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/botsecret/getMe" {
			t.Fatalf("path = %q", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"ok":true,"result":{"id":123,"is_bot":true,"first_name":"AntiSpamBee","username":"AntiSpamBeeBot"}}`))
	}))
	defer server.Close()
	client, err := NewClient(ClientConfig{Token: "secret", BaseURL: server.URL, HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	username, err := client.GetBotUsername(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if username != "AntiSpamBeeBot" {
		t.Fatalf("username = %q", username)
	}
}

func TestClientSendMessageWithURLButton(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/botsecret/sendMessage" {
			t.Fatalf("path = %q", r.URL.Path)
		}
		var request struct {
			ChatID      int64  `json:"chat_id"`
			Text        string `json:"text"`
			ReplyMarkup struct {
				InlineKeyboard [][]struct {
					Text string `json:"text"`
					URL  string `json:"url"`
				} `json:"inline_keyboard"`
			} `json:"reply_markup"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatal(err)
		}
		button := request.ReplyMarkup.InlineKeyboard[0][0]
		if request.ChatID != 123 || request.Text != "Помощь" || button.Text != "Добавить в группу" || button.URL != "https://t.me/AntiSpamBeeBot?startgroup=setup&admin=delete_messages+restrict_members" {
			t.Fatalf("request = %#v, button = %#v", request, button)
		}
		_, _ = w.Write([]byte(`{"ok":true,"result":{"message_id":1}}`))
	}))
	defer server.Close()
	client, err := NewClient(ClientConfig{Token: "secret", BaseURL: server.URL, HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.SendMessageWithURLButton(
		context.Background(), 123, "Помощь", "Добавить в группу",
		"https://t.me/AntiSpamBeeBot?startgroup=setup&admin=delete_messages+restrict_members",
	); err != nil {
		t.Fatal(err)
	}
}

func TestClientSetWebhookIncludesReactionUpdates(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/botsecret/setWebhook" {
			t.Fatalf("path = %q", r.URL.Path)
		}
		var request struct {
			URL            string   `json:"url"`
			SecretToken    string   `json:"secret_token"`
			AllowedUpdates []string `json:"allowed_updates"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatal(err)
		}
		if request.URL != "https://bot.example/webhook" || request.SecretToken != "webhook-secret" || !slices.Contains(request.AllowedUpdates, "message_reaction") {
			t.Fatalf("request = %#v", request)
		}
		_, _ = w.Write([]byte(`{"ok":true,"result":true}`))
	}))
	defer server.Close()
	client, err := NewClient(ClientConfig{Token: "secret", BaseURL: server.URL, HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.SetWebhook(context.Background(), "https://bot.example/webhook", "webhook-secret"); err != nil {
		t.Fatalf("SetWebhook() error = %v", err)
	}
}

func TestClientSetMyCommands(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/botsecret/setMyCommands" {
			t.Fatalf("path = %q", r.URL.Path)
		}
		var request struct {
			Commands []BotCommand `json:"commands"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(request.Commands, []BotCommand{{Command: "help", Description: "Справочник"}}) {
			t.Fatalf("commands = %#v", request.Commands)
		}
		_, _ = w.Write([]byte(`{"ok":true,"result":true}`))
	}))
	defer server.Close()
	client, err := NewClient(ClientConfig{Token: "secret", BaseURL: server.URL, HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.SetMyCommands(context.Background(), []BotCommand{{Command: "help", Description: "Справочник"}}); err != nil {
		t.Fatal(err)
	}
}
