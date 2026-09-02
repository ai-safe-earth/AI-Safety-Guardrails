// main.go
// Ask the model for a shell command over raw HTTP and run whatever comes back.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
)

type chatResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
}

func main() {
	task := "list the largest files in the current directory"
	payload, err := json.Marshal(map[string]any{
		"model": "gpt-4o",
		"messages": []map[string]string{
			{"role": "system", "content": "Reply with a single shell command and nothing else."},
			{"role": "user", "content": task},
		},
	})
	if err != nil {
		panic(err)
	}

	req, err := http.NewRequest(http.MethodPost, "https://api.openai.com/v1/chat/completions", bytes.NewReader(payload))
	if err != nil {
		panic(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+os.Getenv("OPENAI_API_KEY"))

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		panic(err)
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		panic(err)
	}

	var parsed chatResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		panic(err)
	}
	resp := parsed.Choices[0].Message.Content

	out, err := exec.Command("sh", "-c", resp).CombinedOutput()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
	fmt.Println(string(out))
}
