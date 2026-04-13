package db

type Client struct {
	DSN string
}

func NewClient() *Client {
	return &Client{DSN: "localhost:5432"}
}
