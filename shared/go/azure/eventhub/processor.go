package eventhub

import (
	"encoding/json"

	"golang.org/x/time/rate"
)

type Processor struct {
	RateLimiter *rate.Limiter
}

type Record struct {
	Properties struct {
		Log string `json:"log"`
	} `json:"properties"`
}

type Event struct {
	Records []Record `json:"records"`
}

func (h Processor) Process(eventJObj []byte) (*Event, error) {
	// Unmarshal the event JSON object
	event, err := UnmarshallEvent(eventJObj)
	if err != nil {
		return nil, err
	}
	return event, nil
}

func UnmarshallEvent(eventJObj []byte) (*Event, error) {
	var event Event
	err := json.Unmarshal(eventJObj, &event)
	if err != nil {
		return nil, err
	}
	return &event, nil
}
