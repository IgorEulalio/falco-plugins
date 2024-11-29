package eventhub

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/messaging/azeventhubs"
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

func (p *Processor) Process(
	partitionClient *azeventhubs.ProcessorPartitionClient,
	recordChan chan<- Record,
) error {
	defer closePartitionResources(partitionClient)

	for {
		receiveCtx, receiveCtxCancel := context.WithTimeout(context.TODO(), time.Minute)
		events, err := partitionClient.ReceiveEvents(receiveCtx, 100, nil)
		receiveCtxCancel()

		if err != nil && !errors.Is(err, context.DeadlineExceeded) {
			return err
		}

		for _, event := range events {
			eventData, err := UnmarshallEvent(event.Body)
			if err != nil {
				return err
			}

			for _, record := range eventData.Records {
				ctx := context.Background()
				err := p.RateLimiter.Wait(ctx)
				if err != nil {
					// Handle the error (e.g., log it and continue)
					continue
				}
				recordChan <- record
			}

			if err := partitionClient.UpdateCheckpoint(context.TODO(), event, nil); err != nil {
				return err
			}
		}
	}
}

func UnmarshallEvent(eventJObj []byte) (*Event, error) {
	var event Event
	err := json.Unmarshal(eventJObj, &event)
	if err != nil {
		return nil, err
	}
	return &event, nil
}

func closePartitionResources(partitionClient *azeventhubs.ProcessorPartitionClient) {
	defer partitionClient.Close(context.TODO())
}
