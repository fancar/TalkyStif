package main
// Producer test
import (
	"sync/atomic"
	"fmt"
	"gopkg.in/confluentinc/confluent-kafka-go.v1/kafka"
    "bytes"
    "encoding/json"
    //"unsafe"
)

/* producer to bgdata garden */
func Kafka() {
	topic := CFG_KAFKA_TOPIC

	p, err := kafka.NewProducer(&kafka.ConfigMap{
		"bootstrap.servers": CFG_KAFKA_SERVERS,
		"linger.ms" : CFG_KAFKA_LINGERMS,
		// "batch.size" : CFG_KAFKA_BATCHSIZE,
	})
		// "debug": "broker"})
	if err != nil {
		log.Error("[kafka] "+err.Error())
		panic(err)
	}

	defer p.Close()

	// Delivery report handler for produced messages
	go func() {
		for e := range p.Events() {
			switch ev := e.(type) {
			case *kafka.Message:
				if ev.TopicPartition.Error != nil {
					log.Error(fmt.Sprintf("[kafka] Delivery failed: %v\n", ev.TopicPartition))
					atomic.AddInt64(&kafka_errors_count, 1)
					atomic.AddInt64(&kafka_errors_count_total, 1)					
				} else {
					log.Debug(fmt.Sprintf("[kafka] Delivered message to: %v\n", ev.TopicPartition))
					atomic.AddInt64(&macs_notified, 1)
					atomic.AddInt64(&macs_notified_total, 1)
				}
			}
		}
	}()

	// Produce messages from channel to topic (asynchronously)
	for {
		m := <-mac_to_produce

		BodyBytes := new(bytes.Buffer)
		json.NewEncoder(BodyBytes).Encode(m)

		p.Produce(&kafka.Message{
			TopicPartition: kafka.TopicPartition{Topic: &topic, Partition: kafka.PartitionAny},
			Value: BodyBytes.Bytes(), // this is the []byte
		}, nil)

	}
}