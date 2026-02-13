package batch

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// batchSendsTotal counts the total number of batch send operations
	batchSendsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "batch_sends_total",
		Help: "Total number of batch send operations",
	})

	// batchSendMessagesTotal counts the total number of messages sent via batch operations
	batchSendMessagesTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "batch_send_messages_total",
		Help: "Total number of messages sent via batch operations",
	})

	// batchRecvsTotal counts the total number of batch receive operations
	batchRecvsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "batch_recvs_total",
		Help: "Total number of batch receive operations",
	})

	// batchRecvMessagesTotal counts the total number of messages received via batch operations
	batchRecvMessagesTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "batch_recv_messages_total",
		Help: "Total number of messages received via batch operations",
	})

	// batchFallbackTotal counts the number of times batch I/O fell back to single-packet mode
	batchFallbackTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "batch_fallback_total",
		Help: "Total number of batch I/O fallbacks by reason",
	}, []string{"reason"})
)
