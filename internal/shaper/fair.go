package shaper

import (
	"container/heap"
	"sync"
	"sync/atomic"
	"time"

	"stealthlink/internal/metrics"
)

type FrameType int

const (
	FrameData FrameType = iota
	FrameSYN
	FrameFIN
	FrameNOP
	FrameUPD
	FramePING
	FrameWINDOW
)

type Priority int

const (
	PriorityLow Priority = iota
	PriorityNormal
	PriorityHigh
	PriorityControl
)

type QueuedFrame struct {
	Type      FrameType
	Priority  Priority
	StreamID  uint32
	Data      []byte
	Timestamp time.Time
	Index     int
}

type PriorityClass int

const (
	ClassControl PriorityClass = iota
	ClassHigh
	ClassNormal
	ClassLow
)

func framePriority(t FrameType) Priority {
	switch t {
	case FrameSYN, FrameFIN, FrameNOP, FrameUPD, FramePING, FrameWINDOW:
		return PriorityControl
	default:
		return PriorityNormal
	}
}

func frameClass(t FrameType) PriorityClass {
	switch t {
	case FrameSYN, FrameFIN, FrameNOP, FrameUPD, FramePING, FrameWINDOW:
		return ClassControl
	default:
		return ClassNormal
	}
}

type FrameHeap []*QueuedFrame

func (h FrameHeap) Len() int           { return len(h) }
func (h FrameHeap) Less(i, j int) bool { return h[i].Timestamp.Before(h[j].Timestamp) }
func (h FrameHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
	h[i].Index = i
	h[j].Index = j
}

func (h *FrameHeap) Push(x interface{}) {
	n := len(*h)
	item := x.(*QueuedFrame)
	item.Index = n
	*h = append(*h, item)
}

func (h *FrameHeap) Pop() interface{} {
	old := *h
	n := len(old)
	item := old[n-1]
	old[n-1] = nil
	item.Index = -1
	*h = old[0 : n-1]
	return item
}

type StreamQueue struct {
	streamID  uint32
	heap      FrameHeap
	available bool
	mu        sync.Mutex
}

func NewStreamQueue(streamID uint32) *StreamQueue {
	return &StreamQueue{
		streamID:  streamID,
		heap:      make(FrameHeap, 0),
		available: true,
	}
}

func (q *StreamQueue) Push(frame *QueuedFrame) {
	q.mu.Lock()
	defer q.mu.Unlock()
	heap.Push(&q.heap, frame)
}

func (q *StreamQueue) Pop() *QueuedFrame {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.heap.Len() == 0 {
		return nil
	}
	return heap.Pop(&q.heap).(*QueuedFrame)
}

func (q *StreamQueue) Len() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.heap.Len()
}

func (q *StreamQueue) SetAvailable(available bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.available = available
}

func (q *StreamQueue) IsAvailable() bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.available
}

type FairShaper struct {
	controlQueue  *StreamQueue
	streamQueues  map[uint32]*StreamQueue
	roundRobin    []uint32
	rrIndex       int
	maxQueueSize  int
	starvationMin int
	mu            sync.RWMutex
	totalQueued   atomic.Int64
	totalSent     atomic.Int64
}

func NewFairShaper(maxQueueSize, starvationMin int) *FairShaper {
	if maxQueueSize == 0 {
		maxQueueSize = 1024
	}
	if starvationMin == 0 {
		starvationMin = 10
	}

	return &FairShaper{
		controlQueue:  NewStreamQueue(0),
		streamQueues:  make(map[uint32]*StreamQueue),
		maxQueueSize:  maxQueueSize,
		starvationMin: starvationMin,
	}
}

func (s *FairShaper) Enqueue(frame *QueuedFrame) error {
	frame.Timestamp = time.Now()

	if framePriority(frame.Type) == PriorityControl {
		s.controlQueue.Push(frame)
		metrics.IncSmuxShaperControlFrames()
	} else {
		s.mu.Lock()
		q, ok := s.streamQueues[frame.StreamID]
		if !ok {
			q = NewStreamQueue(frame.StreamID)
			s.streamQueues[frame.StreamID] = q
			s.roundRobin = append(s.roundRobin, frame.StreamID)
		}
		s.mu.Unlock()

		if q.Len() >= s.maxQueueSize {
			s.mu.Lock()
			delete(s.streamQueues, frame.StreamID)
			for i, id := range s.roundRobin {
				if id == frame.StreamID {
					s.roundRobin = append(s.roundRobin[:i], s.roundRobin[i+1:]...)
					break
				}
			}
			s.mu.Unlock()
			metrics.IncSmuxShaperStarvationPreventions()
			return nil
		}

		q.Push(frame)
		metrics.IncSmuxShaperDataFrames()
	}

	s.totalQueued.Add(1)
	metrics.SetSmuxShaperQueueSize(s.totalQueued.Load())
	return nil
}

func (s *FairShaper) Dequeue() *QueuedFrame {
	if frame := s.controlQueue.Pop(); frame != nil {
		s.totalSent.Add(1)
		return frame
	}

	s.mu.RLock()
	if len(s.roundRobin) == 0 {
		s.mu.RUnlock()
		return nil
	}

	startIdx := s.rrIndex
	for {
		streamID := s.roundRobin[s.rrIndex]
		s.rrIndex = (s.rrIndex + 1) % len(s.roundRobin)

		if q, ok := s.streamQueues[streamID]; ok && q.IsAvailable() {
			s.mu.RUnlock()
			frame := q.Pop()
			if frame != nil {
				s.totalSent.Add(1)
				return frame
			}
			s.mu.RLock()
		}

		if s.rrIndex == startIdx {
			break
		}
	}
	s.mu.RUnlock()

	return nil
}

func (s *FairShaper) DequeueBatch(max int) []*QueuedFrame {
	frames := make([]*QueuedFrame, 0, max)
	for len(frames) < max {
		frame := s.Dequeue()
		if frame == nil {
			break
		}
		frames = append(frames, frame)
	}
	return frames
}

func (s *FairShaper) BlockStream(streamID uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if q, ok := s.streamQueues[streamID]; ok {
		q.SetAvailable(false)
	}
}

func (s *FairShaper) UnblockStream(streamID uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if q, ok := s.streamQueues[streamID]; ok {
		q.SetAvailable(true)
	}
}

func (s *FairShaper) RemoveStream(streamID uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.streamQueues, streamID)
	for i, id := range s.roundRobin {
		if id == streamID {
			s.roundRobin = append(s.roundRobin[:i], s.roundRobin[i+1:]...)
			if s.rrIndex >= len(s.roundRobin) && len(s.roundRobin) > 0 {
				s.rrIndex = 0
			}
			break
		}
	}
}

func (s *FairShaper) QueueSize() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	total := s.controlQueue.Len()
	for _, q := range s.streamQueues {
		total += q.Len()
	}
	return total
}

func (s *FairShaper) StreamCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.streamQueues)
}

func (s *FairShaper) PreventStarvation() {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, q := range s.streamQueues {
		if q.Len() < s.starvationMin {
			q.SetAvailable(true)
		}
	}
}

type ShaperStats struct {
	TotalQueued  int64
	TotalSent    int64
	StreamCount  int
	QueueSize    int
	ControlQueue int
}

func (s *FairShaper) Stats() ShaperStats {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return ShaperStats{
		TotalQueued:  s.totalQueued.Load(),
		TotalSent:    s.totalSent.Load(),
		StreamCount:  len(s.streamQueues),
		QueueSize:    s.QueueSize(),
		ControlQueue: s.controlQueue.Len(),
	}
}
