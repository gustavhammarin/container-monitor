package api

import "time"

type PollState struct {
	LastPoll *time.Time `json:"lastPoll"`
	IsFinished bool `json:"isFinished"`
}

func Init() *PollState {
	return &PollState{LastPoll: nil, IsFinished: false}
}

func (p *PollState) Update(){
	p.IsFinished = true
}