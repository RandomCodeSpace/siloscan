package p

import "time"

type T struct {
	Bar          string    `form:"bar"`
	TimeUTC      time.Time `form:"time_utc" time_format:"02/01/2006 15:04" time_utc:"1"`
	Opt          string    `json:"opt,omitempty" validate:"required,min=1"`
	Dashed       string    `protobuf:"bytes,1,opt,name=a,json=b,proto3" json:"a,omitempty"`
	Plain        string
	Empty        string ``
}
