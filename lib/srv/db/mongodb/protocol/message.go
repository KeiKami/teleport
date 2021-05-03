/*
Copyright 2021 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package protocol

import (
	"io"

	"go.mongodb.org/mongo-driver/x/mongo/driver/wiremessage"

	"github.com/gravitational/trace"
)

// Message defines common interface for MongoDB wire protocol messages.
type Message interface {
	// GetHeader returns the wire message header.
	GetHeader() MessageHeader
	// GetBytes returns raw wire message bytes.
	GetBytes() []byte
	// ToWire coverts the message to wire bytes format.
	ToWire(responseTo int32) []byte
}

// ReadMessage reads the next MongoDB wire protocol message from the reader.
func ReadMessage(reader io.Reader) (Message, error) {
	header, payload, err := readHeaderAndPayload(reader)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	// Parse the message body.
	switch header.OpCode {
	case wiremessage.OpMsg:
		return readOpMsg(*header, payload)
	case wiremessage.OpQuery:
		return readOpQuery(*header, payload)
	case wiremessage.OpReply:
		return readOpReply(*header, payload)
	default:
		return &MessageUnknown{
			Header: *header,
			raw:    payload,
		}, nil
	}
}

func readHeaderAndPayload(reader io.Reader) (*MessageHeader, []byte, error) {
	// First read message header which is 16 bytes.
	var header [headerSizeBytes]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return nil, nil, trace.Wrap(err)
	}
	length, requestID, responseTo, opCode, _, ok := wiremessage.ReadHeader(header[:])
	if !ok {
		return nil, nil, trace.BadParameter("failed to read message header %v", header)
	}
	// Then read the entire message body.
	payload := make([]byte, length-headerSizeBytes)
	if _, err := io.ReadFull(reader, payload); err != nil {
		return nil, nil, trace.Wrap(err)
	}
	return &MessageHeader{
		MessageLength: length,
		RequestID:     requestID,
		ResponseTo:    responseTo,
		OpCode:        opCode,
		bytes:         header,
	}, payload, nil
}

// MessageHeader represents parsed MongoDB wire protocol message header.
//
// https://docs.mongodb.com/master/reference/mongodb-wire-protocol/#standard-message-header
type MessageHeader struct {
	MessageLength int32
	RequestID     int32
	ResponseTo    int32
	OpCode        wiremessage.OpCode
	bytes         [headerSizeBytes]byte
}

// MessageUnknown represents a wire message we don't currently support.
type MessageUnknown struct {
	Header MessageHeader
	raw    []byte
}

// GetHeader returns the wire message header.
func (m *MessageUnknown) GetHeader() MessageHeader {
	return m.Header
}

// GetBytes returns the message raw bytes.
func (m *MessageUnknown) GetBytes() []byte {
	return append(m.Header.bytes[:], m.raw...)
}

// ToWire converts the message to wire bytes format.
func (m *MessageUnknown) ToWire(responseTo int32) []byte {
	return m.raw
}

const (
	headerSizeBytes = 16
)
