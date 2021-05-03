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
	"net"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/x/mongo/driver/wiremessage"

	"github.com/gravitational/trace"
)

// Authenticate authenticates the provided MongoDB connection using x509
// authentication mechanism as a specified user.
func Authenticate(serverConn net.Conn, user string) error {
	authMessage, err := makeAuthMessage(user)
	if err != nil {
		return trace.Wrap(err)
	}
	_, err = serverConn.Write(authMessage.ToWire(0))
	if err != nil {
		return trace.Wrap(err)
	}
	reply, err := ReadMessage(serverConn)
	if err != nil {
		return trace.Wrap(err)
	}
	err = checkAuthReply(reply)
	if err != nil {
		return trace.Wrap(err)
	}
	return nil
}

// ReplyError sends error wire message to the client.
func ReplyError(clientConn net.Conn, replyTo Message, clientErr error) (err error) {
	// If the message we're replying to is OP_MSG, send OP_MSG error reply,
	// otherwise send OP_REPLY.
	var errMessage Message
	switch replyTo.(type) {
	case *MessageOpMsg:
		errMessage, err = makeOpMsgError(clientErr)
	default:
		errMessage, err = makeOpReplyError(clientErr)
	}
	if err != nil {
		return trace.Wrap(err)
	}
	var replyToID int32
	if replyTo != nil {
		replyToID = replyTo.GetHeader().RequestID
	}
	_, err = clientConn.Write(errMessage.ToWire(replyToID))
	if err != nil {
		return trace.Wrap(err)
	}
	return nil
}

// makeAuthMessage builds a "authenticate" command wire message.
func makeAuthMessage(user string) (Message, error) {
	document, err := bson.Marshal(bson.D{ // Must use bson.D since order matters.
		{Key: "authenticate", Value: 1},
		{Key: "mechanism", Value: "MONGODB-X509"},
		{Key: "$db", Value: "$external"},
		{Key: "user", Value: "CN=" + user},
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return MakeOpMsg(document), nil
}

// checkAuthReply verifies "authenticate" command response.
//
// Successful auth reply contains a OP_MSG message with a single document:
// {"dbname": "$external", "user": "CN=<user>", "ok": 1}
func checkAuthReply(message Message) error {
	opMsg, ok := message.(*MessageOpMsg)
	if !ok {
		return trace.BadParameter("unexpected reply to auth command: %v", message)
	}
	authReply, err := opMsg.GetDocument()
	if err != nil {
		return trace.Wrap(err)
	}
	authOK, ok := authReply.Lookup("ok").AsInt32OK()
	if !ok || authOK != 1 {
		return trace.BadParameter("authentication failed: %s", authReply.Lookup("errmsg"))
	}
	return nil
}

// makeOpReplyError builds a OP_REPLY error wire message.
func makeOpReplyError(err error) (Message, error) {
	document, err := bson.Marshal(bson.M{
		"$err": err.Error(),
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return MakeOpReplyWithFlags(document, wiremessage.QueryFailure), nil
}

// makeOpMsgError builds a OP_MSG error wire message.
func makeOpMsgError(err error) (Message, error) {
	document, err := bson.Marshal(bson.M{
		"ok":     0,
		"errmsg": err.Error(),
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return MakeOpMsg(document), nil
}
