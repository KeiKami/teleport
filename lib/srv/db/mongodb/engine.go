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

package mongodb

import (
	"context"
	"crypto/tls"
	"net"

	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/srv/db/common"
	"github.com/gravitational/teleport/lib/srv/db/mongodb/protocol"
	"github.com/gravitational/teleport/lib/utils"

	"github.com/gravitational/trace"
	"github.com/jonboulle/clockwork"
	"github.com/sirupsen/logrus"
)

// Engine implements the MongoDB database service that accepts client
// connections coming over reverse tunnel from the proxy and proxies
// them between the proxy and the MongoDB database instance.
//
// Implements common.Engine.
type Engine struct {
	// Auth handles database access authentication.
	Auth common.Auth
	// Audit emits database access audit events.
	Audit common.Audit
	// Context is the database server close context.
	Context context.Context
	// Clock is the clock interface.
	Clock clockwork.Clock
	// Log is used for logging.
	Log logrus.FieldLogger
}

// HandleConnection processes the connection from MongoDB proxy coming
// over reverse tunnel.
//
// It handles all necessary startup actions, authorization and acts as a
// middleman between the proxy and the database intercepting and interpreting
// all messages i.e. doing protocol parsing.
func (e *Engine) HandleConnection(ctx context.Context, sessionCtx *common.Session, clientConn net.Conn) (err error) {
	defer func() {
		if err != nil {
			e.replyError(clientConn, nil, err)
		}
	}()
	// Perform authorization checks.
	err = e.checkConnectAccess(sessionCtx)
	if err != nil {
		return trace.Wrap(err, "error authorizing database access")
	}
	// Establish connection to the MongoDB server.
	serverConn, err := e.connect(ctx, sessionCtx)
	if err != nil {
		return trace.Wrap(err, "error connecting to the database")
	}
	defer func() {
		err := serverConn.Close()
		if err != nil {
			e.Log.WithError(err).Error("Failed to close connection to MongoDB server.")
		}
	}()
	e.Audit.OnSessionStart(e.Context, sessionCtx, nil)
	defer e.Audit.OnSessionEnd(e.Context, sessionCtx)
	// Copy between the connections.
	clientErrCh := make(chan error, 1)
	serverErrCh := make(chan error, 1)
	go e.receiveFromClient(clientConn, serverConn, clientErrCh, sessionCtx)
	go e.receiveFromServer(serverConn, clientConn, serverErrCh)
	select {
	case err := <-clientErrCh:
		e.Log.WithError(err).Debug("Client done.")
	case err := <-serverErrCh:
		e.Log.WithError(err).Debug("Server done.")
	case <-ctx.Done():
		e.Log.Debug("Context canceled.")
	}
	return nil
}

// checkConnectAccess does authorization check for MongoDB connection about
// to be established.
func (e *Engine) checkConnectAccess(sessionCtx *common.Session) error {
	ap, err := e.Auth.GetAuthPreference()
	if err != nil {
		return trace.Wrap(err)
	}
	mfaParams := services.AccessMFAParams{
		Verified:       sessionCtx.Identity.MFAVerified != "",
		AlwaysRequired: ap.GetRequireSessionMFA(),
	}
	// Only the username is checked upon initial connection. MongoDB sends
	// database name with each protocol message (for query, update, etc.)
	// so it is checked when we receive a message from client.
	err = sessionCtx.Checker.CheckAccessToDatabase(sessionCtx.Server, mfaParams,
		&services.DatabaseLabelsMatcher{Labels: sessionCtx.Server.GetAllLabels()},
		&services.DatabaseUserMatcher{User: sessionCtx.DatabaseUser})
	if err != nil {
		e.Audit.OnSessionStart(e.Context, sessionCtx, err)
		return trace.Wrap(err)
	}
	return nil
}

// connect establishes connection to MongoDB database.
func (e *Engine) connect(ctx context.Context, sessionCtx *common.Session) (*tls.Conn, error) {
	tlsConfig, err := e.Auth.GetTLSConfig(ctx, sessionCtx)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	tlsConn, err := tls.Dial("tcp", sessionCtx.Server.GetURI(), tlsConfig)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	// MongoDB clients can connect to the database unauthenticated and then
	// execute db.auth() command to authenticate. This would potentially allow
	// the client to authenticate as a different user than what's encoded in
	// the certificate.
	//
	// For this reason, run x509 authentication sequence ourselves - i.e.
	// force-authenticate the connection as a user that's encoded in the
	// certificate.
	//
	// This way, if the client executes db.auth() itself as a different user,
	// they will be getting authorization errors because Mongo doesn't allow
	// multiple authenticated users for the same session.
	err = protocol.Authenticate(tlsConn, sessionCtx.DatabaseUser)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return tlsConn, nil
}

// receiveFromClient relays protocol messages received from MongoDB client
// to MongoDB database server.
func (e *Engine) receiveFromClient(clientConn, serverConn net.Conn, clientErrCh chan<- error, sessionCtx *common.Session) {
	log := e.Log.WithFields(logrus.Fields{
		"from":   "client",
		"client": clientConn.RemoteAddr(),
		"server": serverConn.RemoteAddr(),
	})
	defer func() {
		log.Debug("Stop receiving from client.")
		close(clientErrCh)
	}()
	for {
		message, err := protocol.ReadMessage(clientConn)
		if err != nil {
			if utils.IsOKNetworkError(err) {
				log.Debug("Client connection closed.")
				return
			}
			log.WithError(err).Error("Failed to read MongoDB message from client.")
			clientErrCh <- err
			return
		}
		log.Debugf("===> %v", message)
		switch msg := message.(type) {
		case *protocol.MessageOpMsg:
			// MongoDB client sends database information in each command so
			// authorize it against user's role.
			err = e.authorizeCommand(sessionCtx, msg)
			if err != nil {
				e.Audit.OnQuery(e.Context, sessionCtx, common.Query{
					Database:  msg.GetDatabase(),
					Documents: msg.GetDocumentsAsStrings(),
					Error:     err,
				})
				// Don't pass message to the server, instead reply with an
				// error to the client.
				e.replyError(clientConn, message, err)
				continue
			}
			e.Audit.OnQuery(e.Context, sessionCtx, common.Query{
				Database:  msg.GetDatabase(),
				Documents: msg.GetDocumentsAsStrings(),
			})
		}
		_, err = serverConn.Write(message.GetBytes())
		if err != nil {
			log.WithError(err).Error("Failed to write MongoDB message to server.")
			clientErrCh <- err
			return
		}
	}
}

// authorizeCommand checks if the user can run the provided MongoDB command.
//
// Each MongoDB command contains information about the database it's run in
// so we check it against allowed databases in the user's role.
func (e *Engine) authorizeCommand(sessionCtx *common.Session, message *protocol.MessageOpMsg) error {
	database := message.GetDatabase()
	if database == "" {
		e.Log.Warnf("No database info in message: %v.", message)
		return nil
	}
	return sessionCtx.Checker.CheckAccessToDatabase(sessionCtx.Server,
		services.AccessMFAParams{Verified: true},
		&services.DatabaseLabelsMatcher{Labels: sessionCtx.Server.GetAllLabels()},
		&services.DatabaseUserMatcher{User: sessionCtx.DatabaseUser},
		&services.DatabaseNameMatcher{Name: database})
}

// receiveFromServer relays protocol messages received from MongoDB database
// server to MongoDB client.
func (e *Engine) receiveFromServer(serverConn, clientConn net.Conn, serverErrCh chan<- error) {
	log := e.Log.WithFields(logrus.Fields{
		"from":   "server",
		"client": clientConn.RemoteAddr(),
		"server": serverConn.RemoteAddr(),
	})
	defer func() {
		log.Debug("Stop receiving from server.")
		close(serverErrCh)
	}()
	for {
		message, err := protocol.ReadMessage(serverConn)
		if err != nil {
			if utils.IsOKNetworkError(err) {
				log.Debug("Server connection closed.")
				return
			}
			log.WithError(err).Error("Failed to read MongoDB message from server.")
			serverErrCh <- err
			return
		}
		log.Debugf("<=== %v", message)
		_, err = clientConn.Write(message.GetBytes())
		if err != nil {
			log.WithError(err).Error("Failed to write MongoDB message to client.")
			serverErrCh <- err
			return
		}
	}
}

func (e *Engine) replyError(clientConn net.Conn, replyTo protocol.Message, err error) {
	errSend := protocol.ReplyError(clientConn, nil, err)
	if errSend != nil {
		e.Log.WithError(errSend).Errorf("Failed to send error message to MongoDB client: %v.", err)
	}
}
