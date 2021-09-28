// Go NETCONF Client
//
// Copyright (c) 2013-2018, Juniper Networks, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package netconf

import (
	"bytes"
	"crypto/rand"
	"encoding/xml"
	"fmt"
	"io"
	"strings"

	"github.com/beevik/etree"
)

const (
	editConfigXml = `<edit-config>
<target><%s/></target>
<default-operation>merge</default-operation>
<error-option>rollback-on-error</error-option>
<config>%s</config>
</edit-config>`
)

// RPCMessage represents an RPC Message to be sent.
type RPCMessage struct {
	MessageID string
	Methods   []RPCMethod
}

// NewRPCMessage generates a new RPC Message structure with the provided methods
func NewRPCMessage(methods []RPCMethod) *RPCMessage {
	return &RPCMessage{
		MessageID: msgID(),
		Methods:   methods,
	}
}

func (m *RPCMessage) Exec(s *Session) (*RPCReply, error) {
	request, err := xml.Marshal(m)
	if err != nil {
		return nil, err
	}

	header := []byte(xml.Header)
	request = append(header, request...)

	err = s.Transport.Send(request)
	if err != nil {
		return nil, err
	}

	rawXML, err := s.Transport.Receive()
	if err != nil {
		return nil, err
	}

	reply, err := newRPCReply(rawXML, s.ErrOnWarning, m.MessageID)
	if err != nil {
		return nil, err
	}

	return reply, nil
}

// MarshalXML marshals the NETCONF XML data
func (m *RPCMessage) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	var buf bytes.Buffer
	for _, method := range m.Methods {
		buf.WriteString(method.MarshalMethod())
	}

	data := struct {
		MessageID string `xml:"message-id,attr"`
		Xmlns     string `xml:"xmlns,attr"`
		Methods   []byte `xml:",innerxml"`
	}{
		m.MessageID,
		"urn:ietf:params:xml:ns:netconf:base:1.0",
		buf.Bytes(),
	}

	// Wrap the raw XML (data) into <rpc>...</rpc> tags
	start.Name.Local = "rpc"
	return e.EncodeElement(data, start)
}

// RPCReply defines a reply to a RPC request
type RPCReply struct {
	Errors    []RPCError
	Data      *etree.Document
	Ok        bool
	MessageID string
}

func newRPCReply(rawXML []byte, ErrOnWarning bool, messageID string) (*RPCReply, error) {
	reply := &RPCReply{
		Data: etree.NewDocument(),
	}

	if err := reply.Data.ReadFromBytes(rawXML); err != nil {
		return nil, err
	}

	if reply.Data.FindElement("//ok") != nil {
		reply.Ok = true
	}

	if root := reply.Data.FindElement("rpc-reply").ChildElements()[0]; root == nil {
		return nil, fmt.Errorf("can't find root")
	} else {
		reply.Data.SetRoot(root)
	}

	safeText := func(el *etree.Element) string {
		if el == nil {
			return ""
		}
		return el.Text()
	}

	for _, rpcErr := range reply.Data.FindElements("//rpc-error") {

		reply.Errors = append(reply.Errors, RPCError{
			Type:     safeText(rpcErr.FindElement("error-type")),
			Tag:      safeText(rpcErr.FindElement("error-tag")),
			Severity: safeText(rpcErr.FindElement("error-severity")),
			Path:     safeText(rpcErr.FindElement("error-path")),
			Message:  safeText(rpcErr.FindElement("error-message")),
		})
	}

	// will return a valid reply so setting Requests message id
	reply.MessageID = messageID

	if reply.Errors != nil {
		for _, rpcErr := range reply.Errors {
			if rpcErr.Severity == "error" || ErrOnWarning {
				return reply, &rpcErr
			}
		}
	}

	return reply, nil
}

// RPCError defines an error reply to a RPC request
type RPCError struct {
	Type     string `xml:"error-type"`
	Tag      string `xml:"error-tag"`
	Severity string `xml:"error-severity"`
	Path     string `xml:"error-path"`
	Message  string `xml:"error-message"`
}

// Error generates a string representation of the provided RPC error
func (re *RPCError) Error() string {
	return fmt.Sprintf("netconf rpc [%s] '%s'", re.Severity, strings.TrimSpace(re.Message))
}

// RPCMethod defines the interface for creating an RPC method.
type RPCMethod interface {
	MarshalMethod() string
}

// RawMethod defines how a raw text request will be responded to
type RawMethod string

// MarshalMethod converts the method's output into a string
func (r RawMethod) MarshalMethod() string {
	return string(r)
}

// MethodLock files a NETCONF lock target request with the remote host
func MethodLock(target string) RawMethod {
	return RawMethod(fmt.Sprintf("<lock><target><%s/></target></lock>", target))
}

// MethodUnlock files a NETCONF unlock target request with the remote host
func MethodUnlock(target string) RawMethod {
	return RawMethod(fmt.Sprintf("<unlock><target><%s/></target></unlock>", target))
}

// MethodGetConfig files a NETCONF get-config source request with the remote host
func MethodGetConfig(source string) RawMethod {
	return RawMethod(fmt.Sprintf("<get-config><source><%s/></source></get-config>", source))
}

// MethodGet files a NETCONF get source request with the remote host
func MethodGet(filterType string, dataXml string) RawMethod {
	return RawMethod(fmt.Sprintf("<get><filter type=\"%s\">%s</filter></get>", filterType, dataXml))
}

// MethodEditConfig files a NETCONF edit-config request with the remote host
func MethodEditConfig(database string, dataXml string) RawMethod {
	return RawMethod(fmt.Sprintf(editConfigXml, database, dataXml))
}

// MethodValidate files a NETCONF validating config with the remote host
func MethodValidate(source string) RawMethod {
	return RawMethod(fmt.Sprintf("<validate><source><%s/></source></validate>", source))
}

// MethodSetConfig files a NETCONF set-config request with the remote host
func MethodSetConfig(config string) RawMethod {
	return RawMethod(fmt.Sprintf(`<load-configuration action="set" format="text"><configuration-set>%s</configuration-set></load-configuration>`, config))
}

//MethodDiscard files a NETCONF discard request with the remote host
func MethodDiscard() RawMethod {
	return RawMethod(`<discard-changes/>`)
}

//MethodCompare files a NETCONF compare request with the remote host
func MethodCompare() RawMethod {
	return RawMethod(`<get-configuration compare="rollback" rollback="0" format="text"/>`)
}

//MethodCompare files a NETCONF commit request with the remote host
func MethodCommit(msg string) RawMethod {
	return RawMethod(fmt.Sprintf(`<commit-configuration><log>%s</log></commit-configuration>`, msg))
}

var msgID = uuid

// uuid generates a "good enough" uuid without adding external dependencies
func uuid() string {
	b := make([]byte, 16)
	io.ReadFull(rand.Reader, b)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}
