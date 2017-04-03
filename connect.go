/*
MIT License

Copyright (c) 2017 Simon Schmidt

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/


package sshproxy

import "golang.org/x/crypto/ssh"
import "encoding/asn1"
import "net"
import "time"
import "errors"
import "log"

const conn_req1 = "connrequestv1"

type connRequest1 struct{
	Net  []byte
	Addr []byte
	Hotness   int
}

/*
Hotness:
	0 = This level exist on the originating client.
	1 = If the request reaches the first proxy. (Direct proxy, no mix).
	2 = First proxy-indirection
	3 = Second proxy-indirection
	4 = Third proxy-indirection
	...
*/

func ch_connect(nc ssh.NewChannel){
	var cr connRequest1
	_,e := asn1.Unmarshal(nc.ExtraData(),&cr)
	if e!=nil {
		log.Println("asn1.Unmarshal",e)
		nc.Reject(ssh.ConnectionFailed,"Fail!")
		return
	}
	switch string(cr.Net){
	case "tcp","tcp4","tcp6":break
	default:
		log.Println("unsupported",string(cr.Net))
		nc.Reject(ssh.Prohibited,"Illegal Type "+string(cr.Net))
		return
	}
	if cr.Hotness<Level {
		cr.Hotness++
		b,e := asn1.Marshal(cr)
		if e!=nil {
			log.Println("asn1.Marshal",e)
			nc.Reject(ssh.ConnectionFailed,"Fail!")
			return
		}
		cl := selClient()
		if cl==nil {
			log.Println("No Client")
			nc.Reject(ssh.ConnectionFailed,"Fail!")
			return
		}
		ch,rq,e := cl.open(conn_req1,b)
		if e!=nil {
			log.Println("cl.open",conn_req1,e)
			nc.Reject(ssh.ConnectionFailed,"Fail!")
			return
		}
		ch2,rq2,e := nc.Accept()
		if e!=nil {
			log.Println("nc.Accept",e)
			go DevNullRequest(rq)
			ch.Close()
			return
		}
		go ch_proxy_reqs(ch,rq2)
		go ch_proxy_reqs(ch2,rq)
		go ch_proxy_copy(ch,ch2)
		go ch_proxy_copy(ch2,ch)
		/* TODO stderr */
		return
	}
	conn,err := net.Dial(string(cr.Net),string(cr.Addr))
	if err!=nil {
		log.Println("net.Dial",err)
		nc.Reject(ssh.ConnectionFailed,"Fail!")
		return
	}
	ch2,rq2,e := nc.Accept()
	if e!=nil {
		log.Println("nc.Accept",e)
		conn.Close()
		return
	}
	go DevNullRequest(rq2)
	go ch_proxy_copyin(conn,ch2)
	go ch_proxy_copyout(ch2,conn)
}

type myaddr int
func (o myaddr) Network() string { return "tcp" }
func (o myaddr) String() string { return "localhost:54321" }

type addrp struct{
	n,a string
}
func (o addrp) Network() string { return o.n }
func (o addrp) String() string { return o.a }

type myconn struct{
	ssh.Channel
	l net.Addr
	r net.Addr
}
func (m *myconn) LocalAddr() net.Addr { return m.l }
func (m *myconn) RemoteAddr() net.Addr { return m.r }
func (m *myconn) SetDeadline     (t time.Time) error { return nil }
func (m *myconn) SetReadDeadline (t time.Time) error { return nil }
func (m *myconn) SetWriteDeadline(t time.Time) error { return nil }

func Dial(netw, addr string) (net.Conn,error) {
	var cr connRequest1
	cr.Net  = []byte(netw)
	cr.Addr = []byte(addr)
	cr.Hotness = 1
	
	b,e := asn1.Marshal(cr)
	if e!=nil {
		log.Println("Dial: asn1.Marshal",e)
		return nil,e
	}
	
	cl := selClient()
	if cl==nil { return nil,errors.New("No Client") }
	ch,rq,e := cl.open(conn_req1,b)
	if e!=nil {
		log.Println("Dial: cl.open",e)
		return nil,e
	}
	lo,_ := net.ResolveTCPAddr("tcp","localhost:54321")
	rm,_ := net.ResolveTCPAddr("tcp",addr)
	
	go DevNullRequest(rq)
	return &myconn{ch,lo,rm},nil
}



