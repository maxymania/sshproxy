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

import "bytes"
import "encoding/binary"
import "golang.org/x/crypto/ssh"
import "net"
import "log"
import "errors"
import "io"
import "time"

import "github.com/maxymania/sshproxy/scrambler"

const conn_req2 = "connrequestv2"

type connRequest2 struct{
	Hotness uint8
	Level   uint8
}

type connHeader2 struct{
	Len uint8
	T int8
	K [256]byte
}

func ch_connect2(nc ssh.NewChannel){
	var cr connRequest2
	
	e := binary.Read(bytes.NewReader(nc.ExtraData()), binary.BigEndian,&cr)
	if e!=nil {
		log.Println("binary.Read",e)
		nc.Reject(ssh.ConnectionFailed,"Fail!")
		return
	}
	if cr.Hotness<cr.Level {
		cr.Hotness++
		buf := new(bytes.Buffer)
		e = binary.Write(buf,binary.BigEndian,cr)
		if e!=nil {
			log.Println("binary.Write",e)
			nc.Reject(ssh.ConnectionFailed,"Fail!")
			return
		}
		
		b := buf.Bytes()
		cl := selClient()
		if cl==nil {
			log.Println("No Client")
			nc.Reject(ssh.ConnectionFailed,"Fail!")
			return
		}
		ch,rq,e := cl.open(conn_req2,b)
		if e!=nil {
			log.Println("cl.open",conn_req2,e)
			nc.Reject(ssh.ConnectionFailed,"Fail!")
			return
		}
		go DevNullRequest(rq)
		
		ch2,rq2,e := nc.Accept()
		
		if e!=nil {
			log.Println("nc.Accept",e)
			ch.Close()
			return
		}
		go DevNullRequest(rq2)
		
		e = scrambler.Intermediate(ch2,ch)
		
		if e!=nil {
			log.Println("scrambler.Intermediate",e)
			ch.Close()
			ch2.Close()
		}
		return
	}
	
	ch2,rq2,e := nc.Accept()
	
	if e!=nil {
		log.Println("nc.Accept",e)
		return
	}
	go DevNullRequest(rq2)
	
	ech2,e := scrambler.Endpt(ch2)
	if e!=nil {
		log.Println("scrambler.Endpt",e)
		return
	}
	
	var msg connHeader2
	
	e = binary.Read(ech2, binary.BigEndian,&msg)
	if e!=nil {
		log.Println("binary.Read",e)
		ch2.Close()
		return
	}
	
	netw := "tcp"
	
	if msg.T==4 { netw = "tcp4" }
	if msg.T==6 { netw = "tcp6" }
	addr := string(msg.K[:msg.Len])
	
	conn,err := net.Dial(netw,addr)
	if err!=nil {
		log.Println("net.Dial",err)
		ech2.Write([]byte{0xff})
		ech2.Close()
		return
	}
	ech2.Write([]byte{0})
	
	go ch_proxy_copyin2(conn,ech2,ch2)
	go ch_proxy_copyout2(ech2,conn)
}

type myconn2 struct{
	io.Reader
	io.Writer
	io.Closer
	l net.Addr
	r net.Addr
}
func (m *myconn2) LocalAddr() net.Addr { return m.l }
func (m *myconn2) RemoteAddr() net.Addr { return m.r }
func (m *myconn2) SetDeadline     (t time.Time) error { return nil }
func (m *myconn2) SetReadDeadline (t time.Time) error { return nil }
func (m *myconn2) SetWriteDeadline(t time.Time) error { return nil }

func Dial(netw, addr string) (net.Conn,error) {
	var cr connRequest2
	var cc connHeader2
	
	switch netw{
	case "tcp":cc.T = 0
	case "tcp4":cc.T = 4
	case "tcp6":cc.T = 6
	}
	if len(addr)>255 { return nil, errors.New("Address too long!") }
	cc.Len = byte(len(addr))
	copy(cc.K[:],[]byte(addr))
	
	cr.Hotness = 1
	cr.Level = uint8(Level)
	
	buf := new(bytes.Buffer)
	binary.Write(buf,binary.BigEndian,cr)
	
	cl := selClient()
	if cl==nil { return nil,errors.New("No Client") }
	ch,rq,e := cl.open(conn_req2,buf.Bytes()) /* send connRequest2 */
	if e!=nil {
		log.Println("Dial2: cl.open",e)
		return nil,e
	}
	go DevNullRequest(rq)
	
	ech,e := scrambler.Initiator(ch)
	if e!=nil {
		log.Println("Dial2: scrambler.Initiator",e)
		ch.Close()
		return nil,e
	}
	
	e = binary.Write(ech,binary.BigEndian,cc)
	if e!=nil {
		log.Println("Dial2: binary.Write",e)
		ech.Close()
		return nil,e
	}
	
	resp := []byte{0}
	
	_,e = ech.Read(resp)
	if e!=nil { return nil,e }
	if resp[0]!=0 {
		return nil,errors.New("Connection failed!")
	}
	
	lo,_ := net.ResolveTCPAddr("tcp","localhost:54321")
	rm,_ := net.ResolveTCPAddr("tcp",addr)
	
	go DevNullRequest(rq)
	return &myconn2{ech,ech,ch,lo,rm},nil
}

