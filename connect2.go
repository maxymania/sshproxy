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
import "crypto/cipher"
import "crypto/rand"
import "encoding/binary"
import "golang.org/x/crypto/curve25519"
import "golang.org/x/crypto/ssh"
import "net"
import "log"
import "errors"
import "io"
import "time"

const conn_req2 = "connrequestv2"

type connRequest2 struct{
	A [32]byte
	B [32]byte
	C [32]byte
	Hotness uint8
	Level   uint8
}
type connResponse2 struct{
	A [32]byte
	B [32]byte
	C [32]byte
}
type connHeader2 struct{
	Len uint8
	T int8
	K [256]byte
}

func ch_connect2(nc ssh.NewChannel){
	var cr connRequest2
	var c2 connResponse2
	
	e := binary.Read(bytes.NewReader(nc.ExtraData()), binary.BigEndian,&cr)
	if e!=nil {
		log.Println("binary.Read",e)
		nc.Reject(ssh.ConnectionFailed,"Fail!")
		return
	}
	if cr.Hotness<cr.Level {
		var K0,K1 [32]byte
		var t [32]byte
		var t1 [32]byte
		var t2 [32]byte
		cr.Hotness++
		rand.Read(t[:])
		rand.Read(t1[:])
		rand.Read(t2[:])
		
		curve25519.ScalarMult(&K0,&t2,&cr.A)  /* K[0] = A^t2 */
		
		curve25519.ScalarMult(&cr.A,&t,&cr.B) /* A = B^t */
		curve25519.ScalarBaseMult(&cr.B,&t1)  /* B = g^t1  (aka T1) */
		curve25519.ScalarMult(&cr.C,&t,&cr.C) /* C = C^t */
		
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
		
		
		e = binary.Read(ch, binary.BigEndian,&c2)
		if e!=nil {
			log.Println("binary.Read",e)
			nc.Reject(ssh.ConnectionFailed,"Fail!")
			return
		}
		
		curve25519.ScalarMult(&K1,&t1,&c2.B)  /* K[1] = B^t1 */
		
		curve25519.ScalarBaseMult(&c2.A,&t2)  /* A = g^t2  (aka T2)*/
		curve25519.ScalarMult(&c2.B,&t,&c2.A) /* B = A^t */
		curve25519.ScalarMult(&c2.C,&t,&c2.C) /* C = C^t */
		
		ch2,rq2,e := nc.Accept()
		if e!=nil {
			log.Println("nc.Accept",e)
			ch.Close()
			return
		}
		go DevNullRequest(rq2)
		
		
		e = binary.Write(ch2,binary.BigEndian,c2)
		if e!=nil {
			log.Println("binary.Write",e)
			nc.Reject(ssh.ConnectionFailed,"Fail!")
			return
		}
		
		rch  := cipher.StreamReader{multiStream{createCipher(K0[:]),createCipher(K1[:])},ch}
		rch2 := cipher.StreamReader{multiStream{createCipher(K0[:]),createCipher(K1[:])},ch2}
		
		go ch_proxy_copyin(rch,ch2)
		go ch_proxy_copyin(rch2,ch)
		/* TODO stderr */
		return
	}
	
	
	{
		var t1 [32]byte
		var t2 [32]byte
		var t3 [32]byte
		rand.Read(t1[:])
		rand.Read(t2[:])
		rand.Read(t3[:])
		
		curve25519.ScalarMult (&cr.A,&t1,&cr.A)
		curve25519.ScalarMult (&cr.B,&t2,&cr.B)
		curve25519.ScalarMult (&cr.C,&t3,&cr.C)
		
		curve25519.ScalarBaseMult (&c2.A,&t1)
		curve25519.ScalarBaseMult (&c2.B,&t2)
		curve25519.ScalarBaseMult (&c2.C,&t3)
	}
	
	i1 := multiStream{
		createCipher(cr.A[:]),
		createCipher(cr.B[:]),
		createCipher(cr.C[:]),
	}
	i2 := multiStream{
		createCipher(cr.A[:]),
		createCipher(cr.B[:]),
		createCipher(cr.C[:]),
	}
	ch2,rq2,e := nc.Accept()
	if e!=nil {
		log.Println("nc.Accept",e)
		return
	}
	go DevNullRequest(rq2)
	
	e = binary.Write(ch2,binary.BigEndian,c2)
	if e!=nil {
		log.Println("binary.Write",e)
		ch2.Close()
		return
	}
	
	rch2 := cipher.StreamReader{i1,ch2}
	wch2 := cipher.StreamWriter{i2,ch2,nil}
	
	var ch connHeader2
	
	e = binary.Read(rch2, binary.BigEndian,&ch)
	if e!=nil {
		log.Println("binary.Read",e)
		ch2.Close()
		return
	}
	netw := "tcp"
	
	if ch.T==4 { netw = "tcp4" }
	if ch.T==6 { netw = "tcp6" }
	addr := string(ch.K[:ch.Len])
	
	conn,err := net.Dial(netw,addr)
	if err!=nil {
		log.Println("net.Dial",err)
		wch2.Write([]byte{0xff})
		ch2.Close()
		return
	}
	wch2.Write([]byte{0})
	
	go ch_proxy_copyin2(conn,wch2,ch2)
	go ch_proxy_copyout2(rch2,conn)
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

func Dial2(netw, addr string) (net.Conn,error) {
	var t1,t2,t3 [32]byte
	var cr connRequest2
	var c2 connResponse2
	var cc connHeader2
	
	switch netw{
	case "tcp":cc.T = 0
	case "tcp4":cc.T = 4
	case "tcp6":cc.T = 6
	}
	if len(addr)>255 { return nil, errors.New("Address too long!") }
	cc.Len = byte(len(addr))
	copy(cc.K[:],[]byte(addr))
	
	rand.Read(t1[:])
	rand.Read(t2[:])
	rand.Read(t3[:])
	
	curve25519.ScalarBaseMult (&cr.A,&t1)
	curve25519.ScalarBaseMult (&cr.B,&t2)
	curve25519.ScalarBaseMult (&cr.C,&t3)
	
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
	
	e = binary.Read(ch,binary.BigEndian,&c2) /* obtain connResponse2 */
	if e!=nil {
		log.Println("Dial2: binary.Read",e)
		ch.Close()
		return nil,e
	}
	
	curve25519.ScalarMult (&c2.A,&t1,&c2.A)
	curve25519.ScalarMult (&c2.B,&t2,&c2.B)
	curve25519.ScalarMult (&c2.C,&t3,&c2.C)
	
	i1 := multiStream{
		createCipher(cr.A[:]),
		createCipher(cr.B[:]),
		createCipher(cr.C[:]),
	}
	i2 := multiStream{
		createCipher(cr.A[:]),
		createCipher(cr.B[:]),
		createCipher(cr.C[:]),
	}
	
	rch := cipher.StreamReader{i1,ch}
	wch := cipher.StreamWriter{i2,ch,nil}
	
	e = binary.Write(wch,binary.BigEndian,cc)
	if e!=nil {
		log.Println("Dial2: binary.Write",e)
		ch.Close()
		return nil,e
	}
	resp := []byte{0}
	
	_,e = rch.Read(resp)
	if e!=nil { return nil,e }
	if resp[0]!=0 {
		return nil,errors.New("Connection failed!")
	}
	
	lo,_ := net.ResolveTCPAddr("tcp","localhost:54321")
	rm,_ := net.ResolveTCPAddr("tcp",addr)
	
	go DevNullRequest(rq)
	return &myconn2{rch,wch,ch,lo,rm},nil
}

