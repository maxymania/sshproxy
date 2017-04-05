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
import "github.com/maxymania/sshproxy/anyproto"

const conn_req2 = "connrequestv2"

type connRequest2 struct{
	Hotness uint8
	Level   uint8
}

type connHdr2S struct{
	Port uint16
	T uint8
	IP [16]byte
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
	
	var cx connHdr2S
	
	e = binary.Read(ech2, binary.BigEndian,&cx)
	if e!=nil {
		log.Println("binary.Read",e)
		ch2.Close()
		return
	}
	
	if cx.T>16 { cx.T = 16 }
	
	var coadr net.TCPAddr
	
	coadr.IP = net.IP(cx.IP[:cx.T])
	coadr.Port = int(cx.Port)
	
	conn,err := net.DialTCP("tcp",nil,&coadr)
	if err!=nil {
		log.Println("net.DialTCP",err)
		ech2.Write([]byte{0xff})
		ech2.Close()
		return
	}
	ech2.Write([]byte{0})
	
	go ch_proxy_copyin2(conn,ech2,ch2)
	go ch_proxy_copyout2(ech2,conn)
}

func ap1_connect(ech2 io.ReadWriteCloser, ch2 ssh.Channel){
	var cx connHdr2S
	
	e := binary.Read(ech2, binary.BigEndian,&cx)
	if e!=nil {
		log.Println("binary.Read",e)
		ch2.Close()
		return
	}
	
	if cx.T>16 { cx.T = 16 }
	
	var coadr net.TCPAddr
	
	coadr.IP = net.IP(cx.IP[:cx.T])
	coadr.Port = int(cx.Port)
	
	conn,err := net.DialTCP("tcp",nil,&coadr)
	if err!=nil {
		log.Println("net.DialTCP",err)
		anyproto.EncodeOneByteMessage(ech2,apc_err)
		ech2.Close()
		return
	}
	anyproto.EncodeOneByteMessage(ech2,apc_ok)
	
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
	var cx connHdr2S
	
	rm,e := net.ResolveTCPAddr(netw,addr)
	if e!=nil { return nil,e }
	
	IPb := []byte(rm.IP)
	cx.T = uint8(len(IPb))
	cx.Port = uint16(rm.Port)
	copy(cx.IP[:],IPb)
	
	ech,e := chopen_anyproto1(ap_conn)
	if e!=nil { return nil,e }
	
	e = binary.Write(ech,binary.BigEndian,cx)
	if e!=nil {
		log.Println("Dial3: binary.Write",e)
		ech.Close()
		return nil,e
	}
	
	cty,e := anyproto.DecodeOneByteMessage(ech)
	if e!=nil {
		log.Println("Dial3: anyproto.DecodeOneByteMessage",e)
		ech.Close()
		return nil,e
	}
	
	if cty == apc_err {
		ech.Close()
		return nil,errors.New("Connection Failed/Refused!")
	}
	if cty != apc_ok {
		ech.Close()
		return nil,errors.New("Unknown error!")
	}
	lo := new(net.TCPAddr)
	lo.Port = 54321
	lo.IP = net.IP{128,0,0,1}
	
	return &myconn2{ech,ech,ech,lo,rm},nil
}

/* Old, 'less secure' connect. */
func Old2Dial(netw, addr string) (net.Conn,error) {
	var cr connRequest2
	var cx connHdr2S
	
	if !AllowInsecure { return nil, errors.New("Insecure Operation") }
	
	rm,e := net.ResolveTCPAddr(netw,addr)
	if e!=nil { return nil,e }
	
	IPb := []byte(rm.IP)
	cx.T = uint8(len(IPb))
	cx.Port = uint16(rm.Port)
	copy(cx.IP[:],IPb)
	
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
	
	e = binary.Write(ech,binary.BigEndian,cx)
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
	
	return &myconn2{ech,ech,ch,lo,rm},nil
}

