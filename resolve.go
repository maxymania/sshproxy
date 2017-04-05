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
import "errors"
import "log"
import "io"

const dns_req1 = "dnsrequestv1"

type dnsRequest1 struct{
	Name    string
	Hotness int
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

func ch_dns1(nc ssh.NewChannel){
	msg := make([]byte,16+1)
	msg[0] = 0
	
	/* Open Client. */
	ch2,rq2,e := nc.Accept()
	if e!=nil {
		log.Println("nc.Accept",e)
		return
	}
	go DevNullRequest(rq2)
	go ch_proxy_eat(ch2) /* Eat Client Input. */
	
	var cr dnsRequest1
	_,e = asn1.Unmarshal(nc.ExtraData(),&cr)
	if e!=nil {
		log.Println("asn1.Unmarshal",e)
		ch2.Write(msg)
		ch2.CloseWrite()
		return
	}
	if cr.Hotness<Level {
		cr.Hotness++
		b,e := asn1.Marshal(cr)
		if e!=nil {
			log.Println("asn1.Marshal",e)
			ch2.Write(msg)
			ch2.CloseWrite()
			return
		}
		cl := selClient()
		if cl==nil {
			msg[0] = 200
			log.Println("No Client")
			ch2.Write(msg)
			ch2.CloseWrite()
			return
		}
		
		ch,rq,e := cl.open(dns_req1,b)
		if e!=nil {
			msg[0] = 200
			log.Println("cl.open",dns_req1,e)
			ch2.Write(msg)
			ch2.CloseWrite()
			return
		}
		go DevNullRequest(rq)
		go ch_proxy_copy(ch,ch2) /* Copy Server Input to Client Output */
		ch.CloseWrite() /* Close Server Output */
		return
	}
	
	addr, e := net.ResolveIPAddr("ip", cr.Name)
	if e!=nil {
	}else{
		IPB := []byte(addr.IP)
		msg[0] = byte(len(IPB))
		copy(msg[1:],IPB)
	}
	ch2.Write(msg)
	ch2.CloseWrite()
}

/* Old, 'insecure' resolve */
func OldResolve(name string) (net.IP, error){
	if !AllowInsecure { return nil, errors.New("Insecure Operation") }
	
	cr := dnsRequest1{ name, 1 }
	
	b,e := asn1.Marshal(cr)
	if e!=nil { return nil,e }
	
	cl := selClient()
	if cl==nil { return nil,errors.New("No client!") }
	
	ch,rq,e := cl.open(dns_req1,b)
	if e!=nil {
		log.Println("resolve:",e)
		return nil,e
	}
	go DevNullRequest(rq)
	msg := make([]byte,16+1)
	_,e = io.ReadFull(ch,msg)
	if e!=nil {
		log.Println("resolve:",e)
		return nil,e
	}
	
	switch msg[0] {
	case 0: return nil,errors.New("No such name!")
	case 200: return nil,errors.New("Network Problems!")
	case 4,16:break
	default:
		return nil,errors.New("Unknown error!")
	}
	
	return net.IP(msg[1:][:msg[0]]),e
}

