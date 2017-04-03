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

func rq_dns1(r *ssh.Request){
	var cr dnsRequest1
	_,e := asn1.Unmarshal(r.Payload,&cr)
	if e!=nil {
		log.Println("asn1.Unmarshal",e)
		r.Reply(false,nil)
		return
	}
	if cr.Hotness<Level {
		cr.Hotness++
		b,e := asn1.Marshal(cr)
		if e!=nil {
			log.Println("asn1.Marshal",e)
			r.Reply(false,nil)
			return
		}
		cl := selClient()
		if cl==nil {
			log.Println("No Client!")
			r.Reply(false,nil)
			return
		}
		ok,data,e := cl.send(dns_req1,true,b)
		if !ok {
			log.Println("cl.send",dns_req1,ok,data,e)
		}
		r.Reply(ok,data)
		return
	}
	addr, e := net.ResolveIPAddr("ip", cr.Name)
	if e!=nil {
		log.Println("net.ResolveIPAddr:",cr.Name,e)
		r.Reply(false,nil)
		return
	}
	e = r.Reply(true,[]byte(addr.IP))
	log.Println("r.Reply",true,addr.IP,e)
}

func Resolve(name string) (net.IP, error){
	cr := dnsRequest1{ name, 1 }
	
	b,e := asn1.Marshal(cr)
	if e!=nil { return nil,e }
	
	cl := selClient()
	if cl==nil { return nil,errors.New("No client!") }
	
	ok,data,e := cl.send(dns_req1,true,b)
	if !ok {
		log.Println("resolve:",ok,data,e)
		if e==nil { e = errors.New("No such name!") }
		return nil,e
	}
	switch len(data) {
	case 4,16:break
	default:
		return nil,errors.New("invalid length!")
	}
	
	return net.IP(data),e
}

