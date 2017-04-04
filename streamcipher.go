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

import "io"
import "crypto/cipher"
import "golang.org/x/crypto/sha3"


type keyStream struct{
	r io.Reader
	buf []byte
	pos, max int
}
func (k *keyStream) XORKeyStream(dst, src []byte){
	var e error
	for i,n := 0, len(src); i<n; i++ {
		if k.pos >= k.max {
			k.pos = 0
			k.max,e = k.r.Read(k.buf)
			if e!=nil { panic(e) }
		}
		dst[i] = src[i] ^ k.buf[k.pos]
		k.pos++
	}
}

func createCipher(key []byte) cipher.Stream {
	s := sha3.NewShake256()
	s.Write(key)
	ks := new(keyStream)
	ks.r = s
	ks.buf = make([]byte,1<<13)
	ks.pos = 0
	ks.max = 0
	return ks
}

type multiStream []cipher.Stream
func (m multiStream) XORKeyStream(dst, src []byte) {
	for _,k := range m {
		k.XORKeyStream(dst,src)
	}
}

