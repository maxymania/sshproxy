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

/*
 Multi-Hop Anonymization Protocol for one connection. This Protocol uses
 the public key function curve448 ECDH and the cipher ChaCha20.
 A Session consists of two end points (Client and Server) and zero or more
 Intermediate stations. The Intermediate station scrambles the key-exchange
 handshake without braking it and it scrambles the communicated data without
 breaking it. The Intermediate station's input and output can not be associated
 with each other (to identify a Session), except with a 448-bit brute force attack.
*/
package scrambler

import "io"
import "encoding/binary"

import "git.schwanenlied.me/yawning/x448.git"
// XXX: Use this in production, in case the above passes away.
//import "github.com/mad-day/x448"

/*
 * And the Repository  "git.schwanenlied.me/yawning/chacha20.git"  passed away.
 *   We will miss you.
 *   R.I.P.
 *
 *
 * import "git.schwanenlied.me/yawning/chacha20.git"
 */
import "github.com/mad-day/chacha20"
import "crypto/rand"
import "crypto/cipher"
import "fmt"

const (
	ivC2S = "Client-to-Server"
	ivS2C = "Server-to-Client"
	ivP2P = "Peer---to---Peer"
)

func hex(i interface{}) string{
	return fmt.Sprintf("%X",i)
}

type CryptoRecord struct{
	Array [3][56]byte
}

type wrapper struct{
	C io.Closer
	cipher.StreamReader
	cipher.StreamWriter
}
func (w *wrapper) Close() error{
	if w.C==nil { return nil }
	return w.C.Close()
}

/*
 * x448 keys are 56 bytes big. This means, that both, KEY and NONCE of the
 * ChaCha20 cipher can be initilaized using not more than the shared secret.
 * However, as the same shared secret (which produces KEY and NONCE) is used
 * for C2S (Client-to-Server) and S2C (Server-to-Client)
 * communications, we would have the same key-stream used for two different
 * data streams, rendering them potentially vulnerable. To avoid it, we XOR
 * our constant nonces over the SECRET NONCE, provided by the shared secret,
 * in order to deviate them from each other. So, we will have two different
 * key streams.
 */
func c2sChaCha(key *[56]byte) *chacha20.Cipher {
	var lkey [56]byte
	copy(lkey[:],key[:])
	for i := 0 ; i<16; i++ { lkey[i+32] ^= ivC2S[i] } // XOR C2S nonce
	return mustChaCha(chacha20.NewCipher(lkey[:32],lkey[32:]))
}
func s2cChaCha(key *[56]byte) *chacha20.Cipher {
	var lkey [56]byte
	copy(lkey[:],key[:])
	for i := 0 ; i<16; i++ { lkey[i+32] ^= ivS2C[i] } // XOR S2C nonce
	return mustChaCha(chacha20.NewCipher(lkey[:32],lkey[32:]))
}

func mustChaCha(c *chacha20.Cipher,e error) *chacha20.Cipher {
	if e!=nil { panic(e) }
	return c
}

var E_ECDH_FAILED = fmt.Errorf("Handshake failed due to x448")

/* Client side function to start a session. */
func Initiator(srv io.ReadWriteCloser) (io.ReadWriteCloser,error){
	var t [3][56]byte
	var r CryptoRecord
	
	fail := 0
	for i := range t {
restart:
		rand.Read(t[i][:])
		if x448.ScalarBaseMult(&(r.Array[i]),&(t[i])) != 0 { goto restart } // Kick out broken private keys.
	}
	//if fail!=0 { return nil,E_ECDH_FAILED } // If an error occours afterwarts, fail.
	
	e := binary.Write(srv,binary.BigEndian,r)
	if e!=nil { return nil,e }
	e = binary.Read(srv,binary.BigEndian,&r)
	if e!=nil { return nil,e }
	
	
	for i := range t {
		fail |= x448.ScalarMult(&(r.Array[i]),&(t[i]),&(r.Array[i]))
	}
	if fail!=0 { return nil,E_ECDH_FAILED } // If an error occours afterwarts, fail.
	
	//------------------------------------------------------------
	
	c2s := make(multiStream,3)
	for i := range r.Array {
		c2s[i] = c2sChaCha(&(r.Array[i]))
	}
	
	s2c := make(multiStream,3)
	for i := range r.Array {
		s2c[i] = s2cChaCha(&(r.Array[i]))
	}
	
	return &wrapper{
		srv,
		cipher.StreamReader{s2c,srv},
		cipher.StreamWriter{c2s,srv,nil},
	},nil
}

/*
Intermediate station function to start a session.
If an error is returned, please close the connections, otherwise, don't.
*/
func Intermediate(clt io.ReadWriteCloser,srv io.ReadWriteCloser) error{
	const (
		SALT = iota
		SALT2
		CLTK
		SRVK
		N_Ts /* Number of t-Keys */
	)
	
	var t [N_Ts][56]byte
	var K [2][56]byte
	var r CryptoRecord
	var test [56]byte
	
	fail := 0
	for i := range t {
restart:
		rand.Read(t[i][:])
		if x448.ScalarBaseMult(&test,&(t[i])) != 0 { goto restart } // Kick out broken private keys.
	}
	
	//if fail!=0 { return E_ECDH_FAILED } // If an error occours afterwarts, fail.
	
	//-------------------------------------------------------
	
	/*  [A,B,X] -> [B,C,X]  */
	
	e := binary.Read(clt,binary.BigEndian,&r)
	if e!=nil { return e }
	
	//fail = 0
	
	fail |= x448.ScalarMult(&(K[0]),&(t[CLTK]),&(r.Array[0]))
	r.Array[0] = r.Array[1]
	fail |= x448.ScalarBaseMult(&(r.Array[1]),&(t[SRVK]))
	
	/* Scramble B and X */
	
	fail |= x448.ScalarMult(&(r.Array[0]),&(t[SALT]),&(r.Array[0]))
	fail |= x448.ScalarMult(&(r.Array[2]),&(t[SALT2]),&(r.Array[2]))
	
	if fail!=0 { return E_ECDH_FAILED } // If an error occours afterwarts, fail.
	
	e = binary.Write(srv,binary.BigEndian,r)
	if e!=nil { return e }
	
	//-------------------------------------------------------
	
	/*  [B,C,X] -> [A,B,X]  */
	
	e = binary.Read(srv,binary.BigEndian,&r)
	if e!=nil { return e }
	
	//fail = 0
	
	fail |= x448.ScalarMult(&(K[1]),&(t[SRVK]),&(r.Array[1]))
	r.Array[1] = r.Array[0]
	fail |= x448.ScalarBaseMult(&(r.Array[0]),&(t[CLTK]))
	
	/* Scramble B and X */
	
	fail |= x448.ScalarMult(&(r.Array[1]),&(t[SALT]),&(r.Array[1]))
	fail |= x448.ScalarMult(&(r.Array[2]),&(t[SALT2]),&(r.Array[2]))
	
	if fail!=0 { return E_ECDH_FAILED } // If an error occours afterwarts, fail.
	
	e = binary.Write(clt,binary.BigEndian,r)
	if e!=nil { return e }
	
	//-------------------------------------------------------
	
	/* Apply Transcryption (A and C) */
	
	
	c2s := make(multiStream,2)
	for i := range K {
		c2s[i] = c2sChaCha(&(K[i]))
	}
	
	s2c := make(multiStream,2)
	for i := range K {
		s2c[i] = s2cChaCha(&(K[i]))
	}
	
	eclt := cipher.StreamReader{c2s,clt}
	esrv := cipher.StreamReader{s2c,srv}
	
	go dispatch(eclt,srv)
	go dispatch(esrv,clt)
	
	return nil
}

/* Server side function to start a session. */
func Endpt(clt io.ReadWriteCloser) (io.ReadWriteCloser,error) {
	var t [3][56]byte
	var r,r2 CryptoRecord
	
	fail := 0
	for i := range t {
restart:
		rand.Read(t[i][:])
		if x448.ScalarBaseMult(&(r2.Array[i]),&(t[i])) != 0 { goto restart } // Kick out broken private keys.
	}
	
	e := binary.Read(clt,binary.BigEndian,&r)
	if e!=nil { return nil,e }
	
	for i := range t {
		fail |= x448.ScalarMult(&(r.Array[i]),&(t[i]),&(r.Array[i]))
	}
	if fail!=0 { return nil,E_ECDH_FAILED } // If an error occours afterwarts, fail.
	
	e = binary.Write(clt,binary.BigEndian,r2)
	if e!=nil { return nil,e }
	
	
	//-------------------------------------------------------
	
	c2s := make(multiStream,3)
	for i := range r.Array {
		c2s[i] = c2sChaCha(&(r.Array[i]))
	}
	
	s2c := make(multiStream,3)
	for i := range r.Array {
		s2c[i] = s2cChaCha(&(r.Array[i]))
	}
	
	return &wrapper{
		clt,
		cipher.StreamReader{c2s,clt},
		cipher.StreamWriter{s2c,clt,nil},
	},nil
}

