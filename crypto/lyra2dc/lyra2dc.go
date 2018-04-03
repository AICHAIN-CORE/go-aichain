// Copyright 2015 The go-aichain Authors
// This file is part of the go-aichain library.
//
// The go-aichain library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-aichain library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-aichain library. If not, see <http://www.gnu.org/licenses/>.

// Package lyra2dc wraps the bitcoin lyra2dc C library.
package lyra2dc

/*
#cgo CFLAGS: -I./liblyra2dc

#include "./liblyra2dc/blake.c"
#include "./liblyra2dc/bmw.c"
#include "./liblyra2dc/cubehash.c"
#include "./liblyra2dc/groestl.c"
#include "./liblyra2dc/keccak.c"
#include "./liblyra2dc/Lyra2.c"
#include "./liblyra2dc/skein.c"
#include "./liblyra2dc/Sponge.c"
#include "./liblyra2dc/Lyra2DC.h"
#include "./liblyra2dc/Lyra2DC.c"
*/
import "C"

import (
	"errors"
	"unsafe"
)

func init() {
	// lyra2DC do not need any process on init!
}

var (
	ErrUnkownErrorLyra2DC = errors.New("Unkown error on lyra2DC")
)

// Sign creates a recoverable ECDSA signature.
// The produced signature is in the 65-byte [R || S || V] format where V is 0 or 1.
//
// The caller is responsible for ensuring that msg cannot be chosen
// directly by an attacker. It is usually preferable to use a cryptographic
// hash function on any input before handing it to this function.
func Do_lyra2DC(msg []byte) ([]byte, error) {
	var (
		outHash = make([]byte, 32)
	)
	msgIn := (*C.uchar)(unsafe.Pointer(&msg[0]))
	hashdata := (*C.uchar)(unsafe.Pointer(&outHash[0]))
	C.lyra2dc_hash(msgIn, C.size_t(len(msg)), hashdata)
	return outHash, nil
}
