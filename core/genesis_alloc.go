// Copyright 2017 The go-aichain Authors
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

package core

// Constants containing the genesis allocation of built-in genesis blocks.
// Their content is an RLP-encoded list of (address, balance) tuples.
// Use mkalloc.go to create/update them.

// nolint: misspell
const mainnetAllocData = "\xe3\xe2\x94z\xc9\xcf\xfcJ\x906\x96\xd1C\x8f\x92Z\x14*\xadmQ\xb8\u010c\x05\u0104s\xe4\xf2\xe4\xe7\x99\x00\x00\x00"

const testnetAllocData = "\xe3\u25315\xfbtu\x99\xb80\xe2\x11\vV\xe3\xc7d\x96\xdcA,T\x8c\x06\xc9\x14L\x1ci\rL\xb4\x00\x00\x00"

const rinkebyAllocData = "\xdb\u0694z\xc9\xcf\xfcJ\x906\x96\xd1C\x8f\x92Z\x14*\xadmQ\xb8\u0104]\xe0\x97\xc0"

const aiconsensusAllocData = "\xf8n\xf6\x94hF\xe9S\xb9YK`+\xab1\x9d\x11\x14\x83l+\x05\x04\x91\xa0\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xf6\x94\xb15\xfbtu\x99\xb80\xe2\x11\vV\xe3\xc7d\x96\xdcA,T\xa0\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
