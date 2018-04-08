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
const mainnetAllocData = "\xe3\xe2\x94z\xc9\xcf\xfcJ\x906\x96\xd1C\x8f\x92Z\x14*\xadmQ\xb8\u010c\x05\x16\xcf9\x15N\xc9\xf9\x87\x00\x00\x00"

const testnetAllocData = "\xdb\u0694z\xc9\xcf\xfcJ\x906\x96\xd1C\x8f\x92Z\x14*\xadmQ\xb8\u0104]\xe0\x97\xc0"

const rinkebyAllocData = "\xdb\u0694z\xc9\xcf\xfcJ\x906\x96\xd1C\x8f\x92Z\x14*\xadmQ\xb8\u0104]\xe0\x97\xc0"
