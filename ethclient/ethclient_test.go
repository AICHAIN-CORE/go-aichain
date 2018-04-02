// Copyright 2016 The go-aichain Authors
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

package ethclient

import "github.com/AICHAIN-CORE/go-aichain"

// Verify that Client implements the aichain interfaces.
var (
	_ = aichain.ChainReader(&Client{})
	_ = aichain.TransactionReader(&Client{})
	_ = aichain.ChainStateReader(&Client{})
	_ = aichain.ChainSyncReader(&Client{})
	_ = aichain.ContractCaller(&Client{})
	_ = aichain.GasEstimator(&Client{})
	_ = aichain.GasPricer(&Client{})
	_ = aichain.LogFilterer(&Client{})
	_ = aichain.PendingStateReader(&Client{})
	// _ = aichain.PendingStateEventer(&Client{})
	_ = aichain.PendingContractCaller(&Client{})
)
