// Copyright 2014 The go-aichain Authors
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

// Package miner implements AICHAIN block creation and mining.
package miner

import (
	"fmt"
	"math/big"
	"os"
	"sync/atomic"
	"time"

	"github.com/AICHAIN-CORE/go-aichain/accounts"
	"github.com/AICHAIN-CORE/go-aichain/common"
	"github.com/AICHAIN-CORE/go-aichain/consensus"
	"github.com/AICHAIN-CORE/go-aichain/core"
	"github.com/AICHAIN-CORE/go-aichain/core/state"
	"github.com/AICHAIN-CORE/go-aichain/core/types"
	"github.com/AICHAIN-CORE/go-aichain/eth/downloader"
	"github.com/AICHAIN-CORE/go-aichain/ethdb"
	"github.com/AICHAIN-CORE/go-aichain/event"
	"github.com/AICHAIN-CORE/go-aichain/log"
	"github.com/AICHAIN-CORE/go-aichain/p2p"
	"github.com/AICHAIN-CORE/go-aichain/params"
)

// Backend wraps all methods required for mining.
type Backend interface {
	AccountManager() *accounts.Manager
	BlockChain() *core.BlockChain
	TxPool() *core.TxPool
	ChainDb() ethdb.Database
	Downloader() *downloader.Downloader // add for check peers num before start mining!!!
	NodeServer() *p2p.Server
}

// Miner creates blocks and searches for proof-of-work values.
type Miner struct {
	mux *event.TypeMux

	worker *worker

	coinbase common.Address
	mining   int32
	eth      Backend
	engine   consensus.Engine

	canStart    int32 // can start indicates whether we can start the mining operation
	shouldStart int32 // should start indicates whether we should start after sync
}

func New(eth Backend, config *params.ChainConfig, mux *event.TypeMux, engine consensus.Engine) *Miner {
	miner := &Miner{
		eth:      eth,
		mux:      mux,
		engine:   engine,
		worker:   newWorker(config, engine, common.Address{}, eth, mux),
		canStart: 1,
	}
	miner.Register(NewCpuAgent(eth.BlockChain(), engine))
	go miner.update()

	return miner
}

// update keeps track of the downloader events. Please be aware that this is a one shot type of update loop.
// It's entered once and as soon as `Done` or `Failed` has been broadcasted the events are unregistered and
// the loop is exited. This to prevent a major security vuln where external parties can DOS you with blocks
// and halt your mining operation for as long as the DOS continues.
func (self *Miner) update() {
	events := self.mux.Subscribe(downloader.StartEvent{}, downloader.DoneEvent{}, downloader.FailedEvent{})
out:
	for ev := range events.Chan() {
		switch ev.Data.(type) {
		case downloader.StartEvent:
			atomic.StoreInt32(&self.canStart, 0)
			if self.Mining() {
				self.Stop()
				atomic.StoreInt32(&self.shouldStart, 1)
				log.Info("Mining aborted due to sync")
			}
		case downloader.DoneEvent, downloader.FailedEvent:
			shouldStart := atomic.LoadInt32(&self.shouldStart) == 1

			atomic.StoreInt32(&self.canStart, 1)
			atomic.StoreInt32(&self.shouldStart, 0)
			if shouldStart {
				self.Start(self.coinbase)
			}
			// unsubscribe. we're only interested in this event once
			events.Unsubscribe()
			// stop immediately and ignore all further pending events
			break out
		}
	}
}

func (self *Miner) Start(coinbase common.Address) {
	atomic.StoreInt32(&self.shouldStart, 1)
	self.worker.setEtherbase(coinbase)
	self.coinbase = coinbase

	stateDb, err := self.eth.BlockChain().StateAt(self.eth.BlockChain().CurrentBlock().Root())
	if err == nil {
		balance := stateDb.GetBalance(coinbase)
		if !self.eth.BlockChain().Config().CheckMinerAccountAit(balance) {
			fmt.Printf("Not enough AIT for the miner account, %s AIT needed, balance of current miner account: %s AIT.\n", self.eth.BlockChain().Config().AitNeedForMinerAccount().Text(10), balance.Div(balance, big.NewInt(1e+18)).Text(10))
			os.Exit(1)
		}
	} else {
		log.Error("get coinbase balance error\n", "err", err)
		os.Exit(1)
	}

	if atomic.LoadInt32(&self.canStart) == 0 {
		log.Info("Network syncing, will start miner afterwards")
		return
	}

	for {
		npeers := self.eth.NodeServer().PeerCount()
		fmt.Printf("Can not start miner, the miner must have peers. Current peers num=%d\n", npeers)
		if npeers <= 0 {
			log.Info("Error: There is no peers connected!")
			time.Sleep(10 * time.Second)
		} else {
			break
		}
	}

	//When forked, miner stopped, and the chain stopped.
	// var (
	// 	syncing bool
	// )

	// sync := self.eth.Downloader().Progress()
	// syncing = self.eth.BlockChain().CurrentHeader().Number.Uint64() >= sync.HighestBlock
	// if syncing {
	// } else {
	// 	log.Info("Error: Node need sync blockchain data before start mining!")
	// 	return
	// }

	atomic.StoreInt32(&self.mining, 1)

	log.Info("Starting mining operation")
	self.worker.start()
	self.worker.commitNewWork()
}

func (self *Miner) Stop() {
	self.worker.stop()
	atomic.StoreInt32(&self.mining, 0)
	atomic.StoreInt32(&self.shouldStart, 0)
}

func (self *Miner) Register(agent Agent) {
	if self.Mining() {
		agent.Start()
	}
	self.worker.register(agent)
}

func (self *Miner) Unregister(agent Agent) {
	self.worker.unregister(agent)
}

func (self *Miner) Mining() bool {
	return atomic.LoadInt32(&self.mining) > 0
}

func (self *Miner) HashRate() (tot int64) {
	if pow, ok := self.engine.(consensus.PoW); ok {
		tot += int64(pow.Hashrate())
	}
	// do we care this might race? is it worth we're rewriting some
	// aspects of the worker/locking up agents so we can get an accurate
	// hashrate?
	for agent := range self.worker.agents {
		if _, ok := agent.(*CpuAgent); !ok {
			tot += agent.GetHashRate()
		}
	}
	return
}

func (self *Miner) SetExtra(extra []byte) error {
	if uint64(len(extra)) > params.MaximumExtraDataSize {
		return fmt.Errorf("Extra exceeds max length. %d > %v", len(extra), params.MaximumExtraDataSize)
	}
	self.worker.setExtra(extra)
	return nil
}

// Pending returns the currently pending block and associated state.
func (self *Miner) Pending() (*types.Block, *state.StateDB) {
	return self.worker.pending()
}

// PendingBlock returns the currently pending block.
//
// Note, to access both the pending block and the pending state
// simultaneously, please use Pending(), as the pending state can
// change between multiple method calls
func (self *Miner) PendingBlock() *types.Block {
	return self.worker.pendingBlock()
}

func (self *Miner) SetEtherbase(addr common.Address) {
	self.coinbase = addr
	self.worker.setEtherbase(addr)
}

func (self *Miner) SetEtherbasePassphrase(passphrase string) {
	self.worker.SetEtherbasePassphrase(passphrase)
}
