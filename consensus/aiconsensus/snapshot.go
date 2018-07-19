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

package aiconsensus

import (
	"bytes"
	"encoding/json"
	"math/big"

	"github.com/AICHAIN-CORE/go-aichain/common"
	"github.com/AICHAIN-CORE/go-aichain/core/types"
	"github.com/AICHAIN-CORE/go-aichain/ethdb"
	"github.com/AICHAIN-CORE/go-aichain/log"
	"github.com/AICHAIN-CORE/go-aichain/params"
	lru "github.com/hashicorp/golang-lru"
)

// Vote represents a single vote that an authorized signer made to modify the
// list of authorizations.
type Vote struct {
	Signer    common.Address `json:"signer"`    // Authorized signer that cast this vote
	Block     uint64         `json:"block"`     // Block number the vote was cast in (expire old votes)
	Address   common.Address `json:"address"`   // Account being voted on to change its authorization
	Authorize bool           `json:"authorize"` // Whether to authorize or deauthorize the voted account
}

// Tally is a simple vote tally to keep the current score of votes. Votes that
// go against the proposal aren't counted since it's equivalent to not voting.
type Tally struct {
	Authorize bool `json:"authorize"` // Whether the vote is about authorizing or kicking someone
	Votes     int  `json:"votes"`     // Number of votes until now wanting to pass the proposal
}

// Snapshot is the state of the authorization voting at a given point in time.
type Snapshot struct {
	config   *params.AiConsensusConfig // Consensus engine parameters to fine tune behavior
	sigcache *lru.ARCCache             // Cache of recent block signatures to speed up ecrecover

	Number    uint64                      `json:"number"`     // Block number where the snapshot was created
	Hash      common.Hash                 `json:"hash"`       // Block hash where the snapshot was created
	Validator map[common.Address]struct{} `json:"validators"` // Set of authorized signers at this moment
	// Recents     map[uint64]common.Address   `json:"recents"`   // Set of recent signers for spam protections
	Votes       []*Vote                     `json:"votes"`        // List of votes cast in chronological order
	Tally       map[common.Address]Tally    `json:"tally"`        // Current vote tally to avoid recalculating
	Weight      map[common.Address]*big.Int `json:"weight"`       // Weight for each PoW block miner
	PooledMiner map[common.Address]bool     `json:"pooledMiners"` // Pool miner selected in last milestone

	totalBlockPooledMinerNotMined int                    // Pool miner selected in last milestone
	blockInturnNotMined           map[common.Address]int //a pooled block not mined by inturn pooled miner
}

// newSnapshot creates a new snapshot with the specified startup parameters. This
// method does not initialize the set of recent signers, so only ever use if for
// the genesis block.
func newSnapshot(config *params.AiConsensusConfig, sigcache *lru.ARCCache, number uint64, hash common.Hash, validators []common.Address, pooledminers []common.Address) *Snapshot {
	snap := &Snapshot{
		config:    config,
		sigcache:  sigcache,
		Number:    number,
		Hash:      hash,
		Validator: make(map[common.Address]struct{}),
		// Recents:                       make(map[uint64]common.Address),
		Tally:                         make(map[common.Address]Tally),
		PooledMiner:                   make(map[common.Address]bool),
		totalBlockPooledMinerNotMined: 0,
		blockInturnNotMined:           make(map[common.Address]int),
	}
	for _, validator := range validators {
		snap.Validator[validator] = struct{}{}
	}
	for _, miner := range pooledminers {
		snap.PooledMiner[miner] = true
	}
	return snap
}

// loadSnapshot loads an existing snapshot from the database.
func loadSnapshot(config *params.AiConsensusConfig, sigcache *lru.ARCCache, db ethdb.Database, hash common.Hash) (*Snapshot, error) {
	blob, err := db.Get(append([]byte("aiconsensus-"), hash[:]...))
	if err != nil {
		return nil, err
	}
	snap := new(Snapshot)
	if err := json.Unmarshal(blob, snap); err != nil {
		return nil, err
	}
	snap.config = config
	snap.sigcache = sigcache

	return snap, nil
}

// store inserts the snapshot into the database.
func (s *Snapshot) store(db ethdb.Database) error {
	blob, err := json.Marshal(s)
	if err != nil {
		return err
	}
	return db.Put(append([]byte("aiconsensus-"), s.Hash[:]...), blob)
}

// copy creates a deep copy of the snapshot, though not the individual votes.
func (s *Snapshot) copy() *Snapshot {
	cpy := &Snapshot{
		config:    s.config,
		sigcache:  s.sigcache,
		Number:    s.Number,
		Hash:      s.Hash,
		Validator: make(map[common.Address]struct{}),
		// Recents:                       make(map[uint64]common.Address),
		Votes:                         make([]*Vote, len(s.Votes)),
		Tally:                         make(map[common.Address]Tally),
		Weight:                        make(map[common.Address]*big.Int),
		PooledMiner:                   make(map[common.Address]bool),
		totalBlockPooledMinerNotMined: s.totalBlockPooledMinerNotMined,
		blockInturnNotMined:           make(map[common.Address]int),
	}
	for signer := range s.Validator {
		cpy.Validator[signer] = struct{}{}
	}
	// for block, signer := range s.Recents {
	// 	cpy.Recents[block] = signer
	// }
	for address, tally := range s.Tally {
		cpy.Tally[address] = tally
	}
	// log.Info("address weight copy", "lastblockHash", s.Hash, "blockNuber", s.Number)
	for address, weight := range s.Weight {
		cpy.Weight[address] = new(big.Int).Set(weight)
		// log.Info("address weight copy", "address", address, "weight", weight)
	}
	for address, authorize := range s.PooledMiner {
		cpy.PooledMiner[address] = authorize
	}
	for address, number := range s.blockInturnNotMined {
		cpy.blockInturnNotMined[address] = number
	}

	copy(cpy.Votes, s.Votes)

	// for addr, authorized := range cpy.PooledMiner {
	// 	fmt.Printf("unauthorized addr:%v authorized:%v\n", addr, authorized)
	// }

	return cpy
}

// validVote returns whether it makes sense to cast the specified vote in the
// given snapshot context (e.g. don't try to add an already authorized signer).
func (s *Snapshot) validVote(address common.Address, authorize bool) bool {
	_, signer := s.Validator[address]
	return (signer && !authorize) || (!signer && authorize)
}

// cast adds a new vote into the tally.
func (s *Snapshot) cast(address common.Address, authorize bool) bool {
	// Ensure the vote is meaningful
	if !s.validVote(address, authorize) {
		return false
	}
	// Cast the vote into an existing or new tally
	if old, ok := s.Tally[address]; ok {
		old.Votes++
		s.Tally[address] = old
	} else {
		s.Tally[address] = Tally{Authorize: authorize, Votes: 1}
	}
	return true
}

// uncast removes a previously cast vote from the tally.
func (s *Snapshot) uncast(address common.Address, authorize bool) bool {
	// If there's no tally, it's a dangling vote, just drop
	tally, ok := s.Tally[address]
	if !ok {
		return false
	}
	// Ensure we only revert counted votes
	if tally.Authorize != authorize {
		return false
	}
	// Otherwise revert the vote
	if tally.Votes > 1 {
		tally.Votes--
		s.Tally[address] = tally
	} else {
		delete(s.Tally, address)
	}
	return true
}

// apply creates a new authorization snapshot by applying the given headers to
// the original one.
func (s *Snapshot) apply(headers []*types.Header) (*Snapshot, error) {
	// Allow passing in no headers for cleaner code
	if len(headers) == 0 {
		return s, nil
	}
	// Sanity check that the headers can be applied
	for i := 0; i < len(headers)-1; i++ {
		if headers[i+1].Number.Uint64() != headers[i].Number.Uint64()+1 {
			return nil, errInvalidVotingChain
		}
	}
	if headers[0].Number.Uint64() != s.Number+1 {
		return nil, errInvalidVotingChain
	}
	log.Debug("snapshot apply enter", "header[0].hash", headers[0].Hash, "blockNumber", headers[0].Number)
	// Iterate through the headers and create a new snapshot
	snap := s.copy()

	for _, header := range headers {
		// Remove any votes on checkpoint blocks
		number := header.Number.Uint64()
		// Delete the oldest signer from the recent list to allow it signing again
		// if limit := uint64(len(snap.Validator)/2 + 1); number >= limit {
		// 	delete(snap.Recents, number-limit)
		// }
		// Resolve the authorization key and check against signers
		signer, err := ecrecover(header, snap.sigcache)
		if err != nil {
			return nil, err
		}
		if header.Difficulty.Cmp(diffValidatorInTurn) == 0 ||
			header.Difficulty.Cmp(diffValidatorNoTurn) == 0 {
			//PoA
			if number%snap.config.VoteEpoch == 0 {
				snap.Votes = nil
				snap.Tally = make(map[common.Address]Tally)
			}

			if _, ok := snap.Validator[signer]; !ok {
				return nil, errUnauthorized
			}
			log.Debug("block found 1", "number", number, "diff", header.Difficulty, "signer", signer)
			// for _, recent := range snap.Recents {
			// 	if recent == signer {
			// 		return nil, errUnauthorized
			// 	}
			// }
			// snap.Recents[number] = signer

			//check whether the difficulty of the header is corret.
			inturn := snap.validatorsInturn(number, signer)
			if (inturn && header.Difficulty == diffValidatorNoTurn) || (!inturn && header.Difficulty == diffValidatorInTurn) {
				return nil, errUnauthorized
			}

			// Header authorized, discard any previous votes from the signer
			for i, vote := range snap.Votes {
				if vote.Signer == signer && vote.Address == header.Coinbase {
					// Uncast the vote from the cached tally
					snap.uncast(vote.Address, vote.Authorize)

					// Uncast the vote from the chronological list
					snap.Votes = append(snap.Votes[:i], snap.Votes[i+1:]...)
					break // only one vote allowed
				}
			}
			// Tally up the new vote from the signer
			var authorize bool
			switch {
			case bytes.Equal(header.Nonce[:], nonceAuthVote):
				authorize = true
			case bytes.Equal(header.Nonce[:], nonceDropVote):
				authorize = false
			default:
				return nil, errInvalidVote
			}
			if snap.cast(header.Coinbase, authorize) {
				snap.Votes = append(snap.Votes, &Vote{
					Signer:    signer,
					Block:     number,
					Address:   header.Coinbase,
					Authorize: authorize,
				})
			}
			// If the vote passed, update the list of signers
			if tally := snap.Tally[header.Coinbase]; tally.Votes > len(snap.Validator)/2 {
				if tally.Authorize {
					snap.Validator[header.Coinbase] = struct{}{}
				} else {
					delete(snap.Validator, header.Coinbase)

					// // Signer list shrunk, delete any leftover recent caches
					// if limit := uint64(len(snap.Validator)/2 + 1); number >= limit {
					// 	delete(snap.Recents, number-limit)
					// }
					// Discard any previous votes the deauthorized signer cast
					for i := 0; i < len(snap.Votes); i++ {
						if snap.Votes[i].Signer == header.Coinbase {
							// Uncast the vote from the cached tally
							snap.uncast(snap.Votes[i].Address, snap.Votes[i].Authorize)

							// Uncast the vote from the chronological list
							snap.Votes = append(snap.Votes[:i], snap.Votes[i+1:]...)

							i--
						}
					}
				}
				// Discard any previous votes around the just changed account
				for i := 0; i < len(snap.Votes); i++ {
					if snap.Votes[i].Address == header.Coinbase {
						snap.Votes = append(snap.Votes[:i], snap.Votes[i+1:]...)
						i--
					}
				}
				delete(snap.Tally, header.Coinbase)
			}
		} else if header.Difficulty.Cmp(diffPooledMinerInTurn) == 0 {
			//PoA, but not allow to vote
			// Resolve the authorization key and check against signers
			signer, err := ecrecover(header, snap.sigcache)
			if err != nil {
				return nil, err
			}
			log.Debug("block found 2", "number", number, "diff", header.Difficulty, "signer", signer)
			if _, ok := snap.PooledMiner[signer]; !ok {
				return nil, errUnauthorized
			}
			//all block in the single block is mined by a pooled miner.
			// for _, recent := range snap.Recents {
			// 	if recent == signer {
			// 		return nil, errUnauthorized
			// 	}
			// }
			//snap.Recents[number] = signer

			//check whether the difficulty of the header is corret.
			inturn := snap.pooledMinersInturn(number, signer)
			if !inturn {
				return nil, errUnauthorized
			}
			snap.totalBlockPooledMinerNotMined = 0
			snap.blockInturnNotMined[signer] = 0
			//can not vote, not vote process
		} else if header.Difficulty.Cmp(diffPooledMinerNoTurnPow) == 0 {
			//PoW
			log.Debug("block found 3", "number", number, "diff", header.Difficulty, "coinbase", signer)
			if _, ok := snap.PooledMiner[signer]; !ok {
				return nil, errUnauthorized
			}
			//check whether the difficulty of the header is corret.
			inturn := snap.pooledMinersInturn(number, signer)
			if inturn {
				return nil, errUnauthorized
			}
			snap.totalBlockPooledMinerNotMined = 0
			//unauthorized the inturn pooled miner, make a penalty
			addr := snap.findInturnPooledMiners(number)
			if addr != (common.Address{}) {
				if _, ok := snap.blockInturnNotMined[addr]; !ok {
					snap.blockInturnNotMined[addr] = 0
				}
				log.Debug("current pooled miner status:", "addr", addr, "number", snap.blockInturnNotMined[addr])
				if snap.blockInturnNotMined[addr] < maxBlockOnePooledMinerNotMined {
					snap.blockInturnNotMined[addr]++
					log.Debug("current pooled miner status:", "addr", addr, "number", snap.blockInturnNotMined[addr])
					if authorized, ok := snap.PooledMiner[addr]; ok && authorized &&
						snap.blockInturnNotMined[addr] >= maxBlockOnePooledMinerNotMined {
						snap.PooledMiner[addr] = false
						log.Debug("unauthorized", "addr", addr)
						for addr, authorized := range snap.PooledMiner {
							log.Debug("current pooled miner status:", "addr", addr, "authorized", authorized)
						}
					}
				}
			}
		} else if header.Difficulty.Cmp(diffPow) == 0 || header.Difficulty.Cmp(diffNotPooledMinerPow) == 0 {
			//PoW, the weight will count
			log.Debug("block found 4", "number", number, "diff", header.Difficulty, "coinbase", signer)
			if _, ok := snap.Validator[signer]; ok {
				return nil, errUnauthorized
			}
			if header.Difficulty.Cmp(diffNotPooledMinerPow) == 0 {
				log.Debug("Check total block pooled miner not mined", "diff", diffNotPooledMinerPow, "number", snap.totalBlockPooledMinerNotMined)
				if snap.totalBlockPooledMinerNotMined < maxBlockPooledMinerNotMined {
					snap.totalBlockPooledMinerNotMined++
					log.Debug("Check total block pooled miner not mined", "number", snap.totalBlockPooledMinerNotMined)
					if snap.totalBlockPooledMinerNotMined >= maxBlockPooledMinerNotMined {
						for addr := range snap.PooledMiner {
							snap.PooledMiner[addr] = false
						}
						log.Debug("Unauthorize all pooled miner.")
						for addr, authorized := range snap.PooledMiner {
							log.Debug("current pooled miner status:", "addr", addr, "authorized", authorized)
						}
					}
				}
				addr := snap.findInturnPooledMiners(number)
				if addr != (common.Address{}) {
					if _, ok := snap.blockInturnNotMined[addr]; !ok {
						snap.blockInturnNotMined[addr] = 0
					}
					log.Debug("current pooled miner status:", "addr", addr, "number", snap.blockInturnNotMined[addr])
					if snap.blockInturnNotMined[addr] < maxBlockOnePooledMinerNotMined {
						snap.blockInturnNotMined[addr]++
						log.Debug("current pooled miner status:", "addr", addr, "number", snap.blockInturnNotMined[addr])
						if authorized, ok := snap.PooledMiner[addr]; ok && authorized &&
							snap.blockInturnNotMined[addr] >= maxBlockOnePooledMinerNotMined {
							snap.PooledMiner[addr] = false
							log.Debug("unauthorized", "addr", addr)
							for addr, authorized := range snap.PooledMiner {
								log.Debug("current pooled miner status:", "addr", addr, "authorized", authorized)
							}
						}
					}
				}
			}
			//add weight 1 (block reward) + GasUsed/GasLimit
			if _, ok := snap.Weight[signer]; !ok {
				snap.Weight[signer] = big.NewInt(int64(100 + header.GasUsed*100/header.GasLimit))
				log.Debug("weight set", "addr", signer, "weight", snap.Weight[signer])
			} else {
				snap.Weight[signer].Add(snap.Weight[signer], big.NewInt(int64(100+header.GasUsed*100/header.GasLimit)))
				log.Debug("weight add", "addr", signer, "weight", snap.Weight[signer])
			}
		} else {
			return nil, errUnauthorized
		}
		if number%snap.config.Epoch == 0 {
			//remove pooled miner, first one and last one
			//reset parameters
			log.Debug("Epoch reached, start to set pooled miners", "epoch", snap.config.Epoch, "blockNumber", number)
			snap.totalBlockPooledMinerNotMined = 0
			unauthorizedMiner := make(map[common.Address]struct{})
			for address := range snap.blockInturnNotMined {
				delete(snap.blockInturnNotMined, address)
			}
			//remove pooled miner that is unauthorized
			for address, authorized := range snap.PooledMiner {
				if !authorized {
					delete(snap.PooledMiner, address)
					unauthorizedMiner[address] = struct{}{}
					log.Debug("Remove miner unauthorized", "addr", address)
				}
			}
			//remove last two pooled miner
			sortedPooledMiners := snap.pooledMiners()
			randomNumber := number / snap.config.Epoch % uint64(snap.config.MaxPooledMinerNumber/2)
			pooledMinerNeedRemove := 2 - (snap.config.MaxPooledMinerNumber - len(sortedPooledMiners))
			if pooledMinerNeedRemove > 0 {
				log.Debug("Remove pooled miner in random", "number", pooledMinerNeedRemove)
				count := 0
				for i := 0; i < len(sortedPooledMiners) && count < pooledMinerNeedRemove; i++ {
					if i%(snap.config.MaxPooledMinerNumber/2) == int(randomNumber) {
						delete(snap.PooledMiner, sortedPooledMiners[i])
						unauthorizedMiner[sortedPooledMiners[i]] = struct{}{}
						log.Debug("Remove two pooled miner in random", "addr", sortedPooledMiners[i], "pos", i)
						count++
					}
				}
			}

			//sort miner
			powMiners := snap.sortPoWMinerByWeight()
			for i, miner := range powMiners {
				if weight, ok := snap.Weight[miner]; ok {
					log.Debug("Sorted Miner Weight", "index", i+1, "addr", miner, "weight", weight)
				}
			}
			//add miner to pooled miner
			for _, miner := range powMiners {
				//not allow validator to mine
				if _, ok := snap.Validator[miner]; ok {
					//error
					continue
				}
				//not allow pooled miner already unauthorized, such as not mined in turun, last two pooled miner.
				if _, ok := unauthorizedMiner[miner]; ok {
					//not allowed
					continue
				}
				//already in pooled miner map.
				if _, ok := snap.PooledMiner[miner]; ok {
					//already exist
					continue
				}
				//add the miner to the miner pool.
				snap.PooledMiner[miner] = true
				if weight, ok := snap.Weight[miner]; ok {
					log.Debug("Add pooled miner", "addr", miner, "weight", weight)
				}
				if len(snap.PooledMiner) >= snap.config.MaxPooledMinerNumber {
					break
				}
			}
			log.Debug("current pooled miner", "number", len(snap.PooledMiner))
			pooledMiners := snap.pooledMiners()
			for i := 0; i < len(pooledMiners); i++ {
				if authorized, ok := snap.PooledMiner[pooledMiners[i]]; ok {
					log.Debug("current pooled miner status:", "addr", pooledMiners[i], "authorized", authorized)
				}
			}
			//reset paramaters
			snap.Weight = make(map[common.Address]*big.Int)
			snap.blockInturnNotMined = make(map[common.Address]int)
		}
	}
	snap.Number += uint64(len(headers))
	snap.Hash = headers[len(headers)-1].Hash()
	log.Debug("snapshot apply exit", "snap.Hash", snap.Hash, "snap.Number", snap.Number)
	return snap, nil
}

// validator retrieves the list of authorized validator in ascending order.
func (s *Snapshot) validators() []common.Address {
	validators := make([]common.Address, 0, len(s.Validator))
	for validator := range s.Validator {
		validators = append(validators, validator)
	}
	for i := 0; i < len(validators); i++ {
		for j := i + 1; j < len(validators); j++ {
			if bytes.Compare(validators[i][:], validators[j][:]) > 0 {
				validators[i], validators[j] = validators[j], validators[i]
			}
		}
	}
	return validators
}

func (s *Snapshot) pooledMiners() []common.Address {
	pooledMiners := make([]common.Address, 0, len(s.PooledMiner))
	for miner, authorized := range s.PooledMiner {
		if authorized {
			pooledMiners = append(pooledMiners, miner)
		}
	}
	for i := 0; i < len(pooledMiners); i++ {
		for j := i + 1; j < len(pooledMiners); j++ {
			if bytes.Compare(pooledMiners[i][:], pooledMiners[j][:]) > 0 {
				pooledMiners[i], pooledMiners[j] = pooledMiners[j], pooledMiners[i]
			}
		}
	}
	return pooledMiners
}

// inturn returns if a signer at a given block height is in-turn or not.
func (s *Snapshot) calcDifficulty(number uint64, signer common.Address) *big.Int {
	// fmt.Printf("calcDifficulty blocknumber=%v\n", number)
	if number%s.config.BlockValidNumber == 0 {
		//validator block
		//only validator is allowed to mine the block
		if _, ok := s.Validator[signer]; ok {
			if s.validatorsInturn(number, signer) {
				// log.Info("calcDifficulty return1", "blockNumber", number, "signer", signer, "diff", diffValidatorInTurn)
				return diffValidatorInTurn
			}
			// log.Info("calcDifficulty return2", "blockNumber", number, "signer", signer, "diff", diffValidatorNoTurn)
			return diffValidatorNoTurn
		}
		// log.Info("calcDifficulty return3", "blockNumber", number, "signer", signer, "diff", diffInvalid)
		return diffInvalid
	} else if (number+1)%s.config.BlockValidNumber == 0 {
		//pow block
		//validator is not allowed to mine in pow mode.
		if _, ok := s.Validator[signer]; ok {
			// log.Info("calcDifficulty return4", "blockNumber", number, "signer", signer, "diff", diffInvalid)
			return diffInvalid
		}
		// log.Info("calcDifficulty return5", "blockNumber", number, "signer", signer, "diff", diffPow)
		return diffPow
	}

	// fmt.Printf("calcDifficulty blocknumber:%v\n", number)

	// for addr, authorized := range s.PooledMiner {
	// 	fmt.Printf("addr:%v authorized:%v\n", addr, authorized)
	// }

	//other pooled block
	//only pooled miner is allowed to mine.
	//and the miner unauthorized is not allowed to mine.
	if authorized, ok := s.PooledMiner[signer]; ok {
		if !authorized {
			// log.Info("calcDifficulty return6", "blockNumber", number, "signer", signer, "diff", diffNotPooledMinerPow)
			return diffNotPooledMinerPow
		}
		if s.pooledMinersInturn(number, signer) {
			// log.Info("calcDifficulty return7", "blockNumber", number, "signer", signer, "diff", diffPooledMinerInTurn)
			return diffPooledMinerInTurn
		}
		// log.Info("calcDifficulty return8", "blockNumber", number, "signer", signer, "diff", diffPooledMinerNoTurnPow)
		return diffPooledMinerNoTurnPow
	}
	if _, ok := s.Validator[signer]; ok {
		// log.Info("calcDifficulty return9", "blockNumber", number, "signer", signer, "diff", diffInvalid)
		return diffInvalid
	}
	// log.Info("calcDifficulty return10", "blockNumber", number, "signer", signer, "diff", diffNotPooledMinerPow)
	return diffNotPooledMinerPow
}

// validatorInturn returns if a signer at a given round is in-turn or not.
func (s *Snapshot) validatorsInturn(number uint64, signer common.Address) bool {
	number = number % epochLength
	round := number / s.config.BlockValidNumber
	validators, offset := s.validators(), 0
	for offset < len(validators) && validators[offset] != signer {
		offset++
	}
	return (round % uint64(len(validators))) == uint64(offset)
}

// pooledMinerInturn returns if a signer at a given round is in-turn or not.
func (s *Snapshot) pooledMinersInturn(number uint64, signer common.Address) bool {
	number = number % epochLength
	round := number / s.config.BlockValidNumber
	pooledMiners, offset := s.pooledMiners(), 0
	for offset < len(pooledMiners) && pooledMiners[offset] != signer {
		offset++
	}
	return (round % uint64(len(pooledMiners))) == uint64(offset)
}

func (s *Snapshot) findInturnPooledMiners(number uint64) common.Address {
	number = number % epochLength
	round := number / s.config.BlockValidNumber
	pooledMiners, offset := s.pooledMiners(), 0
	// fmt.Printf("pooledMiners:%v\n", pooledMiners)
	for offset < len(pooledMiners) {
		// fmt.Printf("pooledMiner %v:%v\n", offset, pooledMiners[offset])
		if (round % uint64(len(pooledMiners))) == uint64(offset) {
			return pooledMiners[offset]
		}
		offset++
	}
	return common.Address{}
}

// validator retrieves the list of authorized validator in ascending order.
func (s *Snapshot) sortPoWMinerByWeight() []common.Address {
	miners := make([]common.Address, 0, len(s.Weight))
	for miner := range s.Weight {
		miners = append(miners, miner)
	}
	for i := 0; i < len(miners); i++ {
		for j := i + 1; j < len(miners); j++ {
			if s.Weight[miners[i]].Cmp(s.Weight[miners[j]]) < 0 {
				miners[i], miners[j] = miners[j], miners[i]
			} else if s.Weight[miners[i]].Cmp(s.Weight[miners[j]]) == 0 {
				if bytes.Compare(miners[i][:], miners[j][:]) < 0 {
					miners[i], miners[j] = miners[j], miners[i]
				}
			}
		}
	}
	return miners
}
