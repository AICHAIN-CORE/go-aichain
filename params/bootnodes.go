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

package params

// MainnetBootnodes are the enode URLs of the P2P bootstrap nodes running on
// the main AICHAIN network.
var MainnetBootnodes = []string{
	// AICHAIN Foundation Go Bootnodes
/*
	"enode://b6900d502647c234161295c1c0b8bd8de2cb785a4c9b4660bb3da7d41725f6a6a4c0eafde727be0592dfcf86c22799fa3fc68ddf51aa338a349ad11988aabb88@bj.bn.aichain.me:30301",  // BJ.CN
	"enode://095281c13985d1d413ff965c0b84b9a85b8026cd0bf1987072b68b511b213c34da90b080c0259b854292b232f2816704f4a941be475c748229d4ea494d6a6e1a@hz.bn.aichain.me:30301",  // HZ.CN
	"enode://82c5fcf08175dbe991cce6a740756a13b0b4e7dd201484ca501e456cf5d8d7e60b2d299c01e66ab6fb6e9525d5cbe58a23b9ac1853de1d5417e4f3164b8eaaab@zjk.bn.aichain.me:30301", // ZJK.CN
	"enode://772b2c31dc64b4e7801c4b3a0e52df2dce2bcb61815e6e461fc2734c59a6d49c55d903514e46ee63beec798ddbe3926323397f4c6a1febfa54749741717dbfed@sh.bn.aichain.me:30301",  // SH.CN
	"enode://ce6d2f459807f3ec4c5f21ed00376c25fdf70bb175c19e80dd43f2d79634661fec5575dba239e2a0348b7835f8042c8989bc295ff41832646bf6063f9c2cc7b8@sz.bn.aichain.me:30301",  // SZ.CN
	"enode://70314a6e1a09b5de037a9ffc5e99ba9a113cd814a9493a22c45eb7c216382f6ed087b2f18f1407f4eee3083c1eb8a027d2bd3a472ecea3cdb168ed4c419221a5@hk.bn.aichain.me:30301",  // HK.CN
	"enode://e1a37da145a66532c9f57bfd3992a6ceecad0851f64555e096c25de9ed40f36d8be1f0e5284118ccca438c382afc5b4b018578a22e42152ddeb14a177b316fd5@jp.bn.aichain.me:30301",  // JP
	"enode://7955115b5abafe3b4944e1bab551baa572169c8d92a7c51acf738f4ef259954430672c2c16e8639fedfa46a4a284efb0dca07cf4e34ef31a5b610897a8cab786@sg.bn.aichain.me:30301",  // SG
	"enode://f86ada5998563bb32eed527cd16ea58a660ae14e2764af4d9ca593434a0ec96f43aec3b27573f657d8dd2cf774f86e5b6419479ae07da15837705b4684d39dad@us.bn.aichain.me:30301",  // US
	"enode://29a225f1ef7ed63ab3f373e29dcf544d65b3022924d53b9571db7485d80bcca84f9031165011ea933b2e4651750d3b8f8e9b275782efb16cf7afdf95122add84@ger.bn.aichain.me:30301", // GER
*/
	"enode://077818b75daece3ec171c96f58f273df27d9835fb47b7b7e28687ee76a5db8af3569256cb93c445a0e51ab6117086396d5da2242f85badd2daedc3b83b1ce9bc@47.96.70.105:30323",
	"enode://f752913f37fec36a59c94459ceb73bc70dc4729a7491406e90fe35163462b88b83a03d7174958d0d62441483ccc03be107ed70fc4306ccd618ae63b4b8905be5@39.104.101.184:30323",
	"enode://32af4ffeef3018493008ba43cf3a20200ea05a1b6f453a33ef2bbcdd11efe0a8eea8976904fb4d4851888c2a91bb82ac792790fe79c6832a741d12a148df8865@47.91.22.112:30323",
	"enode://1279b4272a25d7caa8295252402e483398d0aaab03ffb3a06d8ad1d348d92bb8bf700a90e462e716ed076871fedb810ff0e1dbce98957c87811625f550bd0287@47.92.38.40:30323",
    "enode://2181fe015ebb5c0932728326420a4c2e8f0650d0e15884212c346a29c577fe9a5c1618f8852ab26a1267f13a42f0c8049e0d276be616c23595c2744f9d5e91af@47.98.243.21:30323",
    "enode://cb97406cfd07f479c1595adf83f5f738fdd6a2a7e740255bd8ae9003f2f2f21d52236655e1d8a3c3a4900042c7a28f11655b094150c692d19551e465e29a3a5f@39.105.62.237:30323",
    "enode://22ee22d9fd54e61949b8c066f1b1fc9dc568115ee8bb43360224d45525d5108446f57b54aeef5963b50beb54c1035decff2c9b3c1a5dd732328d7f63d2ea2209@101.132.185.167:30323",
    "enode://472c1d4be77b502c50f601120d3b4e1efe8f8bd2fadc129cf25aa059ca71639a6a3338a978fbc18e150441984a78ea27f54e4b5e7b1c176d7e0f3bf9acc43b0e@120.79.230.10:30323",
    "enode://49ac218c7f169d5192c3672bb6c139978206b210ed6f736aba05e921c271d5207902d287f3055c7f355690406ec30bf8152a58ab12a33bc86fdd42cc1efec467@123.56.13.71:30323",
    "enode://7f052e88cda4183110f3d84f7316d1ae9ea550230da2d003870e7311fa66d612fb44d183a56042fc8015ab1142ca9af7a12cd3471df497b5518c0b481cdac3e5@47.75.160.56:30323",
    "enode://c32a8b9c7aa465eb9e41fa579ed879dd8dd3fafe7f99aba14de6894a2c31f305336783509f3e41e60b9f4f379ee13c300192fe9500653ab866eebab309f11a9b@47.254.42.75:30323",
    "enode://deb075af14dfece02fbfa7400fe72e864f332c79de42b6bacb215d9bf79ca9385fcaf11af2564590645351b0a8841ae32193d92608ac29ac8538019dadb5d019@47.74.253.244:30323",
    "enode://5bdeccad956b9011549938bc632941537c01e93ba5c1bd29a4dbeb607448eeba965b4541cc7161466affb3e620115250d3435fa609644ce30e7d9a0f5722996f@47.254.132.79:30323",
}

// TestnetBootnodes are the enode URLs of the P2P bootstrap nodes running on the
// Ropsten test network.
var TestnetBootnodes = []string{
	"enode://2ab7a10ee3e571fae09bc506543821b1d0da8874f5e85782f52b59339fa202bb560fe6b412c7bc47cfbf4751aebff76f90afc83dca96c2db548ed88a5b814700@testbootnode1.aichain.me:30301",
	"enode://a19ff2dba347d0726eab230b481e8e146384ecbd8b81e83e183fd1f7e5fec06f67f0bc0ebb5363fc8225d3af13009aa6d51d6cfef32597b5fbef3907613f7610@testbootnode2.aichain.me:30301",
	"enode://3da69fc2e537fc7d9dd8ba00fa2a9c21e2967565864c6cfe8fa3fbfd00bcb0b835c7b73113a016f18746405168f7040f96291793006fa6fa2189ab97b7fbc512@testbootnode3.aichain.me:30301",
	"enode://d149b69fb904c8b800dbd89c6a430b6038c9c28752bf728c650d6a546d1161550eb1d10e6e24f75f089584ef367234a6351b6754287cc103ecb8020978475f90@testbootnode4.aichain.me:30301",
	"enode://1461c415e371ed81931de54135d71a2e74b4da0dfcef693ac302f0414e3026d12aecd3938e8b7d9eaf6a516e44849aceba9e144d2af5173e69c1268f27812e54@47.96.69.161:30323",
    "enode://f95e92b50393b8a922ddd2a16e774b758af34903167f3eb56e9630f58dd2e546dc39fa2a84010dcea3dc636191e2c0da0d403b263756617b95e6c323f27cd4a6@47.96.69.66:30323",
}

// RinkebyBootnodes are the enode URLs of the P2P bootstrap nodes running on the
// Rinkeby test network.
var RinkebyBootnodes = []string{
	"enode://a24ac7c5484ef4ed0c5eb2d36620ba4e4aa13b8c84684e1b4aab0cebea2ae45cb4d375b77eab56516d34bfbd3c1a833fc51296ff084b770b94fb9028c4d25ccf@52.169.42.101:30323", // IE
	"enode://343149e4feefa15d882d9fe4ac7d88f885bd05ebb735e547f12e12080a9fa07c8014ca6fd7f373123488102fe5e34111f8509cf0b7de3f5b44339c9f25e87cb8@52.3.158.184:30323",  // INFURA
	"enode://b6b28890b006743680c52e64e0d16db57f28124885595fa03a562be1d2bf0f3a1da297d56b13da25fb992888fd556d4c1a27b1f39d531bde7de1921c90061cc6@159.89.28.211:30323", // AKASHA
}

// DiscoveryV5Bootnodes are the enode URLs of the P2P bootstrap nodes for the
// experimental RLPx v5 topic-discovery network.
var DiscoveryV5Bootnodes = []string{
	"enode://06051a5573c81934c9554ef2898eb13b33a34b94cf36b202b69fde139ca17a85051979867720d4bdae4323d4943ddf9aeeb6643633aa656e0be843659795007a@35.177.226.168:30323",
	"enode://0cc5f5ffb5d9098c8b8c62325f3797f56509bff942704687b6530992ac706e2cb946b90a34f1f19548cd3c7baccbcaea354531e5983c7d1bc0dee16ce4b6440b@40.118.3.223:30324",
	"enode://1c7a64d76c0334b0418c004af2f67c50e36a3be60b5e4790bdac0439d21603469a85fad36f2473c9a80eb043ae60936df905fa28f1ff614c3e5dc34f15dcd2dc@40.118.3.223:30306",
	"enode://85c85d7143ae8bb96924f2b54f1b3e70d8c4d367af305325d30a61385a432f247d2c75c45c6b4a60335060d072d7f5b35dd1d4c45f76941f62a4f83b6e75daaf@40.118.3.223:30307",
}
