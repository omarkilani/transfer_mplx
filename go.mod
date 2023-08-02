module github.com/omarkilani/transfer_mplx

go 1.20

require (
	github.com/blocto/solana-go-sdk v1.25.0
	github.com/near/borsh-go v0.3.2-0.20220516180422-1ff87d108454
)

require (
	filippo.io/edwards25519 v1.0.0-rc.1 // indirect
	github.com/mr-tron/base58 v1.2.0 // indirect
)

replace github.com/blocto/solana-go-sdk => github.com/omarkilani/solana-go-sdk v0.0.0-20230801231752-d1122952035f
