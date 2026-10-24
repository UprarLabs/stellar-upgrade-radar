module example.com/replace-path

go 1.25

require github.com/stellar/go-stellar-sdk v0.7.3

replace github.com/stellar/go-stellar-sdk => ../local/sdk
