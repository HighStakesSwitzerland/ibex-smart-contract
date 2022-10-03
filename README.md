# Reference Implementation

This is an implementation of a [SNIP-20](https://github.com/SecretFoundation/SNIPs/blob/master/SNIP-20.md), [SNIP-21](https://github.com/SecretFoundation/SNIPs/blob/master/SNIP-21.md), [SNIP-22](https://github.com/SecretFoundation/SNIPs/blob/master/SNIP-22.md), [SNIP-23](https://github.com/SecretFoundation/SNIPs/blob/master/SNIP-23.md) and [SNIP-24](https://github.com/SecretFoundation/SNIPs/blob/master/SNIP-24.md) compliant token contract.
At the time of token creation you may configure:
* Minimum Stake Amount: u128 value for minimum amount on stake tx. DEFAULT: 1_000_000
* Unbonding Period: The duration of unbonding before being able to claim. DEFAULT: 60 seconds

## Usage examples:

To create a new token:

```secretcli tx compute instantiate <contract_number> --from a --label IBEX '{"name": "sibex", "symbol": "IBEX", "label": "IBEX", "decimals": 0, "admin": <admin_wallet>, "initial_balances": [{"address": "secret1ap26qrlp8mcq2pg6r47w43l0y8zkqm8a450s03", "unstaked": "100000", "staked": "100"}], "prng_seed": "dG90b2xhcHJhbGluZQo=", "config": { "unbonding_period": {"time": 60}, "min_stake_amount": "1000"}}'```
`prng_seed` is a random string base64 encoded used as salt
`unbonding_period` is in seconds (604800 for 1 week)
The `admin` field is optional and will default to the "--from" address if you do not specify it.
The `initial_balances` field is optional, and you can specify as many addresses/balances as you like.  The `config` field as well as every field in the `config` is optional.


To get the token info/config:

```
secretcli q compute query <contract-address> '{"token_info": {}}'
{"token_info":{"name":"sibex","symbol":"IBEX","decimals":0,"total_supply":"100100"}}
```

```
secretcli q compute query <contract-address> '{"token_config": {}}'
{"token_config":{"min_stake_amount":"100","unbonding_period":{"time":60}}}
```

To set your viewing key:

```secretcli tx compute execute <contract-address> '{"create_viewing_key": {"entropy": "<random_phrase>"}}' --from <account> --gas 100000```

To check your balance:

```secretcli q compute query <contract-address> '{"balance": {"address":"<your_address>", "key":"your_viewing_key"}}'```

To view your transaction history:

```secretcli q compute query <contract-address> '{"transfer_history": {"address": "<your_address>", "key": "<your_viewing_key>", "page": <optional_page_number>, "page_size": <number_of_transactions_to_return>}}'```

To start unbonding:

```secretcli tx compute execute <contract-address> '{"unstake": {"amount": "<amount_in_smallest_denom_of_token>"}}' --from <account> --gas 100000```

To get the pending claims and their expirations:

```secretcli q compute query <contract-address> '{"claim": {"address":"<your_address>", "key":"your_viewing_key"}}'```


To start claim once the unbonding period has expired:

```secretcli tx compute execute <contract-address> '{"claim"}' --from <account> --gas 100000```

# Weekly Airdrops

To get the current stage:

```secretcli q compute query <contract-address> '{"latest_stage":{}}'```
Response: `{"airdrop_stage":{"stage":1}}`

To get the Merkle Root for a specific stage:

```secretcli q compute query <contract-address> '{"merkle_root": {"stage": <stage_number>}}'```

To know if a wallet has already claimed an airdrop

```secretcli tx compute execute <contract-address> '{"is_airdrop_claimed": {"stage": <stage number>, "address": "<your address>", "key": "<your viewing key>"}}' --gas 1000000```

To claim a weekly airdrop:

```secretcli tx compute execute <contract-address> '{"claim_airdrop": { stage: <stage_number>, amount: <amount_to_claim>, proof: <merkle_proof_generated_in_js>, sig_info: { claim_msg: <cleartext_message>, signature <signature_generated_by_keplr_or_secretcli>} }' --from <account> --gas 1000000```

To view the token contract's configuration:

```secretcli q compute query <contract-address> '{"token_config": {}}'```

To upload a new airdrop (i.e. merkle root hash):

```secretcli tx compute execute <contract-address> '{"register_merkle_root": {"merkle_root": <hash>, "expiration": <stage_expiration>, "start": <stage_start>, "total_amount": "<total_amount_airdropped>"}}' --from <admin_account> --gas 1000000```

`stage_expiration` and `start`: format is `{"at_time": "<nanoseconds from epoch>"}` or `{"at_height": "<block_height>}`

Example:

`secretcli tx compute execute secret136utj09hh78eqmvkfajw0dewje8jlmuqral0hu '{"register_merkle_root": {"merkle_root": "f04ff6555c32626bfcffb0d1bcc665b72560c0aef076a12a10fc204190c3b64d", "expiration": {"at_time":"1664827597"}, "start": {"at_time":"1664727597"}, "total_amount": "46003"}}' --from d --gas 1000000`


Returns the airdrop stage number.

## Troubleshooting

All transactions are encrypted, so if you want to see the error returned by a failed transaction, you need to use the command

`secretcli q compute tx <TX_HASH>`
If nothing useful in this logs, then you are probably out of gas. Use `secretcli q tx <TX_HASH> | jq` instead
