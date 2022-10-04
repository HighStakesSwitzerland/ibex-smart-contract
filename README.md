# Reference Implementation

This is an implementation of a [SNIP-20](https://github.com/SecretFoundation/SNIPs/blob/master/SNIP-20.md), [SNIP-21](https://github.com/SecretFoundation/SNIPs/blob/master/SNIP-21.md), [SNIP-22](https://github.com/SecretFoundation/SNIPs/blob/master/SNIP-22.md), [SNIP-23](https://github.com/SecretFoundation/SNIPs/blob/master/SNIP-23.md) and [SNIP-24](https://github.com/SecretFoundation/SNIPs/blob/master/SNIP-24.md) compliant token contract.
At the time of token creation you may configure:
* Minimum Stake Amount: u128 value for minimum amount on stake tx. DEFAULT: 1_000_000
* Unbonding Period: The duration of unbonding before being able to claim. DEFAULT: 60 seconds

## Usage examples:

### To create a new token (admin):

```secretcli tx compute instantiate <contract_number> --from a --label IBEX '{"name": "sibex", "symbol": "IBEX", "label": "IBEX", "decimals": 0, "admin": <admin_wallet>, "initial_balances": [{"address": "secret1ap26qrlp8mcq2pg6r47w43l0y8zkqm8a450s03", "unstaked": "100000", "staked": "100"}], "prng_seed": "dG90b2xhcHJhbGluZQo=", "config": { "unbonding_period": {"time": 60}, "min_stake_amount": "1000"}}'```
`prng_seed` is a random string base64 encoded used as salt
`unbonding_period` is in seconds (604800 for 1 week)
The `admin` field is optional and will default to the "--from" address if you do not specify it.
The `initial_balances` field is optional, and you can specify as many addresses/balances as you like.  The `config` field as well as every field in the `config` is optional.

# Public tx

### To get the token info/config:

`secretcli q compute query <contract-address> '{"token_info": {}}'`

Response: `{"token_info":{"name":"sibex","symbol":"IBEX","decimals":0,"total_supply":"1000000"}}`


`secretcli q compute query <contract-address> '{"token_config": {}}'`

Response: `{"token_config":{"min_stake_amount":"100","unbonding_period":{"time":60}}}`

### To set your viewing key (used in queries):

```secretcli tx compute execute <contract-address> '{"create_viewing_key": {"entropy": "<random_phrase>"}}' --from <account> --gas 100000```

### To check your balance:

```secretcli q compute query <contract-address> '{"balance": {"address":"<your_address>", "key":"your_viewing_key"}}'```

### To view your transaction history:

```secretcli q compute query <contract-address> '{"transfer_history": {"address": "<your_address>", "key": "<your_viewing_key>", "page": <optional_page_number>, "page_size": <number_of_transactions_to_return>}}'```

### To start unbonding:

```secretcli tx compute execute <contract-address> '{"unstake": {"amount": "<amount_in_smallest_denom_of_token>"}}' --from <account> --gas 100000```

### To get the pending claims and their expirations:

```secretcli q compute query <contract-address> '{"claim": {"address":"<your_address>", "key":"your_viewing_key"}}'```


### To start claim once the unbonding period has expired:

```secretcli tx compute execute <contract-address> '{"claim"}' --from <account> --gas 100000```


### To get the current stage:

```secretcli q compute query <contract-address> '{"latest_stage":{}}'```
Response: `{"airdrop_stage":{"stage":1}}`

### To get the Merkle Root for a specific stage:

```secretcli q compute query <contract-address> '{"merkle_root": {"stage": <stage_number>}}'```

### To know if a wallet has already claimed an airdrop

```secretcli tx compute execute <contract-address> '{"is_airdrop_claimed": {"stage": <stage number>, "address": "<your address>", "key": "<your viewing key>"}}' --gas 1000000```

Returns
```
{
    claimed: bool,
    amount: u128,
    expiration: seconds (not nanos),
    start: seconds (not nanos)
}
```

### To claim a weekly airdrop:

```secretcli tx compute execute <contract-address> '{"claim_airdrop": { stage: <stage_number>, amount: <amount_to_claim>, proof: <merkle_proof_generated_in_js>}' --from <account> --gas 1000000```

### To view the token contract's configuration:

```secretcli q compute query <contract-address> '{"token_config": {}}'```

# Admin tx

### Change admin wallet

To change the admin wallet (the only `--from yyy` authorized to execute admin commands)
```secretcli tx compute execute <contract-address> '{"change_admin": {"address": <new_wallet>}' --from <previous_admin_account> --gas 1000000```

### Lock/Unlock contract (emergency action)

```secretcli tx compute execute <contract-address> '{"set_contract_status": {"level": <level>}}' --from <admin_account> --gas 1000000```

#### Valid levels:

**normal_run** => all tx available

**stop_all_but_unstake** => only `set_contract_status`, unstake` and `claim`

**stop_all** => only `set_contract_status`

### To upload a new airdrop (= merkle root hash):

```secretcli tx compute execute <contract-address> '{"register_merkle_root": {"merkle_root": <hash>, "expiration": <stage_expiration>, "start": <stage_start>, "total_amount": "<total_amount_airdropped>"}}' --from <admin_account> --gas 1000000```

`stage_expiration` and `start`: format is `{"at_time": "<NANOSECONDS from epoch>"}` or `{"at_height": "<block_height (not tested)>}`

`total_amount` = total amount of airdropped ibex. MUST be accurate => used in `withdraw_unclaimed` calculation

#### Example:

`secretcli tx compute execute <contract-address> '{"register_merkle_root": {"merkle_root": "f04ff6555c32626bfcffb0d1bcc665b72560c0aef076a12a10fc204190c3b64d", "expiration": {"at_time":"1664827597000000000"}, "start": {"at_time":"1664727597000000000"}, "total_amount": "46003"}}' --from d --gas 1000000`

Returns the airdrop stage number. Timestamp MUST be in nanoseconds (can't be changed in code)0

### To change the source wallet containing IBEX (when user claims) (emergency action)

```secretcli tx compute execute <contract-address> '{"register_ibex_wallet": {"address": <new_wallet_with_enough_IBEX>}' --from <admin_account> --gas 1000000```

### To replace an airdrop (emergency action)

```secretcli tx compute execute <contract-address> '{"replace_merkle_root": {"stage": <number>, merkle_root": <hash>, "expiration": <stage_expiration>, "start": <stage_start>, "total_amount": "<total_amount_airdropped>"}}' --from <admin_account> --gas 1000000```

#### Example:

`secretcli tx compute execute <contract-address> '{"replace_merkle_root": {"stage": 1, merkle_root": "f04ff6555c32626bfcffb0d1bcc665b72560c0aef076a12a10fc204190c3b64d", "expiration": {"at_time":"1664827597000000000"}, "start": {"at_time":"1664727597000000000"}, "total_amount": "46003"}}' --from d --gas 1000000`

Returns the airdrop stage number.

### To replace an airdrop expiration date (emergency action)

```secretcli tx compute execute <contract-address> '{"update_exp_date": {"stage": <number>, "new_expiration": <stage_expiration_in_NANOS>}} --from <admin_account> --gas 1000000'```

Actually doable using replace_merkle_root, I have wasted my time

### To withdraw all unclaimed IBEX after expiration of airdrop

Works only if stage expiration date is expired. Sends all IBEX unclaimed to the specified address

```secretcli tx compute execute <contract-address> '{"withdraw_unclaimed": {"stage": <number>, "address": <address_to_send_IBEX>}' --from <admin_account> --gas 1000000'```

### To get the list of all IBEX balances

```secretcli tx compute execute <contract-address> '{"get_all":{}}'  --from <admin_account> --gas 1000000'```

Returns the list of all wallet + amount_staked + amount_unstaked

### To get the list of all Claimed airdrops

```secretcli tx compute execute <contract-address> '{"get_all_claimed":{}}'  --from <admin_account> --gas 1000000'```

Returns the list of all wallet + airdrop_stage + claimed_amount (random order)

No wallet = not claimed !

## Troubleshooting

All transactions are encrypted, so if you want to see the error returned by a failed transaction, you need to use the command

`secretcli q compute tx <TX_HASH>`
If nothing useful in this logs, then you are probably out of gas. Use `secretcli q tx <TX_HASH> | jq` instead
