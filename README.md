# SNIP-20 Reference Implementation

This is an implementation of a [SNIP-20](https://github.com/SecretFoundation/SNIPs/blob/master/SNIP-20.md), [SNIP-21](https://github.com/SecretFoundation/SNIPs/blob/master/SNIP-21.md), [SNIP-22](https://github.com/SecretFoundation/SNIPs/blob/master/SNIP-22.md), [SNIP-23](https://github.com/SecretFoundation/SNIPs/blob/master/SNIP-23.md) and [SNIP-24](https://github.com/SecretFoundation/SNIPs/blob/master/SNIP-24.md) compliant token contract.
At the time of token creation you may configure:
* Minimum Stake Amount: u128 value for minimum amount on stake tx. DEFAULT: 1_000_000
* Unbonding Period: The duration of unbonding before being able to claim. DEFAULT: 60 seconds

## Usage examples:

To create a new token:

```secretcli tx compute instantiate 1 --from a --label IBEX '{"name": "sibex", "symbol": "IBEX", "label": "IBEX", "decimals": 0, "initial_balances": [{"address": "secret1ap26qrlp8mcq2pg6r47w43l0y8zkqm8a450s03", "amount": "100000", "staked_amount": "100"}], "prng_seed": "dG90b2xhcHJhbGluZQo=", "config": {"min_staked_balance": "100"}}'```

The `admin` field is optional and will default to the "--from" address if you do not specify it.  The `initial_balances` field is optional, and you can specify as many addresses/balances as you like.  The `config` field as well as every field in the `config` is optional.

To set your viewing key:

```secretcli tx compute execute <contract-address> '{"create_viewing_key": {"entropy": "<random_phrase>"}}' --from <account>```

To check your balance:

```secretcli q compute query <contract-address> '{"balance": {"address":"<your_address>", "key":"your_viewing_key"}}'```

To view your transaction history:

```secretcli q compute query <contract-address> '{"transfer_history": {"address": "<your_address>", "key": "<your_viewing_key>", "page": <optional_page_number>, "page_size": <number_of_transactions_to_return>}}'```

To start unbonding:

```secretcli tx compute execute <contract-address> '{"unstake": {"amount": "<amount_in_smallest_denom_of_token>"}}' --from <account>```

To get the pending claims and their expirations:

```secretcli q compute query <contract-address> '{"claim": {"address":"<your_address>", "key":"your_viewing_key"}}'```


To start claim once the unbonding period has expired:

```secretcli tx compute execute <contract-address> '{"claim"}' --from <account>```

To view the token contract's configuration:

```secretcli q compute query <contract-address> '{"token_config": {}}'```

## Troubleshooting

All transactions are encrypted, so if you want to see the error returned by a failed transaction, you need to use the command

`secretcli q compute tx <TX_HASH>`
