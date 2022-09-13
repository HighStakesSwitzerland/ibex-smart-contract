use crate::storage::claim::Claims;
use crate::storage::expiration::Duration;
use cosmwasm_std::{Addr, StdError, StdResult, Storage, Uint128};
use cosmwasm_storage::{PrefixedStorage, ReadonlyPrefixedStorage};
use schemars::JsonSchema;
use secret_toolkit::serialization::Json;
use secret_toolkit::storage::{Item, Keymap};
use serde::{Deserialize, Serialize};

use crate::msg::ContractStatusLevel;

pub static CONFIG_KEY: &[u8] = b"config";

pub const KEY_CONSTANTS: &[u8] = b"constants";
pub const KEY_TOTAL_SUPPLY: &[u8] = b"total_supply";
pub const KEY_CONTRACT_STATUS: &[u8] = b"contract_status";
pub const KEY_TX_COUNT: &[u8] = b"tx-count";

pub const PREFIX_CONFIG: &[u8] = b"config";
pub const PREFIX_BALANCES: &[u8] = b"balances";
pub const PREFIX_STAKED_BALANCES: &[u8] = b"staked_balances";
pub const PREFIX_VIEW_KEY: &[u8] = b"viewingkey";
pub const PREFIX_RECEIVERS: &[u8] = b"receivers";

pub const CLAIMS: Claims = Claims::new("claims");

// Config

#[derive(Serialize, Debug, Deserialize, Clone, PartialEq, Eq, JsonSchema)]
pub struct Constants {
    pub name: String,
    pub admin: Addr,
    pub symbol: String,
    pub decimals: u8,
    // minimal amount to stake
    pub min_stake_amount: Uint128,
    // unbonding period before being able to storage tokens
    pub unbonding_period: Duration,

    // the address of this contract, used to validate query permits
    pub contract_address: Addr,
}
pub static CONSTANTS: Item<Constants, Json> = Item::new(KEY_CONSTANTS);

impl Constants {
    pub fn load(store: &dyn Storage) -> StdResult<Constants> {
        CONSTANTS
            .load(store)
            .map_err(|_err| StdError::generic_err("no constants stored"))
    }

    pub fn save(store: &mut dyn Storage, constants: &Constants) -> StdResult<()> {
        CONSTANTS.save(store, constants)
    }
}

pub static TOTAL_SUPPLY: Item<u128, Json> = Item::new(KEY_TOTAL_SUPPLY);
pub struct TotalSupplyStore {}
impl TotalSupplyStore {
    pub fn load(store: &dyn Storage) -> StdResult<u128> {
        TOTAL_SUPPLY
            .load(store)
            .map_err(|_err| StdError::generic_err("no total supply stored"))
    }

    pub fn save(store: &mut dyn Storage, supply: u128) -> StdResult<()> {
        TOTAL_SUPPLY.save(store, &supply)
    }
}

pub static CONTRACT_STATUS: Item<ContractStatusLevel, Json> = Item::new(KEY_CONTRACT_STATUS);
pub struct ContractStatusStore {}
impl ContractStatusStore {
    pub fn load(store: &dyn Storage) -> StdResult<ContractStatusLevel> {
        CONTRACT_STATUS
            .load(store)
            .map_err(|_err| StdError::generic_err("no contract status stored"))
    }

    pub fn save(store: &mut dyn Storage, status: ContractStatusLevel) -> StdResult<()> {
        CONTRACT_STATUS.save(store, &status)
    }
}

pub static TX_COUNT: Item<u64, Json> = Item::new(KEY_TX_COUNT);
pub struct TxCountStore {}
impl TxCountStore {
    pub fn load(store: &dyn Storage) -> u64 {
        TX_COUNT.load(store).unwrap_or_default()
    }

    pub fn save(store: &mut dyn Storage, count: u64) -> StdResult<()> {
        TX_COUNT.save(store, &count)
    }
}

pub static BALANCES: Keymap<Addr, u128> = Keymap::new(PREFIX_BALANCES);
pub struct BalancesStore {}
impl BalancesStore {
    pub fn load(store: &dyn Storage, account: &Addr) -> u128 {
        BALANCES.get(store, account).unwrap_or_default()
    }

    pub fn save(store: &mut dyn Storage, account: &Addr, amount: u128) -> StdResult<()> {
        BALANCES.insert(store, account, &amount)
    }
}

pub static STAKED_BALANCES: Keymap<Addr, u128> = Keymap::new(PREFIX_STAKED_BALANCES);
pub struct StakedBalancesStore {}
impl StakedBalancesStore {
    pub fn load(store: &dyn Storage, account: &Addr) -> u128 {
        STAKED_BALANCES.get(store, account).unwrap_or_default()
    }

    pub fn save(store: &mut dyn Storage, account: &Addr, amount: u128) -> StdResult<()> {
        STAKED_BALANCES.insert(store, account, &amount)
    }
}

// Receiver Interface

pub fn get_receiver_hash(store: &dyn Storage, account: &Addr) -> Option<StdResult<String>> {
    let store = ReadonlyPrefixedStorage::new(store, PREFIX_RECEIVERS);
    store.get(account.as_str().as_bytes()).map(|data| {
        String::from_utf8(data)
            .map_err(|_err| StdError::invalid_utf8("stored code hash was not a valid String"))
    })
}

pub fn set_receiver_hash(store: &mut dyn Storage, account: &Addr, code_hash: String) {
    let mut store = PrefixedStorage::new(store, PREFIX_RECEIVERS);
    store.set(account.as_str().as_bytes(), code_hash.as_bytes());
}
