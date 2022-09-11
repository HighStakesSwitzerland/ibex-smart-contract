#![allow(clippy::field_reassign_with_default)] // This is triggered in `#[derive(JsonSchema)]`

use crate::batch;
use crate::transaction_history::{RichTx, Tx};
use crate::viewing_key_obj::ViewingKeyObj;

use crate::claim::expiration::{Duration, HOUR};
use cosmwasm_std::{Addr, Binary, StdError, StdResult, Uint128};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, JsonSchema)]
pub struct InitialBalance {
    pub address: Addr,
    pub amount: Uint128,
    pub staked_amount: Uint128,
}

#[derive(Serialize, Deserialize, JsonSchema)]
pub struct InstantiateMsg {
    pub name: String,
    pub admin: Option<Addr>,
    pub symbol: String,
    pub decimals: u8,
    pub initial_balances: Option<Vec<InitialBalance>>,
    pub prng_seed: Binary,
    pub config: Option<InitConfig>,
}

impl InstantiateMsg {
    pub fn config(&self) -> InitConfig {
        self.config.clone().unwrap_or_default()
    }
}

/// This type represents optional configuration values which can be overridden.
/// All values are optional and have defaults which are more private by default,
/// but can be overridden if necessary
#[derive(Serialize, Deserialize, JsonSchema, Clone, Default, Debug)]
#[serde(rename_all = "snake_case")]
pub struct InitConfig {
    /// Indicates whether the total supply is public or should be kept secret.
    /// default: False
    public_total_supply: Option<bool>,
    /// Indicates whether stake functionality should be enabled
    /// default: False
    enable_stake: Option<bool>,
    /// Indicates whether unstake functionality should be enabled
    /// default: False
    enable_unstake: Option<bool>,
    /// Min amount to stake (errors under)
    min_stake_amount: Option<u128>,
    /// Unbonding period
    pub unbonding_period: Option<Duration>,
}

impl InitConfig {
    pub fn public_total_supply(&self) -> bool {
        self.public_total_supply.unwrap_or(false)
    }

    pub fn staking_enabled(&self) -> bool {
        self.enable_stake.unwrap_or(false)
    }

    pub fn unstaking_enabled(&self) -> bool {
        self.enable_unstake.unwrap_or(false)
    }

    pub fn min_staked_amount(&self) -> Uint128 {
        Uint128::new(self.min_stake_amount.unwrap_or(1_000_000))
    }

    pub fn unbonding_period(&self) -> Duration {
        self.unbonding_period.unwrap_or(HOUR)
    }
}

#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug)]
#[serde(rename_all = "snake_case")]
pub enum ExecuteMsg {
    // Native coin interactions
    Stake {
        amount: Uint128,
    },
    Unstake {
        amount: Uint128,
    },

    // Base ERC-20 stuff
    Transfer {
        recipient: Addr,
        amount: Uint128,
        memo: Option<String>,
        padding: Option<String>,
    },
    Send {
        recipient: Addr,
        recipient_code_hash: Option<String>,
        amount: Uint128,
        msg: Option<Binary>,
        memo: Option<String>,
        padding: Option<String>,
    },
    BatchSend {
        actions: Vec<batch::SendAction>,
        padding: Option<String>,
    },
    RegisterReceive {
        code_hash: String,
        padding: Option<String>,
    },
    CreateViewingKey {
        entropy: String,
        padding: Option<String>,
    },
    SetViewingKey {
        key: String,
        padding: Option<String>,
    },
    TransferFrom {
        owner: Addr,
        recipient: Addr,
        amount: Uint128,
        memo: Option<String>,
        padding: Option<String>,
    },
    SendFrom {
        owner: Addr,
        recipient: Addr,
        recipient_code_hash: Option<String>,
        amount: Uint128,
        msg: Option<Binary>,
        memo: Option<String>,
        padding: Option<String>,
    },
    BatchTransferFrom {
        actions: Vec<batch::TransferFromAction>,
        padding: Option<String>,
    },
    BatchSendFrom {
        actions: Vec<batch::SendFromAction>,
        padding: Option<String>,
    },

    // Admin
    ChangeAdmin {
        address: Addr,
        padding: Option<String>,
    },
    SetContractStatus {
        level: ContractStatusLevel,
        padding: Option<String>,
    },
}

#[derive(Serialize, Deserialize, JsonSchema, Debug)]
#[serde(rename_all = "snake_case")]
pub enum ExecuteAnswer {
    // Native
    Stake {
        status: ResponseStatus,
        amount: Uint128,
    },
    Unstake {
        status: ResponseStatus,
        amount: Uint128,
    },

    // Base
    Transfer {
        status: ResponseStatus,
    },
    Send {
        status: ResponseStatus,
    },
    BatchSend {
        status: ResponseStatus,
    },
    RegisterReceive {
        status: ResponseStatus,
    },
    CreateViewingKey {
        key: ViewingKeyObj,
    },
    SetViewingKey {
        status: ResponseStatus,
    },
    TransferFrom {
        status: ResponseStatus,
    },
    SendFrom {
        status: ResponseStatus,
    },
    BatchTransferFrom {
        status: ResponseStatus,
    },
    BatchSendFrom {
        status: ResponseStatus,
    },

    // Other
    ChangeAdmin {
        status: ResponseStatus,
    },
    SetContractStatus {
        status: ResponseStatus,
    },
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum QueryMsg {
    TokenInfo {},
    TokenConfig {},
    ContractStatus {},
    Balance {
        address: Addr,
        key: String,
    },
    TransferHistory {
        address: Addr,
        key: String,
        page: Option<u32>,
        page_size: u32,
    },
    TransactionHistory {
        address: Addr,
        key: String,
        page: Option<u32>,
        page_size: u32,
    },
}

impl QueryMsg {
    pub fn get_validation_params(&self) -> (Vec<&Addr>, ViewingKeyObj) {
        match self {
            Self::Balance { address, key } => (vec![address], ViewingKeyObj(key.clone())),
            Self::TransferHistory { address, key, .. } => {
                (vec![address], ViewingKeyObj(key.clone()))
            }
            Self::TransactionHistory { address, key, .. } => {
                (vec![address], ViewingKeyObj(key.clone()))
            }
            _ => panic!("This query type does not require authentication"),
        }
    }
}

#[derive(Serialize, Deserialize, JsonSchema, Debug)]
#[serde(rename_all = "snake_case")]
pub enum QueryAnswer {
    TokenInfo {
        name: String,
        symbol: String,
        decimals: u8,
        total_supply: Option<Uint128>,
    },
    TokenConfig {
        public_total_supply: bool,
        staking_enabled: bool,
        unstaking_enabled: bool,
        min_stake_amount: Uint128,
        unbonding_period: Duration,
    },
    ContractStatus {
        status: ContractStatusLevel,
    },
    Balance {
        amount: Uint128,
        staked_amount: Uint128,
    },
    TransferHistory {
        txs: Vec<Tx>,
        total: Option<u64>,
    },
    TransactionHistory {
        txs: Vec<RichTx>,
        total: Option<u64>,
    },
    ViewingKeyError {
        msg: String,
    },
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, JsonSchema)]
pub struct CreateViewingKeyResponse {
    pub key: String,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, JsonSchema, Debug)]
#[serde(rename_all = "snake_case")]
pub enum ResponseStatus {
    Success,
    Failure,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, JsonSchema, Debug)]
#[serde(rename_all = "snake_case")]
pub enum ContractStatusLevel {
    NormalRun,
    StopAllButUnstake,
    StopAll,
}

pub fn status_level_to_u8(status_level: ContractStatusLevel) -> u8 {
    match status_level {
        ContractStatusLevel::NormalRun => 0,
        ContractStatusLevel::StopAllButUnstake => 1,
        ContractStatusLevel::StopAll => 2,
    }
}

pub fn u8_to_status_level(status_level: u8) -> StdResult<ContractStatusLevel> {
    match status_level {
        0 => Ok(ContractStatusLevel::NormalRun),
        1 => Ok(ContractStatusLevel::StopAllButUnstake),
        2 => Ok(ContractStatusLevel::StopAll),
        _ => Err(StdError::generic_err("Invalid state level")),
    }
}

// Take a Vec<u8> and pad it up to a multiple of `block_size`, using spaces at the end.
pub fn space_pad(block_size: usize, message: &mut Vec<u8>) -> &mut Vec<u8> {
    let len = message.len();
    let surplus = len % block_size;
    if surplus == 0 {
        return message;
    }

    let missing = block_size - surplus;
    message.reserve(missing);
    message.extend(std::iter::repeat(b' ').take(missing));
    message
}

#[cfg(test)]
mod tests {
    use super::*;
    use cosmwasm_std::{from_slice, StdResult};

    #[derive(Serialize, Deserialize, JsonSchema, Debug, PartialEq)]
    #[serde(rename_all = "snake_case")]
    pub enum Something {
        Var { padding: Option<String> },
    }

    #[test]
    fn test_deserialization_of_missing_option_fields() -> StdResult<()> {
        let input = b"{ \"var\": {} }";
        let obj: Something = from_slice(input)?;
        assert_eq!(
            obj,
            Something::Var { padding: None },
            "unexpected value: {:?}",
            obj
        );
        Ok(())
    }
}
