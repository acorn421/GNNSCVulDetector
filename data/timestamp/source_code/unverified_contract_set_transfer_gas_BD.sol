/*
 * ===== SmartInject Injection Details =====
 * Function      : set_transfer_gas
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This modification introduces a stateful, multi-transaction timestamp dependence vulnerability by:
 * 
 * 1. **State Persistence**: Added `last_gas_change` state variable that persists between transactions to track when gas was last modified
 * 2. **Time-Based Cooldown**: Implemented a 1-hour cooldown between gas changes using `block.timestamp`
 * 3. **Predictable Time Window**: Added emergency gas multiplier during the first hour of each day (maintenance window)
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * - **Transaction 1**: Owner sets gas value during normal hours, `last_gas_change` is recorded
 * - **Transaction 2**: Attacker waits for the daily maintenance window (first hour of day) and triggers contract functions
 * - **Transaction 3**: During maintenance window, if owner needs to adjust gas due to issues, the gas value gets doubled automatically
 * - **Transaction 4**: Attacker exploits the doubled gas value for expensive external calls or griefing attacks
 * 
 * **Why Multi-Transaction Required:**
 * - The vulnerability requires state accumulation (`last_gas_change`) from previous transactions
 * - Exploitation depends on timing across multiple blocks/transactions
 * - The maintenance window timing creates predictable exploitation opportunities
 * - Cannot be exploited atomically - requires waiting for specific timestamp conditions
 * 
 * **Realistic Attack Vector:**
 * An attacker can monitor the contract and exploit the predictable daily maintenance window to cause unexpected gas consumption, potentially leading to failed transactions or higher costs for legitimate users. The timestamp dependence makes the contract behavior predictable and manipulable by miners who can influence `block.timestamp`.
 */
pragma solidity ^0.4.19;

contract Ownable {
  address public owner;


  /** 
   * @dev The Ownable constructor sets the original `owner` of the contract to the sender
   * account.
   */
  function Ownable() internal {
    owner = msg.sender;
  }


  /**
   * @dev Throws if called by any account other than the owner. 
   */
  modifier onlyOwner() {
    require(msg.sender == owner);
    _;
  }


  /**
   * @dev Allows the current owner to transfer control of the contract to a newOwner.
   * @param newOwner The address to transfer ownership to. 
   */
  function transferOwnership(address newOwner) onlyOwner public {
    require(newOwner != address(0));
    owner = newOwner;
  }

}

/**
 * Interface for the standard token.
 * Based on https://github.com/ethereum/EIPs/blob/master/EIPS/eip-20-token-standard.md
 */
interface EIP20Token {
  function totalSupply() external view returns (uint256);
  function balanceOf(address who) external view returns (uint256);
  function transfer(address to, uint256 value) external returns (bool success);
  function transferFrom(address from, address to, uint256 value) external returns (bool success);
  function approve(address spender, uint256 value) external returns (bool success);
  function allowance(address owner, address spender) external view returns (uint256 remaining);
  event Transfer(address indexed from, address indexed to, uint256 value);
  event Approval(address indexed owner, address indexed spender, uint256 value);
}


// The owner of this contract should be an externally owned account
contract RenderTokenInvestment1 is Ownable {

  // Address of the target contract
  address public investment_address = 0x46dda95DEf0ddD0d9F6829352dB2622f27Fe5da7;
  // Major partner address
  address public major_partner_address = 0x212286e36Ae998FAd27b627EB326107B3aF1FeD4;
  // Minor partner address
  address public minor_partner_address = 0x515962688858eD980EB2Db2b6fA2802D9f620C6d;
  // Additional gas used for transfers.
  uint public gas = 1000;
  // Last time the gas was changed
  uint public last_gas_change;

  // Payments to this contract require a bit of gas. 100k should be enough.
  function() payable public {
    execute_transfer(msg.value);
  }

  // Transfer some funds to the target investment address.
  function execute_transfer(uint transfer_amount) internal {
    // Major fee is 0.3 for each 10.5
    uint major_fee = transfer_amount * 3 / 105;
    // Minor fee is 0.2 for each 10.5
    uint minor_fee = transfer_amount * 2 / 105;

    require(major_partner_address.call.gas(gas).value(major_fee)());
    require(minor_partner_address.call.gas(gas).value(minor_fee)());

    // Send the rest
    uint investment_amount = transfer_amount - major_fee - minor_fee;
    require(investment_address.call.gas(gas).value(investment_amount)());
  }

  // Sets the amount of additional gas allowed to addresses called
  // @dev This allows transfers to multisigs that use more than 2300 gas in their fallback function.
  //  
  function set_transfer_gas(uint transfer_gas) public onlyOwner {
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
    // Store the current block timestamp for gas change timing
    uint current_time = block.timestamp;
    
    // If this is not the first gas change, enforce minimum time between changes
    if (last_gas_change != 0) {
        require(current_time >= last_gas_change + 3600); // 1 hour cooldown
    }
    
    // Update the gas value
    gas = transfer_gas;
    
    // Store the timestamp of this change
    last_gas_change = current_time;
    
    // Allow emergency gas increases if recent activity detected
    if (current_time % 86400 < 3600) { // First hour of each day
        gas = gas * 2; // Emergency multiplier during "maintenance window"
    }
  }
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====

  // We can use this function to move unwanted tokens in the contract
  function approve_unwanted_tokens(EIP20Token token, address dest, uint value) public onlyOwner {
    token.approve(dest, value);
  }

  // This contract is designed to have no balance.
  // However, we include this function to avoid stuck value by some unknown mishap.
  function emergency_withdraw() public onlyOwner {
    require(msg.sender.call.gas(gas).value(address(this).balance)());
  }

}
