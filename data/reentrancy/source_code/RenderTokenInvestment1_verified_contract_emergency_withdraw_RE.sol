/*
 * ===== SmartInject Injection Details =====
 * Function      : emergency_withdraw
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-eth (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **State Tracking Addition**: Added `pending_amount` variable to track the withdrawal amount
 * 2. **External Call Before State Update**: The external call `msg.sender.call.gas(gas).value(pending_amount)()` occurs before any state changes
 * 3. **State Update After External Call**: The gas variable is incremented after the external call, creating a race condition
 * 4. **Multi-Transaction Dependency**: The vulnerability requires multiple transactions to exploit:
 *    - **Transaction 1**: Attacker calls `set_transfer_gas()` to set initial gas value and deposits funds
 *    - **Transaction 2**: Attacker calls `emergency_withdraw()` which triggers reentrancy
 *    - **During Reentrancy**: Attacker's contract can call back to `emergency_withdraw()` again before the gas state is updated
 *    - **State Accumulation**: Each reentrant call processes the full balance before the gas counter is incremented
 * 
 * **Exploitation Sequence:**
 * 1. **Setup (Tx 1)**: Attacker becomes owner and calls `set_transfer_gas(1000)` to set gas, then sends ETH to contract
 * 2. **Exploit (Tx 2)**: Attacker calls `emergency_withdraw()` from malicious contract
 * 3. **Reentrancy**: During the external call, attacker's fallback function calls `emergency_withdraw()` again
 * 4. **State Race**: Since gas is only incremented after the external call, multiple withdrawals can occur with the same balance
 * 5. **Persistence**: The gas state changes persist between transactions, allowing the attacker to track and exploit the withdrawal state
 * 
 * The vulnerability is stateful because it depends on the gas variable state changes that persist across transactions, and it's multi-transaction because the attacker must set up the initial state in one transaction before exploiting in subsequent transactions.
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
    gas = transfer_gas;
  }

  // We can use this function to move unwanted tokens in the contract
  function approve_unwanted_tokens(EIP20Token token, address dest, uint value) public onlyOwner {
    token.approve(dest, value);
  }

  // This contract is designed to have no balance.
  // However, we include this function to avoid stuck value by some unknown mishap.
  function emergency_withdraw() public onlyOwner {
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    // Track pending withdrawals to prevent double spending
    uint256 pending_amount = address(this).balance;
    
    // External call before state update - vulnerable to reentrancy
    require(msg.sender.call.gas(gas).value(pending_amount)());
    
    // State update after external call - creates race condition
    if (pending_amount > 0) {
        // Mark this withdrawal as processed by updating gas to signal completion
        gas = gas + 1;
    }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
  }

}