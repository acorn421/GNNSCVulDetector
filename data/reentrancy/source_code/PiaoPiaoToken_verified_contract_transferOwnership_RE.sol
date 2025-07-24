/*
 * ===== SmartInject Injection Details =====
 * Function      : transferOwnership
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * **STATEFUL, MULTI-TRANSACTION Reentrancy Vulnerability Injection**
 * 
 * **Specific Changes Made:**
 * 1. **Added External Call Before State Update**: Introduced a call to `newOwner.onOwnershipTransfer(address)` before the `owner` state variable is updated
 * 2. **Violated Checks-Effects-Interactions Pattern**: The external call occurs after checks but before the critical state change
 * 3. **Contract Code Check**: Added `newOwner.code.length > 0` to ensure the call only happens to contract addresses
 * 4. **Mandatory Success Requirement**: Added `require(success, ...)` to make the external call mandatory for contracts
 * 
 * **Multi-Transaction Exploitation Path:**
 * The vulnerability requires multiple transactions and persistent state changes:
 * 
 * **Transaction 1 (Setup):** Attacker deploys malicious contract with `onOwnershipTransfer` function
 * **Transaction 2 (Initial Call):** Current owner calls `transferOwnership(maliciousContract)`
 * **Transaction 3+ (Reentrancy):** During the external call in Transaction 2, malicious contract re-enters `transferOwnership` multiple times
 * 
 * **Exploitation Sequence:**
 * 1. **State Persistence**: The `owner` state remains unchanged during the external call window
 * 2. **Multiple Re-entries**: Malicious contract can call `transferOwnership` again during `onOwnershipTransfer` callback
 * 3. **State Accumulation**: Each re-entrant call can transfer ownership to different addresses or back to attacker
 * 4. **Final State**: The final `owner` value depends on the last successful re-entrant call, not the original intended transfer
 * 
 * **Why Multiple Transactions Are Required:**
 * - **Transaction Separation**: The initial call and re-entrant calls occur in separate transaction contexts
 * - **State Dependency**: The vulnerability depends on the persistent `owner` state not being updated during external calls
 * - **Accumulated Effect**: Multiple re-entrant calls accumulate state changes that wouldn't be possible in a single atomic operation
 * - **Cross-Transaction Persistence**: The `owner` state persists between the initial call and re-entrant calls, enabling the exploit
 * 
 * **Realistic Attack Scenario:**
 * An attacker could:
 * 1. Deploy a malicious contract that implements `onOwnershipTransfer`
 * 2. Somehow convince or trick the current owner to transfer ownership to this contract
 * 3. During the ownership transfer, re-enter multiple times to manipulate the final owner state
 * 4. End up with unexpected ownership control through the accumulated re-entrant calls
 * 
 * This creates a realistic, stateful, multi-transaction vulnerability that requires both setup transactions and exploitative re-entrant calls to be effective.
 */
pragma solidity ^0.4.24;
contract Ownable {
  address public owner;
  event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
  constructor() public {
    owner = msg.sender;
  }

  modifier onlyOwner() {
    require(msg.sender == owner);
    _;
  }

  function transferOwnership(address newOwner) public onlyOwner {
    require(newOwner != address(0));
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    // External call to notify new owner before state change
    // This creates a reentrancy window where owner hasn't changed yet
    if (newOwner != address(0) && isContract(newOwner)) {
        require(newOwner.call(bytes4(keccak256("onOwnershipTransfer(address)")), owner));
    }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    OwnershipTransferred(owner, newOwner);
    owner = newOwner;
  // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
  }
  // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

  // Helper to check if address is a contract (since .code doesn't exist in 0.4.24)
  function isContract(address _addr) internal view returns (bool) {
      uint256 size;
      assembly { size := extcodesize(_addr) }
      return size > 0;
  }
}

contract LoveToken is Ownable{
    uint256 public totalSupply;
    function balanceOf(address _owner) public constant returns (uint256 balance);
    function transfer(address _to, uint256 _value) public returns (bool success);
    event Transfer(address indexed _from, address indexed _to, uint256 _value);
}

contract PiaoPiaoToken is LoveToken {
    mapping (address => uint256) balances;
    string public name;                   
    uint8 public decimals;               
    string public symbol;
    string public loveUrl;
    
    constructor() public {
        balances[msg.sender] = 5201314; 
        totalSupply = 5201314;         
        name = "PiaoPiao Token";                   
        decimals = 0;          
        symbol = "PPT";  
    }
    
    function setLoveUrl(string _loveUrl) onlyOwner public returns (bool success) {
        loveUrl = _loveUrl;
        return true;
    }
    
    function transfer(address _to, uint256 _value) public returns (bool success) {
        require(balances[msg.sender] >= _value);
        balances[msg.sender] -= _value;
        balances[_to] += _value;
        Transfer(msg.sender, _to, _value);
        return true;
    }

    function balanceOf(address _owner) public constant returns (uint256 balance) {
        return balances[_owner];
    }
}