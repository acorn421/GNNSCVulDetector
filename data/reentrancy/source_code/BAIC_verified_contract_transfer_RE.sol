/*
 * ===== SmartInject Injection Details =====
 * Function      : transfer
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * **STATEFUL, MULTI-TRANSACTION REENTRANCY VULNERABILITY**
 * 
 * **Specific Changes Made:**
 * 1. **Added External Call Before State Updates**: Introduced a call to `_to.call(bytes4(keccak256("tokenReceived(address,uint256)")), msg.sender, _value)` that occurs AFTER balance checks but BEFORE balance updates
 * 2. **Added Contract Detection**: Added `isContract()` helper function to determine if recipient is a contract
 * 3. **Conditional External Call**: Only makes the external call if the recipient is a contract address
 * 4. **Preserved Original Logic**: All original checks, balance updates, and assertions remain intact
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 - Setup Phase:**
 * - Attacker deploys a malicious contract with a `tokenReceived()` function
 * - Attacker funds their EOA account with initial tokens
 * - This establishes the persistent state needed for the attack
 * 
 * **Transaction 2 - Exploit Execution:**
 * - Attacker calls `transfer(maliciousContract, amount)` from their EOA
 * - The function performs balance checks using current balances
 * - The external call to `maliciousContract.tokenReceived()` is made
 * - **During this callback, the malicious contract calls `transfer()` again**
 * - The second call sees the same old balances (since state hasn't been updated yet)
 * - The second call passes all checks and makes another external call
 * - This creates a reentrant loop that can drain tokens
 * 
 * **Why Multi-Transaction Dependency is Required:**
 * 1. **State Accumulation**: The attacker must first accumulate tokens in their account through legitimate means or initial funding
 * 2. **Contract Deployment**: The malicious contract must be deployed and ready to receive the callback
 * 3. **Sequence Dependency**: The exploit only works when the attacker has sufficient balance from previous transactions to pass the initial checks
 * 4. **Persistent State Manipulation**: Each reentrant call depends on the balance state that was established in earlier transactions
 * 
 * **Exploitation Flow:**
 * ```
 * Transaction 1: Deploy malicious contract + fund attacker account
 * Transaction 2: transfer(maliciousContract, X) 
 *   → tokenReceived() callback
 *   → transfer(maliciousContract, X) [reentrant call]
 *   → tokenReceived() callback  
 *   → transfer(maliciousContract, X) [reentrant call]
 *   → ... [continues until balance insufficient]
 * ```
 * 
 * The vulnerability is realistic because token notification callbacks are common in modern token standards (ERC223, ERC777), but the placement before state updates creates a classic reentrancy vulnerability that requires multiple transactions to set up and exploit.
 */
pragma solidity ^0.4.24;

/*
You should inherit from TokenBase. This implements ONLY the standard functions obeys ERC20,
and NOTHING else. If you deploy this, you won't have anything useful.

Implements ERC 20 Token standard: https://github.com/ethereum/EIPs/issues/20
.*/

library SafeMath {
  function mul(uint256 a, uint256 b) internal pure returns (uint256) {
    uint256 c = a * b;
    assert(a == 0 || c / a == b);
    return c;
  }

  function div(uint256 a, uint256 b) internal pure returns (uint256) {
    // assert(b > 0); // Solidity automatically throws when dividing by 0
    uint256 c = a / b;
    // assert(a == b * c + a % b); // There is no case in which this doesn't hold
    return c;
  }

  function sub(uint256 a, uint256 b) internal pure returns (uint256) {
    assert(b <= a);
    return a - b;
  }

  function add(uint256 a, uint256 b) internal pure returns (uint256) {
    uint256 c = a + b;
    assert(c >= a);
    return c;
  }
}

contract ERC20 {

    /// total amount of tokens
    uint256 public totalSupply;

    /// @param _owner The address from which the balance will be retrieved
    /// @return The balance
    function balanceOf(address _owner) constant public returns (uint256 balance);

    /// @notice send `_value` token to `_to` from `msg.sender`
    /// @param _to The address of the recipient
    /// @param _value The amount of token to be transferred
    /// @return Whether the transfer was successful or not
    function transfer(address _to, uint256 _value) public returns (bool success);

    event Transfer(address indexed _from, address indexed _to, uint256 _value);
}

contract BasicToken is ERC20 {
    using SafeMath for uint;

    mapping (address => uint256) balances; /// balance amount of tokens for address

    function transfer(address _to, uint256 _value) public returns (bool success) {
        // Prevent transfer to 0x0 address.
        require(_to != 0x0);
        // Check if the sender has enough
        require(balances[msg.sender] >= _value);
        // Check for overflows
        require(balances[_to].add(_value) > balances[_to]);

        uint previousBalances = balances[msg.sender].add(balances[_to]);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify recipient contract before updating balances - VULNERABILITY POINT
        if (isContract(_to)) {
            bool callSuccess = _to.call(bytes4(keccak256("tokenReceived(address,uint256)")), msg.sender, _value);
            require(callSuccess, "Token notification failed");
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balances[msg.sender] = balances[msg.sender].sub(_value);
        balances[_to] = balances[_to].add(_value);

        emit Transfer(msg.sender, _to, _value);

        // Asserts are used to use static analysis to find bugs in your code. They should never fail
        assert(balances[msg.sender].add(balances[_to]) == previousBalances);

        return true;
    }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    
    function isContract(address _addr) private view returns (bool) {
        uint32 size;
        assembly {
            size := extcodesize(_addr)
        }
        return (size > 0);
    }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

    function balanceOf(address _owner) constant public returns (uint256 balance) {
        return balances[_owner];
    }
}

contract BAIC is BasicToken {

    function () payable public {
        //if ether is sent to this address, send it back.
        //throw;
        require(false);
    }

    string public constant name = "BAIC";
    string public constant symbol = "BAIC";
    uint256 private constant _INITIAL_SUPPLY = 21000000000;
    uint8 public decimals = 18;
    uint256 public totalSupply;
    string public version = "BAIC 1.0";

    constructor() public {
        // init
        totalSupply = _INITIAL_SUPPLY * 10 ** 18;
        balances[msg.sender] = totalSupply;
    }
}