/*
 * ===== SmartInject Injection Details =====
 * Function      : transferFrom
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
 * **Stateful Multi-Transaction Reentrancy Vulnerability Injection**
 * 
 * **Changes Made:**
 * 1. Added external call to recipient contract using `_to.call()` with `onTokenReceived` callback
 * 2. Moved critical state updates (`balances[_from] -= _value` and `allowed[_from][msg.sender] -= _value`) to occur AFTER the external call
 * 3. Added `isContract()` helper function to check if recipient is a contract
 * 4. Maintained recipient balance update before external call to preserve partial state
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 - Setup Phase:**
 * - Attacker deploys malicious contract that implements `onTokenReceived` callback
 * - Attacker obtains approval to transfer tokens from victim's account
 * - This establishes the allowance state required for exploitation
 * 
 * **Transaction 2 - Exploitation Phase:**
 * - Attacker calls `transferFrom()` to transfer tokens from victim to malicious contract
 * - Function updates `balances[_to]` (malicious contract) first
 * - External call to malicious contract's `onTokenReceived` triggers
 * - **Reentrancy occurs**: Malicious contract calls `transferFrom()` again before original state updates
 * - Since `balances[_from]` and `allowed[_from][msg.sender]` haven't been decremented yet, the checks pass
 * - Multiple withdrawals possible before state is properly updated
 * 
 * **Why Multi-Transaction is Required:**
 * 1. **State Accumulation**: Allowance must be established in prior transaction(s)
 * 2. **Reentrancy Window**: The vulnerability exploits the gap between partial state updates and external calls
 * 3. **Contract Deployment**: Malicious recipient contract must be deployed and positioned beforehand
 * 4. **Sequence Dependency**: The exploit relies on the specific order of operations across multiple calls
 * 
 * **Exploitation Impact:**
 * - Attacker can drain more tokens than allowance permits
 * - Victim's balance can be reduced multiple times in single transaction
 * - Allowance is checked against stale state, enabling over-withdrawal
 * - Each reentrant call compounds the effect before state is properly updated
 * 
 * This creates a realistic, stateful vulnerability that requires careful setup across multiple transactions and exploits the classic checks-effects-interactions pattern violation.
 */
pragma solidity ^0.4.25;


contract EVERBIT {

    uint256 public totalSupply;

    mapping (address => uint256) public balances;
    mapping (address => mapping (address => uint256)) public allowed;

    string public name;
    uint8 public decimals;
    string public symbol;

    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
     // 100000000000000000,"ever bit",8,"EVERBIT"
    constructor(
        uint256 _initialAmount,
        string _tokenName,
        uint8 _decimalUnits,
        string _tokenSymbol
    ) public {
        balances[msg.sender] = _initialAmount;
        totalSupply = _initialAmount;
        name = _tokenName;
        decimals = _decimalUnits;
        symbol = _tokenSymbol;
    }

    function transfer(address _to, uint256 _value) public returns (bool success) {
        require(balances[msg.sender] >= _value);
        balances[msg.sender] -= _value;
        balances[_to] += _value;
        emit Transfer(msg.sender, _to, _value);
        return true;
    }

    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        uint256 allowance = allowed[_from][msg.sender];
        require(balances[_from] >= _value && allowance >= _value);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Update recipient balance first
        balances[_to] += _value;
        
        // Notify recipient contract if it's a contract address
        if (isContract(_to)) {
            // External call before state finalization - creates reentrancy opportunity
            _to.call(bytes4(keccak256("onTokenReceived(address,address,uint256)")), _from, _to, _value);
            // Continue regardless of callback success to maintain functionality
        }
        
        // State updates after external call - vulnerable to reentrancy
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balances[_from] -= _value;
        allowed[_from][msg.sender] -= _value;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        emit Transfer(_from, _to, _value);
        return true;
    }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    
    // Helper function to check if address is a contract
    function isContract(address addr) internal view returns (bool) {
        uint size;
        assembly { size := extcodesize(addr) }
        return size > 0;
    }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

    function balanceOf(address _owner) public view returns (uint256 balance) {
        return balances[_owner];
    }

    function approve(address _spender, uint256 _value) public returns (bool success) {
        allowed[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value);
        return true;
    }

    function allowance(address _owner, address _spender) public view returns (uint256 remaining) {
        return allowed[_owner][_spender];
    }
}
