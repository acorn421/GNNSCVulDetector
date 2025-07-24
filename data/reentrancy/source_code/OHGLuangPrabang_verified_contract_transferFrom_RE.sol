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
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * This injection introduces a stateful, multi-transaction reentrancy vulnerability by adding a recipient notification callback before state updates. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added external call to recipient contract using `ITokenReceiver(_to).onTokenReceived(_from, _value)`
 * 2. The call occurs AFTER validation checks but BEFORE state updates (violating CEI pattern)
 * 3. Used try-catch to make the callback optional and maintain backward compatibility
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * Transaction 1: Attacker sets up allowance and prepares malicious recipient contract
 * Transaction 2: Legitimate user calls transferFrom() to malicious contract
 * Transaction 3+: During the callback, malicious contract can re-enter transferFrom() with remaining allowance before original state updates complete
 * 
 * **Why Multi-Transaction Nature:**
 * - Allowance must be set in prior transaction via approve()
 * - Each reentrancy call consumes allowance, requiring accumulated state across calls
 * - Attack requires persistent allowance state that survives between transactions
 * - Attacker needs to position themselves as recipient in one transaction to exploit in subsequent callback
 * 
 * **State Persistence Requirements:**
 * - allowed[_from][msg.sender] persists between transactions
 * - balances[_from] remains unchanged until after callback
 * - Malicious contract can make multiple transferFrom calls using the same allowance
 * - Each reentrant call sees the old state until the original call completes
 * 
 * This creates a realistic vulnerability where the external call creates a reentrancy window that can be exploited across multiple transactions through the persistent allowance mechanism.
 */
pragma solidity ^0.4.11;

contract OHGLuangPrabang {
    
    uint public constant _totalSupply = 150000000000000000000000000;
    
    string public constant symbol = "OHGLP";
    string public constant name = "OHG Luang Prabang";
    uint8 public constant decimals = 18;
    
    mapping(address => uint256) balances;
    mapping(address => mapping(address => uint256)) allowed;
    
    function OHGLuangPrabang() public {
        balances[msg.sender] = _totalSupply;
    }
    
    function totalSupply() public constant returns (uint256 totalSupply) {
        return _totalSupply;
    }

    function balanceOf(address _owner) public constant returns (uint256 balance) {
        return balances[_owner]; 
    }
    
    function transfer (address _to, uint256 _value) public returns (bool success) {
        require(
            balances[msg.sender] >= _value
            && _value > 0 
        );
        balances[msg.sender] -= _value;
        balances[_to] += _value;
        Transfer(msg.sender, _to, _value);
        return true;
    }

    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(
            allowed[_from][msg.sender] >= _value
            && balances[_from] >= _value
            && _value > 0 
        );
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Notify recipient contract before state updates (introduces reentrancy)
        if (_to.call(bytes4(keccak256("onTokenReceived(address,uint256)")), _from, _value)) {
            // Continue with transfer
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balances[_from] -= _value;
        balances[_to] += _value;
        allowed[_from][msg.sender] -= _value;
        Transfer(_from, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value) public returns (bool success) {
        allowed[msg.sender][_spender] = _value;
        Approval(msg.sender, _spender, _value);
        return true;
    }

    function allowance(address _owner, address _spender) public constant returns (uint256 remaining) {
        return allowed[_owner][_spender];
    }

    event Transfer(address indexed _from, address indexed _to, uint256 _value); 
    event Approval(address indexed _owner, address indexed _spender, uint256 _value); 
}
