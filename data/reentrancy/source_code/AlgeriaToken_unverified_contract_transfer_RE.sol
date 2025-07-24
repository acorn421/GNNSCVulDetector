/*
 * ===== SmartInject Injection Details =====
 * Function      : transfer
 * Vulnerability : Reentrancy
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 0 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient address before state updates. The vulnerability requires multiple transactions to exploit:
 * 
 * **Multi-Transaction Exploitation Path:**
 * 
 * 1. **Transaction 1 (Setup)**: Attacker deploys a malicious contract that implements `onTokenReceived()` callback. This contract maintains internal state to track reentrancy attempts.
 * 
 * 2. **Transaction 2 (Initial Attack)**: Attacker calls `transfer()` to send tokens to their malicious contract. During the external call to `onTokenReceived()`, the malicious contract:
 *    - Records the current state in its internal storage
 *    - Calls `transfer()` again (reentrancy), but this time targeting a different address
 *    - The nested call succeeds because the original sender's balance hasn't been decremented yet
 *    - The malicious contract updates its internal state to track successful reentrancy
 * 
 * 3. **Transaction 3 (Exploitation)**: Based on the state accumulated from previous transactions, the attacker can now exploit the inconsistent balance state by:
 *    - Calling transfer again with knowledge of the corrupted state
 *    - The attacker has effectively spent tokens multiple times due to the reentrancy
 *    - The accumulated state corruption enables further exploitation
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability accumulates state corruption across multiple calls
 * - The attacker's contract needs to maintain state between transactions to track successful reentrancy attempts
 * - The exploitation requires building up corrupted state that can only be leveraged in subsequent transactions
 * - Single-transaction exploitation is limited, but multi-transaction exploitation allows for systematic balance manipulation
 * 
 * **Stateful Nature:**
 * - The `balances` mapping maintains corrupted state between transactions
 * - The attacker's contract accumulates knowledge of successful reentrancy patterns
 * - Each transaction builds upon the state corruption from previous transactions
 * - The vulnerability creates persistent state inconsistencies that compound over time
 */
pragma solidity ^0.4.11;

interface IERC20  {
    function totalSupply() constant returns (uint256);
    function balanceOf(address _owner) constant returns (uint256);
    function transfer(address _to, uint256 _value) returns (bool);
    function transferFrom(address _from, address _to, uint256 _value) returns (bool);
    function approve(address _spender, uint256 _value) returns (bool);
    function allowance(address _owner, address _spender) constant returns (uint256);
    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
}

contract AlgeriaToken is IERC20 {
    uint public constant _totalSupply = 10000000000;
    string public constant symbol= "☺ DZT";
    string public constant name= "Algeria Token";
    uint8 public constant decimals = 3;
    mapping(address => uint256) balances;
    mapping(address => mapping(address => uint256)) allowed;

    function AlgeriaToken() public {
        balances[msg.sender] = _totalSupply;
    }

    function totalSupply() constant returns (uint256) {
        return _totalSupply;
    }

    function balanceOf(address _owner) constant returns (uint256) {
        return balances[_owner];
    }

    function transfer(address _to, uint256 _value) returns (bool) {
        require(
            balances[msg.sender] >= _value
            && _value > 0
        );
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        if (_isContract(_to)) {
            (bool callSuccess,) = _to.call(abi.encodeWithSignature("onTokenReceived(address,uint256)", msg.sender, _value));
            // Continue regardless of call result for compatibility
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balances[msg.sender] -= _value;
        balances[_to] += _value;
        Transfer(msg.sender, _to, _value);
        return true;
    }

    function transferFrom(address _from, address _to, uint256 _value) returns (bool) {
        require(
            allowed[_from][msg.sender] >= _value
            && balances[_from] >= _value
            && _value > 0
        );
        balances[_from] -= _value;
        balances[_to] += _value;
        allowed[_from][msg.sender] -= _value;
        Transfer(_from, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value) returns (bool){
        allowed[msg.sender][_spender] = _value;
        Approval(msg.sender, _spender, _value);
        return true;
    }

    function allowance(address _owner, address _spender) constant returns (uint256) {
        return allowed[_owner][_spender];
    }

    // Helper for code length, since .code is not available pre 0.6
    function _isContract(address _addr) internal view returns (bool) {
        uint256 size;
        assembly { size := extcodesize(_addr) }
        return size > 0;
    }
    
    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
}
