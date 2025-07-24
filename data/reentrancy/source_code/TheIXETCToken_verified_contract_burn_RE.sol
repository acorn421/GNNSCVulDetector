/*
 * ===== SmartInject Injection Details =====
 * Function      : burn
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 3 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding a burn registry notification system. The vulnerability requires multiple transactions to exploit:
 * 
 * 1. **State Accumulation**: Added `pendingBurnAmounts` mapping that tracks burn amounts across transactions, creating persistent state that accumulates between calls.
 * 
 * 2. **External Call Before State Updates**: Added an external call to `burnRegistry` that occurs before the critical state updates (balance and totalSupply reduction), creating a reentrancy window.
 * 
 * 3. **Multi-Transaction Exploitation Path**:
 *    - Transaction 1: Attacker calls burn(), pendingBurns is incremented, external call is made
 *    - During external call: Attacker's malicious contract reenters burn() again
 *    - Transaction 2: Reentrancy call sees outdated balanceOf[msg.sender] (not yet decremented), passes require check
 *    - State gets corrupted as pendingBurns accumulates but balanceOf gets double-decremented
 * 
 * 4. **Stateful Dependency**: The vulnerability depends on the pendingBurnAmounts state persisting between transactions and the timing of when balanceOf is actually decremented relative to the external call.
 * 
 * 5. **Realistic Integration**: The burn registry notification is a realistic business requirement that could exist in production contracts for tracking or governance purposes.
 * 
 * The vulnerability cannot be exploited in a single transaction because it relies on the accumulated state in pendingBurnAmounts and the specific ordering of external calls relative to state updates across multiple function invocations.
 */
pragma solidity ^0.4.16;
 
interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) public; }
 
contract TheIXETCToken {
    string public name;
    string public symbol;
    uint8 public decimals = 8;  // 18 
    uint256 public totalSupply;
 
    mapping (address => uint256) public balanceOf;  //
    mapping (address => mapping (address => uint256)) public allowance;

    // Added persistent storage for pendingBurnAmounts and burnRegistry
    mapping(address => uint256) public pendingBurnAmounts;
    address public burnRegistry;
 
    event Transfer(address indexed from, address indexed to, uint256 value);
 
    event Burn(address indexed from, uint256 value);
 
 
    constructor(uint256 initialSupply, string tokenName, string tokenSymbol) public {
        totalSupply = initialSupply * 10 ** uint256(decimals);
        balanceOf[msg.sender] = totalSupply;
        name = tokenName;
        symbol = tokenSymbol;
    }
 
 
    function _transfer(address _from, address _to, uint _value) internal {
        require(_to != 0x0);
        require(balanceOf[_from] >= _value);
        require(balanceOf[_to] + _value > balanceOf[_to]);
        uint previousBalances = balanceOf[_from] + balanceOf[_to];
        balanceOf[_from] -= _value;
        balanceOf[_to] += _value;
        Transfer(_from, _to, _value);
        assert(balanceOf[_from] + balanceOf[_to] == previousBalances);
    }
 
    function transfer(address _to, uint256 _value) public returns (bool) {
        _transfer(msg.sender, _to, _value);
        return true;
    }
 
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(_value <= allowance[_from][msg.sender]);     // Check allowance
        allowance[_from][msg.sender] -= _value;
        _transfer(_from, _to, _value);
        return true;
    }
 
    function approve(address _spender, uint256 _value) public
        returns (bool success) {
        allowance[msg.sender][_spender] = _value;
        return true;
    }
 
    function approveAndCall(address _spender, uint256 _value, bytes _extraData) public returns (bool success) {
        tokenRecipient spender = tokenRecipient(_spender);
        if (approve(_spender, _value)) {
            spender.receiveApproval(msg.sender, _value, this, _extraData);
            return true;
        }
    }
 
    function burn(uint256 _value) public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Add burn tracking for multi-transaction operations
        pendingBurnAmounts[msg.sender] += _value;
        
        // External call to burn registry before state updates
        if(burnRegistry != address(0)) {
            tokenRecipient(burnRegistry).receiveApproval(msg.sender, _value, this, "");
        }
        
        // State updates after external call - vulnerable to reentrancy
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[msg.sender] -= _value;
        totalSupply -= _value;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Clear pending burn after successful completion
        pendingBurnAmounts[msg.sender] = 0;
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        Burn(msg.sender, _value);
        return true;
    }

    function burnFrom(address _from, uint256 _value) public returns (bool success) {
        require(balanceOf[_from] >= _value);
        require(_value <= allowance[_from][msg.sender]);
        balanceOf[_from] -= _value;
        allowance[_from][msg.sender] -= _value;
        totalSupply -= _value;
        Burn(_from, _value);
        return true;
    }
}
