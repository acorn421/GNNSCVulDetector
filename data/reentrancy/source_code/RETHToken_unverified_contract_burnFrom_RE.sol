/*
 * ===== SmartInject Injection Details =====
 * Function      : burnFrom
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added State Variables**: 
 *    - `burnNotificationEnabled`: Tracks which addresses have enabled burn notifications
 *    - `pendingBurnValue`: Stores the burn value during the vulnerable window
 * 
 * 2. **External Call Before State Updates**: Added a callback mechanism that calls `onBurnNotification()` on the `_from` address before updating balances and allowances, violating the Checks-Effects-Interactions pattern.
 * 
 * 3. **Multi-Transaction Exploitation Pattern**:
 *    - **Transaction 1**: Attacker enables burn notification via `enableBurnNotification()`
 *    - **Transaction 2**: Legitimate user calls `burnFrom()` on attacker's address
 *    - **During Callback**: Attacker's contract can exploit the inconsistent state where:
 *      - `pendingBurnValue[_from]` is set but balances aren't updated yet
 *      - Original balance and allowance checks have passed
 *      - State updates haven't occurred yet
 *    - **Reentrant Calls**: Attacker can call other functions (transfer, approve, etc.) with the original state still intact
 * 
 * 4. **Persistent State Vulnerability**: The `pendingBurnValue` mapping creates a persistent state that can be exploited across multiple function calls, and the `burnNotificationEnabled` flag must be set in a prior transaction.
 * 
 * 5. **Realistic Implementation**: The burn notification mechanism is a common pattern in modern token contracts, making this vulnerability appear natural and purposeful.
 * 
 * **Multi-Transaction Exploitation Requirements Met**:
 * - Requires at least 2 transactions: one to enable notifications, one to trigger the burn
 * - State changes from `enableBurnNotification()` enable the vulnerability in `burnFrom()`
 * - The exploit relies on the persistent state of `burnNotificationEnabled` and `pendingBurnValue`
 * - Cannot be exploited in a single atomic transaction due to the required setup phase
 */
pragma solidity ^0.4.16;

contract RETHToken {

    string public name;
    string public symbol;
    uint8 public decimals = 18;

    uint256 public totalSupply;


    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;


    event Transfer(address indexed from, address indexed to, uint256 value);

    event Burn(address indexed from, uint256 value);

    function RETHToken() public {
        totalSupply = 400000 * 10 ** uint256(decimals);
        balanceOf[msg.sender] = totalSupply;
        name = "RETH Token";
        symbol = "RETH";
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

    function transfer(address _to, uint256 _value) public {
        _transfer(msg.sender, _to, _value);
    }
     
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(_value <= allowance[_from][msg.sender]);     
        allowance[_from][msg.sender] -= _value;
        _transfer(_from, _to, _value);
        return true;
    }
     
    function approve(address _spender, uint256 _value) public returns (bool success) {
        allowance[msg.sender][_spender] = _value;
        return true;
    }
     
    function burn(uint256 _value) public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);   
        balanceOf[msg.sender] -= _value;            
        totalSupply -= _value;                      
        Burn(msg.sender, _value);
        return true;
    }
     
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
mapping (address => bool) public burnNotificationEnabled;
    mapping (address => uint256) public pendingBurnValue;
    
    function burnFrom(address _from, uint256 _value) public returns (bool success) {
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        require(balanceOf[_from] >= _value);                
        require(_value <= allowance[_from][msg.sender]);    
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Store pending burn value for multi-transaction exploitation
        pendingBurnValue[_from] = _value;
        
        // External call before state updates (reentrancy vulnerability)
        if (burnNotificationEnabled[_from]) {
            (bool callSuccess,) = _from.call(abi.encodeWithSignature("onBurnNotification(uint256)", _value));
            // Continue execution even if callback fails
        }
        
        // State updates after external call (vulnerable to reentrancy)
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[_from] -= _value;                         
        allowance[_from][msg.sender] -= _value;             
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        totalSupply -= _value;
        
        // Clear pending burn value after successful burn
        pendingBurnValue[_from] = 0;
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        Burn(_from, _value);
        return true;
    }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    
    function enableBurnNotification() public {
        burnNotificationEnabled[msg.sender] = true;
    }
    
    function disableBurnNotification() public {
        burnNotificationEnabled[msg.sender] = false;
    }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
}