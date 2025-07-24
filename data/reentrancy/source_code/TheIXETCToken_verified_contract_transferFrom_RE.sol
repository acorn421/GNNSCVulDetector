/*
 * ===== SmartInject Injection Details =====
 * Function      : transferFrom
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added Pending Transfer Queue**: Introduced a `pendingTransfers` mapping that accumulates transfer amounts across multiple transactions, creating persistent state.
 * 
 * 2. **Multi-Transaction Processing**: The function now processes previously queued transfers from prior transactions while queuing the current transfer for future processing.
 * 
 * 3. **External Call Before State Update**: Added an external call to `_to.call()` that occurs BEFORE updating the allowance state, violating the checks-effects-interactions pattern.
 * 
 * 4. **State-Dependent Exploitation**: The vulnerability requires:
 *    - Transaction 1: Queue a transfer amount in `pendingTransfers`
 *    - Transaction 2: Process the queued transfer with external call that can re-enter
 *    - The external call can manipulate contract state before allowance is properly decremented
 * 
 * 5. **Realistic Callback Mechanism**: The external call attempts to notify recipients of transfers, which is a common pattern in modern tokens.
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * - **Transaction 1**: Attacker calls `transferFrom()` with legitimate allowance, amount gets queued in `pendingTransfers`
 * - **Transaction 2**: Attacker calls `transferFrom()` again, triggering processing of queued amount
 * - **During Transaction 2**: The external call to recipient allows re-entry before allowance is updated
 * - **Re-entry**: Attacker can call `transferFrom()` again during the external call, exploiting the unchanged allowance
 * - **Result**: Multiple transfers can occur using the same allowance due to the delayed state update
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability cannot be exploited in a single transaction because the initial call only queues the transfer
 * - State accumulation in `pendingTransfers` from previous transactions is necessary for the exploitation
 * - The external call that enables reentrancy only occurs when processing previously queued transfers
 * - This creates a time-delayed vulnerability that spans multiple blocks/transactions
 */
pragma solidity ^0.4.16;
 
interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) public; }
 
contract TheIXETCToken {
    string public name;
    string public symbol;
    uint8 public decimals = 8;  // 18 是建议的默认值
    uint256 public totalSupply;
 
    mapping (address => uint256) public balanceOf;  //
    mapping (address => mapping (address => uint256)) public allowance;
    mapping (address => mapping (address => uint256)) public pendingTransfers; // Added missing declaration

    event Transfer(address indexed from, address indexed to, uint256 value);
 
    event Burn(address indexed from, uint256 value);
 

    function TheIXETCToken(uint256 initialSupply, string tokenName, string tokenSymbol) public {
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
 
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) { // Fixed function definition
        require(_value <= allowance[_from][msg.sender]);     // Check allowance
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Multi-transaction vulnerability: Process pending transfers first
        if (pendingTransfers[_from][msg.sender] > 0) {
            uint256 pendingAmount = pendingTransfers[_from][msg.sender];
            pendingTransfers[_from][msg.sender] = 0;
            
            // External call before state update - enables reentrancy
            if (_to.call(bytes4(keccak256("onTransferReceived(address,uint256)")), _from, pendingAmount)) {
                // This external call can re-enter and manipulate state
            }
            
            // State update after external call
            allowance[_from][msg.sender] -= pendingAmount;
            _transfer(_from, _to, pendingAmount);
        }
        
        // Queue current transfer for next transaction
        pendingTransfers[_from][msg.sender] += _value;
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        return true;
    }
    
    function approve(address _spender, uint256 _value) public returns (bool success) { // Fixed function definition
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
        balanceOf[msg.sender] -= _value;
        totalSupply -= _value;
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
