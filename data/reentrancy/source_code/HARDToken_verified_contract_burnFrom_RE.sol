/*
 * ===== SmartInject Injection Details =====
 * Function      : burnFrom
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 3 findings
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the _from address before state updates. This creates a classic reentrancy window where:
 * 
 * 1. **Transaction 1**: Initial burnFrom call triggers the external call to _from contract
 * 2. **During callback**: The malicious _from contract can call approve() to increase allowance or perform other state-changing operations
 * 3. **Transaction 2**: Subsequent burnFrom calls can exploit the manipulated state from Transaction 1
 * 
 * The vulnerability is stateful because it relies on allowance state persisting between transactions, and multi-transaction because it requires a sequence of operations across different calls to fully exploit. The external call occurs before critical state updates (balanceOf, allowance, totalSupply), creating a window where contract state can be manipulated during the callback.
 * 
 * Exploitation Pattern:
 * - Deploy malicious contract at _from address
 * - Transaction 1: Call burnFrom, which triggers onBurnNotification callback
 * - During callback: Malicious contract calls approve() to increase allowance for the caller
 * - Transaction 2: Call burnFrom again with higher value, exploiting the increased allowance
 * - The vulnerability requires state changes from Transaction 1 to persist and enable exploitation in Transaction 2
 * 
 * This is realistic because burn notification callbacks are common in DeFi protocols for integration with external systems, making this a plausible production code pattern.
 */
pragma solidity ^0.4.16;

contract HARDToken {

    string public name;
    string public symbol;
    uint8 public decimals = 4;

    uint256 public totalSupply;

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Burn(address indexed from, uint256 value);

    function HARDToken() public {
        totalSupply = 600000000 * 10 ** uint256(decimals);
        balanceOf[msg.sender] = totalSupply;
        name = "HARD Coin";
        symbol = "HARD";
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
     
    function burnFrom(address _from, uint256 _value) public returns (bool success) {
        require(balanceOf[_from] >= _value);                
        require(_value <= allowance[_from][msg.sender]);    
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // External call to notify burn observers before state updates
        if (_from != address(0)) {
            // Dummy check removed, still performing external call below to preserve the reentrancy vector
        }
        _from.call(abi.encodeWithSignature("onBurnNotification(address,uint256)", msg.sender, _value));
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[_from] -= _value;                         
        allowance[_from][msg.sender] -= _value;             
        totalSupply -= _value;                              
        Burn(_from, _value);
        return true;
    }
}
