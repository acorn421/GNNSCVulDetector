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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to notify the token holder (_from) about the burn operation BEFORE updating the contract state. This creates a classic reentrancy pattern where:
 * 
 * 1. **External Call Before State Updates**: The function calls _from.call() to notify about the burn operation before updating balanceOf, allowance, and totalSupply
 * 2. **State Persistence Between Calls**: The contract state (balanceOf, allowance, totalSupply) remains unchanged during the external call, allowing multiple burns with the same allowance
 * 3. **Multi-Transaction Exploitation**: Requires multiple transactions to exploit effectively:
 *    - Transaction 1: Initial burnFrom call triggers notification to malicious contract
 *    - During callback: Malicious contract calls burnFrom again with same parameters
 *    - Transaction 2: Second burnFrom executes with stale state values
 *    - Result: Double burning occurs but allowance is only decremented once
 * 
 * The vulnerability is stateful because it depends on the persistent state variables (balanceOf, allowance, totalSupply) maintaining their values between the initial call and the reentrant call. The exploit requires the attacker to deploy a malicious contract at the _from address that implements the onTokenBurn callback to perform the reentrancy attack.
 * 
 * This is a realistic vulnerability pattern that preserves the original function's behavior while introducing a subtle but exploitable security flaw that requires multiple function calls to trigger.
 */
pragma solidity ^0.4.16;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external; }

contract ONID {

    string public name;
    string public symbol;
    uint8 public decimals = 18;
    uint256 public totalSupply;

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Burn(address indexed from, uint256 value);
    uint256 initialSupply=10000000000000;
    string tokenName = "ONID";
    string tokenSymbol = "ONID";

    constructor() public {
        totalSupply = initialSupply * 10 ** uint256(decimals);  
        balanceOf[msg.sender] = totalSupply;               
        name = tokenName;                                  
        symbol = tokenSymbol;                               
    }

    function _transfer(address _from, address _to, uint _value) internal {
        require(_to != 0x0);
        require(balanceOf[_from] >= _value);
        require(balanceOf[_to] + _value >= balanceOf[_to]);
        uint previousBalances = balanceOf[_from] + balanceOf[_to];
        balanceOf[_from] -= _value;
        balanceOf[_to] += _value;
        emit Transfer(_from, _to, _value);
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

    function approve(address _spender, uint256 _value) public
        returns (bool success) {
        allowance[msg.sender][_spender] = _value;
        return true;
    }

    function approveAndCall(address _spender, uint256 _value, bytes _extraData)
        public
        returns (bool success) {
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
        emit Burn(msg.sender, _value);
        return true;
    }

    function isContract(address _addr) internal view returns (bool) {
        uint length;
        assembly { length := extcodesize(_addr) }
        return length > 0;
    }

    function burnFrom(address _from, uint256 _value) public returns (bool success) {
        require(balanceOf[_from] >= _value);                
        require(_value <= allowance[_from][msg.sender]);    
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // VULNERABILITY: External call to notify token holder BEFORE state updates
        // This allows reentrancy if _from is a contract that can call back
        if (_from != msg.sender && isContract(_from)) {
            // Notify the token holder about the burn operation
            _from.call(abi.encodeWithSignature("onTokenBurn(address,uint256)", msg.sender, _value));
            // Continue execution regardless of notification success
        }
        // VULNERABILITY: State updates happen AFTER external call
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[_from] -= _value;                         
        allowance[_from][msg.sender] -= _value;             
        totalSupply -= _value;                              
        emit Burn(_from, _value);
        return true;
    }
}
