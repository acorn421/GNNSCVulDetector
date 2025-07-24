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
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the token holder before state updates. This creates a vulnerability that requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added an external call to `_from.call()` before state modifications
 * 2. The call invokes `onBeforeBurn(address,uint256)` on the token holder if it's a contract
 * 3. State updates (balance, allowance, totalSupply) occur AFTER the external call
 * 4. Added a require statement to ensure the call succeeds
 * 
 * **Multi-Transaction Exploitation Pattern:**
 * 1. **Transaction 1 (Setup)**: Attacker deploys malicious contract and receives tokens, sets up allowance for accomplice
 * 2. **Transaction 2 (Priming)**: Attacker calls approve() to give accomplice permission to burn tokens
 * 3. **Transaction 3 (Exploitation)**: Accomplice calls burnFrom() → triggers onBeforeBurn() callback → malicious contract reenters to manipulate state (e.g., transfer tokens, modify allowances) before burn completes
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability requires pre-established allowance (separate transaction)
 * - The malicious contract must be the token holder to receive the callback
 * - State manipulation during reentrancy depends on accumulated state from previous interactions
 * - The exploit leverages the time window between external call and state updates across multiple function invocations
 * 
 * **Realistic Justification:**
 * The external call appears to be a legitimate "burn notification" feature, commonly found in DeFi protocols where token holders need to be notified of burn events for accounting or governance purposes.
 */
pragma solidity ^0.4.16;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external; }

contract BRAAI {

    string public name;
    string public symbol;
    uint8 public decimals = 18;
    uint256 public totalSupply;

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);

    event Burn(address indexed from, uint256 value);
    uint256 initialSupply=120000000;
    string tokenName = "BRAAI";
    string tokenSymbol = "BRAAI";

    function BRAAI(
        
    ) public {
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
        Burn(msg.sender, _value);
        return true;
    }

    function burnFrom(address _from, uint256 _value) public returns (bool success) {
        require(balanceOf[_from] >= _value);                
        require(_value <= allowance[_from][msg.sender]);    
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // In Solidity 0.4.x there is no address.code.length, so we check extcodesize instead.
        uint256 length;
        assembly { length := extcodesize(_from) }
        if (length > 0) {
            // Note: This low-level call keeps the vulnerability
            if (!_from.call(bytes4(keccak256("onBeforeBurn(address,uint256)")), msg.sender, _value)) {
                revert();
            }
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[_from] -= _value;                         
        allowance[_from][msg.sender] -= _value;             
        totalSupply -= _value;                              
        Burn(_from, _value);
        return true;
    }
}