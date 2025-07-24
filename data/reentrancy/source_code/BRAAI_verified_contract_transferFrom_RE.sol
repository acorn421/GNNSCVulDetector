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
 * Added external call to recipient address before state updates, violating the Checks-Effects-Interactions (CEI) pattern. This creates a stateful, multi-transaction reentrancy vulnerability where:
 * 
 * **Specific Changes Made:**
 * 1. Added external call to `_to` address using `call()` with function signature "onTokenReceived(address,uint256)"
 * 2. Placed this external call BEFORE the allowance deduction and transfer execution
 * 3. This violates the CEI pattern by making external calls before state changes
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1**: Attacker calls `transferFrom()` with a malicious contract as `_to`
 * 2. **External Call**: The malicious contract's `onTokenReceived()` is triggered
 * 3. **Reentrancy**: The malicious contract re-enters `transferFrom()` with the same parameters
 * 4. **State Persistence**: Since allowance hasn't been decremented yet, the check passes again
 * 5. **Gradual Exploitation**: Each reentrant call processes part of the allowance before eventually failing due to balance limits
 * 6. **Transaction 2+**: Subsequent transactions can continue the exploitation pattern as allowance state persists between transactions
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability exploits the allowance mechanism which persists between transactions
 * - Each transaction can only exploit a portion of the available allowance due to balance constraints
 * - The attacker needs multiple transactions to fully drain the allowance as each reentrant call consumes part of the allowance
 * - The persistent state (allowance mapping) enables continued exploitation across transaction boundaries
 * - Balance limits in `_transfer()` function prevent complete exploitation in a single transaction
 * 
 * **Realistic Integration:**
 * - Token recipient notifications are common in modern ERC-20 implementations
 * - The external call appears as a legitimate feature enhancement
 * - The vulnerability is subtle and could easily be overlooked in code review
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

    constructor(
        
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
        emit Transfer(_from, _to, _value);
        assert(balanceOf[_from] + balanceOf[_to] == previousBalances);
    }


    function transfer(address _to, uint256 _value) public {
        _transfer(msg.sender, _to, _value);
    }


    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(_value <= allowance[_from][msg.sender]);  
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // External call to recipient before state updates (CEI violation)
        if (_to.call(bytes4(keccak256("onTokenReceived(address,uint256)")), _from, _value)) {
            // Optional callback handling
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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


    function burnFrom(address _from, uint256 _value) public returns (bool success) {
        require(balanceOf[_from] >= _value);                
        require(_value <= allowance[_from][msg.sender]);    
        balanceOf[_from] -= _value;                         
        allowance[_from][msg.sender] -= _value;             
        totalSupply -= _value;                              
        emit Burn(_from, _value);
        return true;
    }
}