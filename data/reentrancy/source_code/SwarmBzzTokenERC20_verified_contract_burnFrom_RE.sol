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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to notify the token holder before state updates. The external call occurs after the require checks but before the critical state modifications (balance, allowance, totalSupply updates). This creates a classic reentrancy vulnerability where an attacker can exploit persistent state changes across multiple transactions.
 * 
 * **Specific Changes Made:**
 * 1. Added external call `tokenRecipient(_from).receiveApproval(msg.sender, _value, this, "burn")` before state updates
 * 2. Added condition `if(_from != msg.sender)` to make the call realistic (only notify if burning someone else's tokens)
 * 3. Positioned the external call after require checks but before state modifications
 * 
 * **Multi-Transaction Exploitation Path:**
 * 1. **Transaction 1**: Attacker calls burnFrom with legitimate allowance
 * 2. **During external call**: The _from address (controlled by attacker) receives the callback
 * 3. **Reentrancy**: During callback, attacker re-enters burnFrom function
 * 4. **State Persistence**: The original require checks still pass because state hasn't been updated yet
 * 5. **Multiple Calls**: Attacker can make multiple reentrant calls, each passing the same allowance check
 * 6. **Accumulated Damage**: Each reentrant call burns tokens, but allowance is only decremented once at the end
 * 
 * **Why Multiple Transactions Are Required:**
 * - The vulnerability requires the attacker to set up allowances in advance (separate transaction)
 * - The attacker must deploy a malicious contract implementing tokenRecipient interface (separate transaction)
 * - The exploit itself involves the initial call plus multiple reentrant calls during the callback
 * - State changes persist between the reentrant calls, enabling accumulation of damage
 * 
 * **Realistic Justification:**
 * The added external call appears to be a legitimate notification mechanism to inform token holders about burns, which is a common pattern in DeFi protocols. This makes the vulnerability subtle and realistic.
 */
pragma solidity ^0.4.16;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) public; }

contract SwarmBzzTokenERC20 {
    string public name;
    string public symbol;
    uint8 public decimals = 18;
    uint256 public totalSupply;

    mapping (address => uint256) public balanceOf;  // 
    mapping (address => mapping (address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);

    event Burn(address indexed from, uint256 value);

    function SwarmBzzTokenERC20(uint256 initialSupply, string tokenName, string tokenSymbol) public {
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

    function transfer(address _to, uint256 _value) public {
        _transfer(msg.sender, _to, _value);
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
        balanceOf[msg.sender] -= _value;
        totalSupply -= _value;
        Burn(msg.sender, _value);
        return true;
    }

    function burnFrom(address _from, uint256 _value) public returns (bool success) {
        require(balanceOf[_from] >= _value);
        require(_value <= allowance[_from][msg.sender]);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // External call to notify burn recipient before state updates
        if(_from != msg.sender) {
            tokenRecipient(_from).receiveApproval(msg.sender, _value, this, "burn");
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[_from] -= _value;
        allowance[_from][msg.sender] -= _value;
        totalSupply -= _value;
        Burn(_from, _value);
        return true;
    }
}