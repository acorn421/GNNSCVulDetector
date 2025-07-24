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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract (_to) after balance updates but before allowance decrement. This creates a critical window where:
 * 
 * 1. **Transaction 1**: Attacker calls transferFrom, which updates balances but then calls the malicious recipient contract before decrementing allowance
 * 2. **During external call**: Malicious recipient re-enters transferFrom using the same allowance (since it hasn't been decremented yet)
 * 3. **Transaction 2+**: The same allowance can be reused across multiple transactions because the external call happens before allowance update
 * 
 * **Multi-Transaction Exploitation Pattern:**
 * - **State Accumulation**: Each successful transferFrom call updates balances but the allowance remains exploitable due to reentrancy
 * - **Persistent State**: The allowance state persists between transactions, allowing repeated exploitation
 * - **Sequence Dependency**: Requires multiple calls to fully drain the allowance beyond its intended limit
 * 
 * **Why Multi-Transaction is Required:**
 * 1. The vulnerability exploits the persistent allowance state across multiple function calls
 * 2. Each transaction can only transfer up to the current allowance, but reentrancy allows bypassing the allowance decrement
 * 3. Multiple transactions are needed to accumulate the full exploit impact
 * 4. Single transaction exploitation is limited by gas limits and the need to establish the malicious contract state
 * 
 * The external call uses ERC777-style token receiver hooks, which is a realistic feature that legitimately appears in modern token contracts, making this vulnerability subtle and production-like.
 */
pragma solidity ^0.4.8;
contract tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData); }

contract ITokenReceiver {
    function onTokenReceived(address _from, uint256 _value, address _sender) public;
}

contract BlockPlanet{
    /* Public variables of the token */
    string public standard = 'BlockPlanet 0.1';
    string public name;
    string public symbol;
    uint8 public decimals;
    uint256 public totalSupply;

    /* This creates an array with all balances . */
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    /* This generates a public event on the blockchain that will notify clients */
    event Transfer(address indexed from, address indexed to, uint256 value);

    /* This notifies clients about the amount burnt */
    event Burn(address indexed from, uint256 value);

    /* Initializes contract with initial supply tokens to the creator of the contract */
    function BlockPlanet() {
        balanceOf[msg.sender] =  7800000000 * 1000000000000000000;              // Give the creator all initial tokens
        totalSupply =  7800000000 * 1000000000000000000;                        // Update total supply
        name = "BlockPlanet";                                   // Set the name for display purposes
        symbol = "BPL";                               // Set the symbol for display purposes
        decimals = 18;                            // Amount of decimals for display purposes
    }

    /* Send coins */
    function transfer(address _to, uint256 _value) {
        if (_to == 0x0) throw;                               // Prevent transfer to 0x0 address. Use burn() instead
        if (balanceOf[msg.sender] < _value) throw;           // Check if the sender has enough
        if (balanceOf[_to] + _value < balanceOf[_to]) throw; // Check for overflows
        balanceOf[msg.sender] -= _value;                     // Subtract from the sender
        balanceOf[_to] += _value;                            // Add the same to the recipient
        Transfer(msg.sender, _to, _value);                   // Notify anyone listening that this transfer took place
    }

    /* Allow another contract to spend some tokens in your behalf */
    function approve(address _spender, uint256 _value)
        returns (bool success) {
        allowance[msg.sender][_spender] = _value;
        return true;
    }

    /* Approve and then communicate the approved contract in a single tx */
    function approveAndCall(address _spender, uint256 _value, bytes _extraData)
        returns (bool success) {
        tokenRecipient spender = tokenRecipient(_spender);
        if (approve(_spender, _value)) {
            spender.receiveApproval(msg.sender, _value, this, _extraData);
            return true;
        }
    }

    /* A contract attempts to get the coins */
    function transferFrom(address _from, address _to, uint256 _value) returns (bool success) {
        if (_to == 0x0) throw;                                // Prevent transfer to 0x0 address. Use burn() instead
        if (balanceOf[_from] < _value) throw;                 // Check if the sender has enough
        if (balanceOf[_to] + _value < balanceOf[_to]) throw;  // Check for overflows
        if (_value > allowance[_from][msg.sender]) throw;     // Check allowance
        balanceOf[_from] -= _value;                           // Subtract from the sender
        balanceOf[_to] += _value;                             // Add the same to the recipient
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify recipient contract if it has code (ERC777-style hook)
        if (_isContract(_to)) {
            ITokenReceiver(_to).onTokenReceived(_from, _value, msg.sender);
        }
        
        allowance[_from][msg.sender] -= _value;               // Decrement allowance AFTER external call
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        Transfer(_from, _to, _value);
        return true;
    }

    function _isContract(address _addr) internal constant returns (bool) {
        uint256 length;
        assembly {
            length := extcodesize(_addr)
        }
        return (length > 0);
    }

    function burn(uint256 _value) returns (bool success) {
        if (balanceOf[msg.sender] < _value) throw;            // Check if the sender has enough
        balanceOf[msg.sender] -= _value;                      // Subtract from the sender
        totalSupply -= _value;                                // Updates totalSupply
        Burn(msg.sender, _value);
        return true;
    }

    function burnFrom(address _from, uint256 _value) returns (bool success) {
        if (balanceOf[_from] < _value) throw;                // Check if the sender has enough
        if (_value > allowance[_from][msg.sender]) throw;    // Check allowance
        balanceOf[_from] -= _value;                          // Subtract from the sender
        totalSupply -= _value;                               // Updates totalSupply
        Burn(_from, _value);
        return true;
    }
}
