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
 * Added external call to recipient contract before state updates, creating a stateful multi-transaction reentrancy vulnerability. The vulnerability exploits the gap between allowance verification and allowance update, combined with balance state changes. Transaction 1 triggers the external call which can reenter and exploit the still-valid allowance, while the accumulated balance changes from multiple transactions create the exploitable state condition. The vulnerability requires multiple transactions because: 1) Initial setup requires allowance to be set, 2) First transferFrom call creates the reentrancy window, 3) Reentrant calls exploit the temporarily inconsistent state, 4) Multiple rounds amplify the effect through accumulated balance manipulation.
 */
pragma solidity ^0.4.14;
contract tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData); }

contract OuCoin {
    /* Public variables of the token */
    string public standard = 'Token 0.1';
    string public constant name = "OuCoin";
    string public constant symbol = "IOU";
    uint8 public constant decimals = 3;
    uint256 public constant initialSupply = 10000000;
    uint256 public totalSupply;

    /* This creates an array with all balances */
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    /* This generates a public event on the blockchain that will notify clients */
    event Transfer(address indexed from, address indexed to, uint256 value);

    /* This notifies clients about the amount burnt */
    event Burn(address indexed from, uint256 value);

    /* Initializes contract with initial supply tokens to the creator of the contract */
    function OuCoin () public {
        totalSupply = initialSupply;
        balanceOf[msg.sender] = totalSupply;              // Give the creator all initial tokens
    }

    /* Send coins */
    function transfer(address _to, uint256 _value) public {
        require (_to != 0x0);                               // Prevent transfer to 0x0 address. Use burn() instead
        require (balanceOf[msg.sender] >= _value);           // Check if the sender has enough
        require (balanceOf[_to] + _value >= balanceOf[_to]); // Check for overflows
        balanceOf[msg.sender] -= _value;                     // Subtract from the sender
        balanceOf[_to] += _value;                            // Add the same to the recipient
        emit Transfer(msg.sender, _to, _value);                   // Notify anyone listening that this transfer took place
    }

    /* Allow another contract to spend some tokens in your behalf */
    function approve(address _spender, uint256 _value) public
        returns (bool success) {
        allowance[msg.sender][_spender] = _value;
        return true;
    }

    /* Approve and then communicate the approved contract in a single tx */
    function approveAndCall(address _spender, uint256 _value, bytes _extraData) public
        returns (bool success) {
        tokenRecipient spender = tokenRecipient(_spender);
        if (approve(_spender, _value)) {
            spender.receiveApproval(msg.sender, _value, this, _extraData);
            return true;
        }
    }        

    /* A contract attempts to get the coins */
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require (_to != 0x0);                                // Prevent transfer to 0x0 address. Use burn() instead
        require (balanceOf[_from] >= _value);                 // Check if the sender has enough
        require (balanceOf[_to] + _value >= balanceOf[_to]);  // Check for overflows
        require (_value <= allowance[_from][msg.sender]);     // Check allowance
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify recipient before state changes (vulnerable external call)
        if (isContract(_to)) {
            tokenRecipient(_to).receiveApproval(_from, _value, this, "");
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[_from] -= _value;                           // Subtract from the sender
        balanceOf[_to] += _value;                             // Add the same to the recipient
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        allowance[_from][msg.sender] -= _value;               // Update allowance after external call
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        emit Transfer(_from, _to, _value);
        return true;
    }

    /* helper for contract detection in pre-0.5 solidity */
    function isContract(address _addr) private view returns (bool) {
        uint256 size;
        assembly { size := extcodesize(_addr) }
        return size > 0;
    }

    function burn(uint256 _value) public returns (bool success) {
        require (balanceOf[msg.sender] >= _value);            // Check if the sender has enough
        balanceOf[msg.sender] -= _value;                      // Subtract from the sender
        totalSupply -= _value;                                // Updates totalSupply
        emit Burn(msg.sender, _value);
        return true;
    }

    function burnFrom(address _from, uint256 _value) public returns (bool success) {
        require (balanceOf[_from] >= _value);                // Check if the sender has enough
        require (_value <= allowance[_from][msg.sender]);    // Check allowance
        balanceOf[_from] -= _value;                          // Subtract from the sender
        totalSupply -= _value;                               // Updates totalSupply
        emit Burn(_from, _value);
        return true;
    }
}
