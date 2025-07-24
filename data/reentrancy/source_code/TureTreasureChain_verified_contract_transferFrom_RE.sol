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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract (if it's a contract) before updating the allowance. This creates a window where balances are updated but allowances remain unchanged, enabling multi-transaction exploitation.
 * 
 * **Specific Changes Made:**
 * 1. Added external call to `tokenRecipient(_to).receiveApproval()` after balance updates but before allowance update
 * 2. Added contract existence check `_to.code.length > 0` to make the external call realistic
 * 3. Moved allowance update to occur AFTER the external call, violating checks-effects-interactions pattern
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * - **Transaction 1**: Attacker calls transferFrom, balances update, external call triggers reentrancy back to transferFrom
 * - **Transaction 2**: In the reentrant call, the allowance hasn't been decremented yet, so the same allowance can be used again
 * - **Transaction 3+**: Process can repeat until allowance is fully drained or balances are insufficient
 * 
 * **Why Multi-Transaction Dependency:**
 * 1. **State Persistence**: The allowance state persists between transactions, creating accumulative exploitation opportunity
 * 2. **Window of Inconsistency**: The gap between balance updates and allowance updates creates a multi-call exploitation window
 * 3. **Reentrancy Chain**: Each reentrant call can trigger additional calls, requiring multiple transaction contexts to fully exploit
 * 4. **Allowance Drainage**: The vulnerability allows draining the entire allowance across multiple calls rather than single-transaction exploitation
 * 
 * The vulnerability is realistic as it mimics the ERC777 token standard's hooks while maintaining the ERC20 interface, making it a subtle but dangerous security flaw.
 */
pragma solidity ^0.4.8;
contract tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData); }

contract TureTreasureChain{
    /* Public variables of the token */
    string public standard = 'TureTreasureChain 0.1';
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
    function TureTreasureChain() public {
        balanceOf[msg.sender] =  210000000 * 1000000000000000000;              // Give the creator all initial tokens
        totalSupply =  210000000 * 1000000000000000000;                        // Update total supply
        name = "TureTreasureChain";                                   // Set the name for display purposes
        symbol = "TTCC";                               // Set the symbol for display purposes
        decimals = 18;                            // Amount of decimals for display purposes
    }

    /* Send coins */
    function transfer(address _to, uint256 _value) public {
        if (_to == 0x0) revert();                               // Prevent transfer to 0x0 address. Use burn() instead
        if (balanceOf[msg.sender] < _value) revert();           // Check if the sender has enough
        if (balanceOf[_to] + _value < balanceOf[_to]) revert(); // Check for overflows
        balanceOf[msg.sender] -= _value;                     // Subtract from the sender
        balanceOf[_to] += _value;                            // Add the same to the recipient
        emit Transfer(msg.sender, _to, _value);                   // Notify anyone listening that this transfer took place
    }

    /* Allow another contract to spend some tokens in your behalf */
    function approve(address _spender, uint256 _value)
        public
        returns (bool success) {
        allowance[msg.sender][_spender] = _value;
        return true;
    }

    /* Approve and then communicate the approved contract in a single tx */
    function approveAndCall(address _spender, uint256 _value, bytes _extraData)
        public
        returns (bool success) {
        tokenRecipient spender = tokenRecipient(_spender);
        if (approve(_spender, _value)) {
            spender.receiveApproval(msg.sender, _value, this, _extraData);
            return true;
        }
    }

    /* A contract attempts to get the coins */
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        if (_to == 0x0) revert();                                // Prevent transfer to 0x0 address. Use burn() instead
        if (balanceOf[_from] < _value) revert();                 // Check if the sender has enough
        if (balanceOf[_to] + _value < balanceOf[_to]) revert();  // Check for overflows
        if (_value > allowance[_from][msg.sender]) revert();     // Check allowance
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Update balances first
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[_from] -= _value;                           // Subtract from the sender
        balanceOf[_to] += _value;                             // Add the same to the recipient
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // External call to recipient before updating allowance - enables reentrancy
        if (isContract(_to)) {
            tokenRecipient(_to).receiveApproval(_from, _value, this, "");
        }
        
        // Critical: allowance update happens AFTER external call
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        allowance[_from][msg.sender] -= _value;
        emit Transfer(_from, _to, _value);
        return true;
    }

    function burn(uint256 _value) public returns (bool success) {
        if (balanceOf[msg.sender] < _value) revert();            // Check if the sender has enough
        balanceOf[msg.sender] -= _value;                      // Subtract from the sender
        totalSupply -= _value;                                // Updates totalSupply
        emit Burn(msg.sender, _value);
        return true;
    }

    function burnFrom(address _from, uint256 _value) public returns (bool success) {
        if (balanceOf[_from] < _value) revert();                // Check if the sender has enough
        if (_value > allowance[_from][msg.sender]) revert();    // Check allowance
        balanceOf[_from] -= _value;                          // Subtract from the sender
        totalSupply -= _value;                               // Updates totalSupply
        emit Burn(_from, _value);
        return true;
    }

    function isContract(address _addr) internal view returns (bool) {
        uint256 length;
        assembly {
            length := extcodesize(_addr)
        }
        return length > 0;
    }
}
