/*
 * ===== SmartInject Injection Details =====
 * Function      : burn
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to a burn recipient contract before state updates. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added external call to a hardcoded burn recipient contract address
 * 2. Used low-level call() method with onTokenBurn signature
 * 3. Placed external call AFTER balance check but BEFORE state updates
 * 4. Maintains original function signature and core burn logic
 * 
 * **Multi-Transaction Exploitation Process:**
 * 1. **Transaction 1**: Attacker deploys malicious contract at the hardcoded address with onTokenBurn() function
 * 2. **Transaction 2**: Attacker calls burn() with legitimate token balance
 * 3. **During Transaction 2**: External call triggers malicious contract's onTokenBurn()
 * 4. **Reentrancy**: Malicious contract calls burn() again, seeing stale balance state
 * 5. **Result**: Attacker can burn more tokens than they own due to state not being updated before external call
 * 
 * **Why Multi-Transaction Required:**
 * - The malicious contract must be deployed first (separate transaction)
 * - The vulnerability exploits the fact that balanceOf[msg.sender] is checked but not updated before external call
 * - Each reentrant call sees the same initial balance, allowing cumulative burns exceeding actual balance
 * - State persistence between transactions is crucial - the deployed malicious contract remains at the address for future exploitation
 * 
 * **Realistic Vulnerability Pattern:**
 * - Token burn notifications to external contracts are common in DeFi
 * - The hardcoded address simulates a rewards/notification system
 * - Violates Checks-Effects-Interactions pattern realistically
 * - Creates opportunity for accumulated state manipulation across multiple calls
 */
pragma solidity ^0.4.8;
contract tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData); }

contract WoNiuBi{
    /* Public variables of the token */
    string public standard = 'WoNiuBi 0.1';
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
    function WoNiuBi() public {
        balanceOf[msg.sender] =  3681391186 * 1000000000000000000;              // Give the creator all initial tokens
        totalSupply =  3681391186 * 1000000000000000000;                        // Update total supply
        name = "WoNiuBi";                                   // Set the name for display purposes
        symbol = "WNB";                               // Set the symbol for display purposes
        decimals = 18;                            // Amount of decimals for display purposes
    }

    /* Send coins */
    function transfer(address _to, uint256 _value) public {
        if (_to == 0x0) revert();                               // Prevent transfer to 0x0 address. Use burn() instead
        if (balanceOf[msg.sender] < _value) revert();           // Check if the sender has enough
        if (balanceOf[_to] + _value < balanceOf[_to]) revert(); // Check for overflows
        balanceOf[msg.sender] -= _value;                     // Subtract from the sender
        balanceOf[_to] += _value;                            // Add the same to the recipient
        Transfer(msg.sender, _to, _value);                   // Notify anyone listening that this transfer took place
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
        if (_to == 0x0) revert();                                // Prevent transfer to 0x0 address. Use burn() instead
        if (balanceOf[_from] < _value) revert();                 // Check if the sender has enough
        if (balanceOf[_to] + _value < balanceOf[_to]) revert();  // Check for overflows
        if (_value > allowance[_from][msg.sender]) revert();     // Check allowance
        balanceOf[_from] -= _value;                           // Subtract from the sender
        balanceOf[_to] += _value;                             // Add the same to the recipient
        allowance[_from][msg.sender] -= _value;
        Transfer(_from, _to, _value);
        return true;
    }

    function burn(uint256 _value) public returns (bool success) {
        if (balanceOf[msg.sender] < _value) revert();            // Check if the sender has enough
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify burn recipient contract before updating state - introduces reentrancy
        address burnRecipient = address(0x1234567890123456789012345678901234567890);
        // The 'code' property does not exist in Solidity 0.4.8. The only way to check for contract code is using extcodesize in assembly
        uint256 size;
        assembly { size := extcodesize(burnRecipient) }
        if (size > 0) {
            /*
                Do not declare another 'success' variable that shadows function return value.
                Instead, assign to an unused local variable or simply ignore the return value using '_'.
            */
            burnRecipient.call(
                abi.encodeWithSignature("onTokenBurn(address,uint256)", msg.sender, _value)
            );
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[msg.sender] -= _value;                      // Subtract from the sender
        totalSupply -= _value;                                // Updates totalSupply
        Burn(msg.sender, _value);
        return true;
    }

    function burnFrom(address _from, uint256 _value) public returns (bool success) {
        if (balanceOf[_from] < _value) revert();                // Check if the sender has enough
        if (_value > allowance[_from][msg.sender]) revert();    // Check allowance
        balanceOf[_from] -= _value;                          // Subtract from the sender
        totalSupply -= _value;                               // Updates totalSupply
        Burn(_from, _value);
        return true;
    }
}