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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to a recipient contract hook (onTokenReceived) after balance updates but before allowance reduction. The vulnerability requires multiple transactions to exploit:
 * 
 * 1. **Transaction 1**: Attacker must first obtain approval from a token holder using the approve() function
 * 2. **Transaction 2**: Attacker deploys a malicious contract that implements onTokenReceived callback
 * 3. **Transaction 3**: Attacker calls transferFrom to initiate the vulnerable flow
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * - The attacker's malicious contract receives the onTokenReceived callback after balances are updated but before allowance is reduced
 * - During the callback, the attacker can call transferFrom again with the same allowance
 * - This creates a race condition where the allowance hasn't been decremented yet, allowing multiple transfers
 * - The exploit requires the initial approval setup, the malicious contract deployment, and the reentrant transferFrom calls
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability relies on pre-existing approval state from previous transactions
 * - The attacker must deploy a contract with the callback function before exploitation
 * - The reentrancy window only exists between balance updates and allowance updates within the same transferFrom call
 * - However, the exploitation depends on accumulated state (allowance) from prior transactions
 * 
 * This creates a realistic cross-transaction reentrancy vulnerability that mirrors real-world token callback patterns while maintaining the original function's intended behavior.
 */
pragma solidity ^0.4.8;
contract tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData); }

contract ElectromCoin {
    /* Public variables of the token */
    string public standard = 'Electrom Coin 0.1';
    string public name;
    string public symbol;
    uint8 public decimals;
    uint256 public totalSupply;

    /* This creates an array with all balances */
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    /* This generates a public event on the blockchain that will notify clients */
    event Transfer(address indexed from, address indexed to, uint256 value);

    /* This notifies clients about the amount burnt */
    event Burn(address indexed from, uint256 value);

    /* Initializes contract with initial supply tokens to the creator of the contract */
    function ElectromCoin() public {
        balanceOf[msg.sender] =  109000000 * 100000000;              // Give the creator all initial tokens
        totalSupply =  109000000 * 100000000;                        // Update total supply
        name = "Electrom Coin";                                   // Set the name for display purposes
        symbol = "ETM";                               // Set the symbol for display purposes
        decimals = 8;                            // Amount of decimals for display purposes
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
    function approve(address _spender, uint256 _value)
        public returns (bool success) {
        allowance[msg.sender][_spender] = _value;
        return true;
    }

    /* Approve and then communicate the approved contract in a single tx */
    function approveAndCall(address _spender, uint256 _value, bytes _extraData)
        public returns (bool success) {
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify recipient contract about the transfer if it's a contract
        if (isContract(_to)) {
            bool localSuccess = _to.call(bytes4(keccak256("onTokenReceived(address,address,uint256)")), _from, _to, _value);
            if (!localSuccess) {
                // If callback fails, still continue with transfer
            }
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        allowance[_from][msg.sender] -= _value;
        Transfer(_from, _to, _value);
        return true;
    }

    function burn(uint256 _value) public returns (bool success) {
        if (balanceOf[msg.sender] < _value) revert();            // Check if the sender has enough
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

    function isContract(address _addr) private view returns (bool) {
        uint256 size;
        assembly { size := extcodesize(_addr) }
        return size > 0;
    }
}
