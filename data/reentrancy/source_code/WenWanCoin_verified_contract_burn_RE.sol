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
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by implementing a staged burn mechanism that requires multiple function calls to complete. The vulnerability is created through:
 * 
 * 1. **State Persistence**: Added persistent state variables (pendingBurns, burnInProgress) that track burn operations across multiple transactions
 * 2. **Multi-Transaction Requirement**: The burn process now requires two separate transactions - one to initiate and one to complete the burn
 * 3. **External Call Placement**: Added external calls to user-controlled contracts before critical state updates, creating reentrancy windows
 * 4. **Checks-Effects-Interactions Violation**: The second transaction performs external calls before updating balances and clearing pending state
 * 
 * **Multi-Transaction Exploitation Pattern:**
 * - Transaction 1: Attacker calls burn(), setting burnInProgress[attacker] = true and pendingBurns[attacker] = amount
 * - Transaction 2: Attacker calls burn() again, triggering the completion path with external call before state updates
 * - During the external call in Transaction 2, the attacker can re-enter and call burn() again, exploiting the fact that pendingBurns still shows the original amount and balanceOf hasn't been updated yet
 * 
 * **Why Multiple Transactions Are Required:**
 * - The vulnerability cannot be exploited in a single transaction because the first call sets up the pending state but doesn't complete the burn
 * - The second call is needed to trigger the vulnerable completion path with the external call
 * - The staged nature means the vulnerability window only opens during the second transaction's external call
 * - State accumulation from the first transaction is essential for the second transaction's exploitation
 */
pragma solidity ^0.4.8;
contract tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData); }

contract WenWanCoin {
    /* Public variables of the token */
    string public standard = 'WenWanCoin 0.1';
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
    constructor() public {
        balanceOf[msg.sender] = 50000000 * 1000000000000000000;              // Give the creator all initial tokens
        totalSupply = 50000000 * 1000000000000000000;                        // Update total supply
        name = "WenWanCoin";                                   // Set the name for display purposes
        symbol = "WWC";                               // Set the symbol for display purposes
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
        allowance[_from][msg.sender] -= _value;
        emit Transfer(_from, _to, _value);
        return true;
    }

        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    // Burn tracking state variables (would need to be added to contract)
    mapping(address => uint256) public pendingBurns;
    mapping(address => bool) public burnInProgress;
    
    function burn(uint256 _value) public returns (bool success) {
        if (balanceOf[msg.sender] < _value) revert();            // Check if the sender has enough
        
        // Stage 1: If no burn in progress, initiate staged burn
        if (!burnInProgress[msg.sender]) {
            burnInProgress[msg.sender] = true;
            pendingBurns[msg.sender] = _value;
            
            // External call to burn notification contract - vulnerable to reentrancy
            if (extcodesize(msg.sender) > 0) {
                bool innerSuccess1 = msg.sender.call(bytes4(keccak256("onBurnInitiated(uint256)")), _value);
                // Continue regardless of call success
            }
            
            return true;
        }
        
        // Stage 2: Complete the burn if already in progress
        if (burnInProgress[msg.sender] && pendingBurns[msg.sender] > 0) {
            uint256 pendingAmount = pendingBurns[msg.sender];
            
            // VULNERABLE: External call before state updates
            if (extcodesize(msg.sender) > 0) {
                bool innerSuccess2 = msg.sender.call(bytes4(keccak256("onBurnCompleting(uint256)")), pendingAmount);
                // Continue regardless of call success
            }
            
            // State updates happen after external call - vulnerable window
            balanceOf[msg.sender] -= pendingAmount;              // Subtract from the sender
            totalSupply -= pendingAmount;                        // Updates totalSupply
            pendingBurns[msg.sender] = 0;                       // Clear pending
            burnInProgress[msg.sender] = false;                 // Reset progress flag
            
            emit Burn(msg.sender, pendingAmount);
            return true;
        }
        
        return false;
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    }

    function burnFrom(address _from, uint256 _value) public returns (bool success) {
        if (balanceOf[_from] < _value) revert();                // Check if the sender has enough
        if (_value > allowance[_from][msg.sender]) revert();    // Check allowance
        balanceOf[_from] -= _value;                          // Subtract from the sender
        totalSupply -= _value;                               // Updates totalSupply
        emit Burn(_from, _value);
        return true;
    }

    // Helper for getting code size of an address (since address.code is not available in 0.4.x)
    function extcodesize(address _addr) internal view returns (uint256 size) {
        assembly { size := extcodesize(_addr) }
    }
}
