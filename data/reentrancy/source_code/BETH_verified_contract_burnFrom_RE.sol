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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the token holder (_from) before state updates. The vulnerability requires multiple transactions to exploit:
 * 
 * **Key Changes Made:**
 * 1. **External Call Before State Changes**: Added `_from.call()` notification before balance/allowance updates
 * 2. **Added Allowance Reduction**: Added `allowance[_from][msg.sender] -= _value` after state changes
 * 3. **Contract Address Check**: Added `_from.code.length > 0` to trigger callback only for contracts
 * 
 * **Multi-Transaction Exploitation Pattern:**
 * 
 * **Transaction 1 (Setup)**: 
 * - Attacker approves a malicious contract with large allowance
 * - Contract implements `onTokenBurn()` callback function
 * 
 * **Transaction 2 (Initial Burn)**:
 * - Legitimate burnFrom call triggers external callback
 * - Callback re-enters burnFrom before state updates
 * - Exploits time window where checks pass but state not yet updated
 * 
 * **Transaction 3+ (Repeated Exploitation)**:
 * - Continued reentrancy calls exploit persistent allowance state
 * - Each call reduces balance but allowance reduction happens after callback
 * - Accumulated burns exceed intended allowance limits
 * 
 * **Why Multi-Transaction Required:**
 * - Allowance state persists between transactions enabling repeated exploitation
 * - Initial setup transaction required to establish malicious callback contract
 * - Multiple burn calls needed to accumulate significant damage
 * - State inconsistency builds up across transaction sequence
 * - Single transaction would be limited by gas constraints and call stack depth
 * 
 * **State Persistence Elements:**
 * - `balanceOf[_from]` - persistent balance state
 * - `allowance[_from][msg.sender]` - persistent approval state
 * - `totalSupply` - global supply state
 * - These enable stateful exploitation across multiple transactions
 */
pragma solidity ^0.4.8;
contract tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData); }

contract BETH {
    /* Public variables of the token */
    string public standard = 'BETH';
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
    function BETH() public {
        balanceOf[msg.sender] =  2100000 * 1000000000000000000;              // Give the creator all initial tokens
        totalSupply =  2100000 * 1000000000000000000;                        // Update total supply
        name = "BETH";                                   // Set the name for display purposes
        symbol = "B.ETH";                               // Set the symbol for display purposes
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
    function approve(address _spender, uint256 _value) public returns (bool success) {
        allowance[msg.sender][_spender] = _value;
        return true;
    }

    /* Approve and then communicate the approved contract in a single tx */
    function approveAndCall(address _spender, uint256 _value, bytes _extraData) public returns (bool success) {
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Notify the token holder about the burn operation before state changes
        if (_from != address(0) && isContract(_from)) {
            // External call to contract before state modifications
            _from.call(abi.encodeWithSignature("onTokenBurn(address,uint256)", msg.sender, _value));
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[_from] -= _value;                          // Subtract from the sender
        totalSupply -= _value;                               // Updates totalSupply
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        allowance[_from][msg.sender] -= _value;              // Reduce allowance after burn
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        emit Burn(_from, _value);
        return true;
    }
    // Helper function to check if address is a contract (for 0.4.x)
    function isContract(address _addr) internal view returns (bool) {
        uint256 length;
        assembly { length := extcodesize(_addr) }
        return (length > 0);
    }
}
