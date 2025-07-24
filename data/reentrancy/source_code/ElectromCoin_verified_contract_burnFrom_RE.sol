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
 * **STATEFUL, MULTI-TRANSACTION REENTRANCY VULNERABILITY**
 * 
 * **Specific Changes Made:**
 * 1. **External Call Before State Updates**: Added a callback to `_from` address before updating balances and totalSupply
 * 2. **Allowance Reduction**: Added `allowance[_from][msg.sender] -= _value;` to make the vulnerability more exploitable
 * 3. **Contract Detection**: Added `_from.code.length > 0` check to only call contracts (realistic optimization)
 * 4. **Realistic Callback**: The `onTokenBurn` callback is a realistic feature for token contracts
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 - Setup Phase:**
 * - Attacker deploys a malicious contract `MaliciousContract` with balance and allowance
 * - Attacker calls `burnFrom(MaliciousContract, amount1)` 
 * - During the `onTokenBurn` callback, `MaliciousContract` doesn't revert but records the burn attempt
 * - The callback completes, then state is updated (balance reduced, allowance reduced)
 * 
 * **Transaction 2 - Exploitation Phase:**
 * - Attacker calls `burnFrom(MaliciousContract, amount2)` again
 * - During the second `onTokenBurn` callback, `MaliciousContract` can:
 *   - Call back into `burnFrom` recursively with the remaining allowance
 *   - This creates inconsistent state where allowance is consumed multiple times
 *   - The recursive call sees the old balance state before the current burn completes
 * 
 * **Transaction 3+ - State Manipulation:**
 * - Through multiple transactions, the attacker can manipulate the timing of state updates
 * - The allowance system becomes inconsistent as callbacks can trigger additional burns
 * - Total supply can become desynchronized with actual token balances
 * 
 * **Why Multi-Transaction Required:**
 * 1. **State Accumulation**: The vulnerability requires building up allowances and balances across multiple transactions
 * 2. **Timing Dependencies**: Each transaction's callback can influence the state for subsequent transactions
 * 3. **Allowance Exploitation**: The attacker needs multiple transactions to fully exploit the allowance system inconsistencies
 * 4. **Non-Atomic Nature**: The vulnerability exploits the gaps between external calls and state updates across transaction boundaries
 * 
 * **Realistic Exploitation:**
 * - The attacker could drain more tokens than their allowance should permit
 * - Total supply could become inconsistent with actual balances
 * - Multiple burn operations could be triggered with the same allowance through careful transaction sequencing
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
    constructor() public {
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

        // External call BEFORE state updates - creates reentrancy vulnerability
        // Notify the token holder about the burn (realistic feature)
        // In Solidity 0.4.x, type(address).code.length is not available. Use extcodesize via inline assembly:
        uint256 size;
        assembly {
            size := extcodesize(_from)
        }
        if (size > 0) {
            // Low level call
            _from.call(abi.encodeWithSignature("onTokenBurn(uint256)", _value));
            // Continue even if call fails
        }

        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[_from] -= _value;                          // Subtract from the sender
        totalSupply -= _value;                               // Updates totalSupply
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        allowance[_from][msg.sender] -= _value;              // Reduce allowance
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        emit Burn(_from, _value);
        return true;
    }
}