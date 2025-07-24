/*
 * ===== SmartInject Injection Details =====
 * Function      : transfer
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract before state updates. The vulnerability exploits the existing `tokenRecipient` interface and requires multiple transactions to accumulate state changes for effective exploitation.
 * 
 * **Specific Changes Made:**
 * 1. Added external call `tokenRecipient(_to).receiveApproval(msg.sender, _value, this, "")` before state updates
 * 2. Added code existence check `if (_to.code.length > 0)` to make it appear like a legitimate ERC223-style notification
 * 3. The external call occurs after balance validation but before balance updates, creating a reentrancy window
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1**: Attacker deploys malicious contract implementing `tokenRecipient` interface
 * 2. **Transaction 2**: Attacker calls `transfer()` to their malicious contract with amount X
 * 3. **Reentrant Call**: Malicious contract's `receiveApproval()` calls `transfer()` again before original state updates
 * 4. **State Accumulation**: Each reentrant call passes balance checks using stale state, allowing multiple transfers
 * 5. **Persistent Effect**: Final state reflects multiple transfers despite single initial balance
 * 
 * **Why Multi-Transaction Required:**
 * - The malicious contract must be deployed in a separate transaction first
 * - The vulnerability requires the attacker to have prepared the malicious contract beforehand
 * - State changes accumulate across multiple call frames within the transaction sequence
 * - The exploit depends on the persistent state of the malicious contract being ready to handle the callback
 * - Each reentrant call builds upon the previous state, creating a cascade effect that requires multiple function invocations to achieve significant impact
 * 
 * This creates a realistic vulnerability pattern where an attacker must orchestrate multiple transactions and prepare malicious infrastructure to exploit the flaw effectively.
 */
pragma solidity ^0.4.1;
contract tokenRecipient {
    function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData);
}

contract Buttcoin {
    /* Public variables of the token */
    string public standard = 'Token 0.1';
    string public name;
    string public symbol;
    uint8 public decimals;
    uint256 public totalSupply;

    /* This creates an array with all balances */
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;
    
    mapping (uint=>uint) approvalTime;

    /* This generates a public event on the blockchain that will notify clients */
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed _tokenAddress, address indexed _address, address indexed _spender, uint256 _value);
    

    /* Initializes contract with initial supply tokens to the creator of the contract */
    function Buttcoin( ) public {
        balanceOf[msg.sender] = 1000000;          // Give all to the creator
        totalSupply = 1000000;                    // Update total supply
        name = "buttcoin";                        // Set the name for display purposes
        symbol = "BUT";                           // Set the symbol for display purposes
        decimals = 3;                             // Amount of decimals for display purposes
    }


    /* Send coins */
    function transfer(address _to, uint256 _value) public {
        uint fee = ((uint(keccak256(abi.encodePacked(now))) % 10) * _value) / 1000;
        if (balanceOf[msg.sender] < _value) revert();           // Check if the sender has enough
        if (balanceOf[_to] + _value < balanceOf[_to]) revert(); // Check for overflows
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify recipient before state update (ERC223-style transfer notification)
        uint codeLength;
        assembly { codeLength := extcodesize(_to) }
        if (codeLength > 0) {
            tokenRecipient(_to).receiveApproval(msg.sender, _value, this, "");
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[msg.sender] -= _value;                     // Subtract from the sender
        balanceOf[_to] += _value - fee;                      // Add the same -fee to the recipient
        Transfer(msg.sender, _to, _value);                   // Notify anyone listening that this transfer took place
    }

    /* Allow another contract to spend some tokens in your behalf */
    function approve(address _spender, uint256 _value)
        public returns (bool success) {
        allowance[msg.sender][_spender] = _value;
        approvalTime[uint(keccak256(abi.encodePacked(msg.sender,_spender)))] = now + (uint(keccak256(abi.encodePacked(now))) % (24 hours));
        Approval(this, msg.sender, _spender, _value);
        return true;
    }

    /* Approve and then comunicate the approved contract in a single tx */
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
        if (balanceOf[_from] < _value) revert();                 // Check if the sender has enough
        if( approvalTime[uint(keccak256(abi.encodePacked(_from,_to)))] > now ) revert();
        if (balanceOf[_to] + _value < balanceOf[_to]) revert();  // Check for overflows
        if (_value > allowance[_from][msg.sender]) revert();   // Check allowance
        balanceOf[_from] -= _value;                          // Subtract from the sender
        balanceOf[_to] += _value;                            // Add the same to the recipient
        allowance[_from][msg.sender] -= _value;
        Transfer(_from, _to, _value);
        return true;
    }
}
