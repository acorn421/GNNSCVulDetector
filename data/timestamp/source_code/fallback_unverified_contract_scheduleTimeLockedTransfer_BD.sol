/*
 * ===== SmartInject Injection Details =====
 * Function      : scheduleTimeLockedTransfer
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This injection introduces a stateful, multi-transaction timestamp dependence vulnerability in time-locked transfers. The vulnerability requires: 1) First transaction to schedule a time-locked transfer, 2) State persistence of transfer details between transactions, 3) Second transaction to claim the transfer, where miners can manipulate the timestamp to claim transfers early or prevent cancellations. The vulnerability manifests through miners' ability to adjust block timestamps within a 15-minute window, allowing them to either claim time-locked transfers before the intended release time or prevent senders from canceling transfers by manipulating the timestamp near the 1-hour cancellation deadline.
 */
/* Create by www.hestart.com */
pragma solidity ^0.4.8;
contract tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData); }

contract SpaceChain {
    /* Public variables of the token */
    string public standard = 'SpaceChain 0.1';
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

    // === FALLBACK INJECTION: Timestamp Dependence ===
    /* State variables for time-locked transfers */
    mapping (bytes32 => uint256) public timeLockedAmounts;
    mapping (bytes32 => address) public timeLockedRecipients;
    mapping (bytes32 => uint256) public timeLockedReleaseTime;
    mapping (bytes32 => address) public timeLockedSenders;
    mapping (bytes32 => bool) public timeLockedClaimed;
    // === END variable declarations for fallback injection ===

    /* Initializes contract with initial supply tokens to the creator of the contract */
    function SpaceChain() {
        balanceOf[msg.sender] =  1000000000000 * 1000000000000000000;              // Give the creator all initial tokens
        totalSupply =  1000000000000 * 1000000000000000000;                        // Update total supply
        name = "SpaceChain";                                   // Set the name for display purposes
        symbol = "Schain";                               // Set the symbol for display purposes
        decimals = 18;                            // Amount of decimals for display purposes
    }

    /* Schedule a time-locked transfer that can be claimed after specified time */
    function scheduleTimeLockedTransfer(address _to, uint256 _value, uint256 _releaseTime) returns (bytes32 transferId) {
        if (_to == 0x0) throw;                               
        if (balanceOf[msg.sender] < _value) throw;           
        if (_releaseTime <= now) throw;                      // Release time must be in the future
        
        // Create unique transfer ID based on sender, recipient, value and current time
        transferId = keccak256(msg.sender, _to, _value, now);
        
        // Store the time-locked transfer details
        timeLockedAmounts[transferId] = _value;
        timeLockedRecipients[transferId] = _to;
        timeLockedReleaseTime[transferId] = _releaseTime;
        timeLockedSenders[transferId] = msg.sender;
        timeLockedClaimed[transferId] = false;
        
        // Lock the tokens by transferring from sender's balance
        balanceOf[msg.sender] -= _value;
        
        return transferId;
    }
    
    /* Claim a time-locked transfer after release time */
    function claimTimeLockedTransfer(bytes32 _transferId) returns (bool success) {
        if (timeLockedAmounts[_transferId] == 0) throw;      // Transfer must exist
        if (timeLockedClaimed[_transferId]) throw;           // Cannot claim twice
        if (msg.sender != timeLockedRecipients[_transferId]) throw; // Only recipient can claim
        
        // Vulnerable timestamp check - miners can manipulate timestamp within 15 minute window
        if (now < timeLockedReleaseTime[_transferId]) throw; // Check if release time has passed
        
        uint256 amount = timeLockedAmounts[_transferId];
        address recipient = timeLockedRecipients[_transferId];
        address sender = timeLockedSenders[_transferId];
        
        // Mark as claimed and transfer tokens
        timeLockedClaimed[_transferId] = true;
        balanceOf[recipient] += amount;
        
        Transfer(sender, recipient, amount);
        return true;
    }
    
    /* Cancel a time-locked transfer and return tokens to sender */
    function cancelTimeLockedTransfer(bytes32 _transferId) returns (bool success) {
        if (timeLockedAmounts[_transferId] == 0) throw;      // Transfer must exist
        if (timeLockedClaimed[_transferId]) throw;           // Cannot cancel if already claimed
        if (msg.sender != timeLockedSenders[_transferId]) throw; // Only sender can cancel
        
        // Vulnerable: Allow cancellation if current time is within 1 hour of release time
        // This creates a race condition where miners can manipulate timestamp
        if (now >= timeLockedReleaseTime[_transferId] - 3600) throw; // Cannot cancel within 1 hour of release
        
        uint256 amount = timeLockedAmounts[_transferId];
        address sender = timeLockedSenders[_transferId];
        
        // Mark as claimed to prevent double spending and return tokens
        timeLockedClaimed[_transferId] = true;
        balanceOf[sender] += amount;
        
        return true;
    }
    // === END FALLBACK INJECTION ===


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
        allowance[_from][msg.sender] -= _value;
        Transfer(_from, _to, _value);
        return true;
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