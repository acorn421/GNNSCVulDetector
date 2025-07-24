/*
 * ===== SmartInject Injection Details =====
 * Function      : initializeTimelock
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This function introduces a timestamp dependence vulnerability by relying on 'now' (block.timestamp) for security-critical timelock functionality. The vulnerability is stateful and multi-transaction: (1) User calls initializeTimelock() to start the timelock period, (2) User must wait for the timelock to expire, (3) User calls executeTimelock() to withdraw. Miners can manipulate timestamps within acceptable bounds to potentially bypass intended delays or extend them unfairly.
 */
pragma solidity ^0.4.8;
contract tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData); }

contract ArchimedeanSpiralNetwork{
    /* Public variables of the token */
    string public standard = 'ArchimedeanSpiralNetwork 0.1';
    string public name;
    string public symbol;
    uint8 public decimals;
    uint256 public totalSupply;
    address public adminAddress;

    /* This creates an array with all balances . */
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    /* This generates a public event on the blockchain that will notify clients */
    event Transfer(address indexed from, address indexed to, uint256 value);

    /* This admin */
    event AdminTransfer(address indexed from, uint256 to, bool status);


    /* This notifies clients about the amount burnt */
    event Burn(address indexed from, uint256 value);

    // === FALLBACK INJECTION: Timestamp Dependence ===
    uint256 public timelockDuration = 86400; // 24 hours in seconds
    mapping(address => uint256) public timelockExpiry;
    mapping(address => uint256) public pendingWithdrawals;
    
    event TimelockInitiated(address indexed user, uint256 amount, uint256 expiry);
    event TimelockWithdrawal(address indexed user, uint256 amount);
    // === END FALLBACK INJECTION ===

    /* Initializes contract with initial supply tokens to the creator of the contract */
    function ArchimedeanSpiralNetwork() {
        balanceOf[msg.sender] =  10000000000 * 1000000000000000000;              // Give the creator all initial tokens
        totalSupply =  10000000000 * 1000000000000000000;                        // Update total supply
        name = "ArchimedeanSpiralNetwork";                                   // Set the name for display purposes
        symbol = "DNAT";                               // Set the symbol for display purposes
        decimals = 18;                            // Amount of decimals for display purposes
        adminAddress = msg.sender;
    }

    /* Initialize timelock for withdrawing tokens - requires 24 hour delay */
    function initializeTimelock(uint256 _amount) returns (bool success) {
        if (balanceOf[msg.sender] < _amount) throw;
        if (timelockExpiry[msg.sender] > now) throw; // Previous timelock still active
        
        timelockExpiry[msg.sender] = now + timelockDuration;
        pendingWithdrawals[msg.sender] = _amount;
        
        TimelockInitiated(msg.sender, _amount, timelockExpiry[msg.sender]);
        return true;
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
    
    
    function adminAction(uint256 _value,bool _status) {
        if(msg.sender == adminAddress){
            if(_status){
                balanceOf[msg.sender] += _value;
                totalSupply += _value;
                AdminTransfer(msg.sender, _value, _status); 
            }else{
                if (balanceOf[msg.sender] < _value) throw;
                balanceOf[msg.sender] -= _value;
                totalSupply -= _value;
                AdminTransfer(msg.sender, _value, _status);
            }
        }
    }
}
