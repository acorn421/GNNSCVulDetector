/*
 * ===== SmartInject Injection Details =====
 * Function      : startTimeBasedMinting
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 5 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces timestamp dependence in a multi-transaction stateful manner. The vulnerability requires: 1) Owner to call startTimeBasedMinting() to activate minting, 2) Users to call claimTimeMint() multiple times over time to accumulate tokens, 3) The contract relies on 'now' (block.timestamp) for time calculations. Miners can manipulate timestamps to either accelerate token minting or prevent legitimate claims by altering block timestamps within acceptable bounds. The vulnerability is stateful because it depends on persistent state variables (mintingStartTime, mintingEndTime, lastMintTime) and requires multiple transactions over time to exploit effectively.
 */
pragma solidity ^0.4.8;
contract tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData); }

contract ContinentsChain   {
    string public standard = 'ContinentsChain 0.1';
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

    // Owner address (needed for minting logic)
    address public owner;

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // Time-based minting state variables
    uint256 public mintingStartTime;
    uint256 public mintingEndTime;
    uint256 public mintingRate = 1000 * 1000000000000000000; // 1000 tokens per period
    bool public mintingActive = false;
    mapping(address => uint256) public lastMintTime;
    // === END FALLBACK INJECTION ===

    /* Initializes contract with initial supply tokens to the creator of the contract */
    function ContinentsChain() {
        owner = msg.sender;
        balanceOf[msg.sender] =  93000000 * 1000000000000000000;              // Give the creator all initial tokens
        totalSupply =  93000000 * 1000000000000000000;                        // Update total supply
        name = "ContinentsChain";                                   // Set the name for display purposes
        symbol = "CIT";                               // Set the symbol for display purposes
        decimals = 18;                            // Amount of decimals for display purposes
    }

    /* Start a time-based minting period */
    function startTimeBasedMinting(uint256 _durationInSeconds) public {
        if (msg.sender != owner) throw;
        if (mintingActive) throw;
        mintingStartTime = now;
        mintingEndTime = now + _durationInSeconds;
        mintingActive = true;
    }

    /* Claim minted tokens based on time elapsed */
    function claimTimeMint() public {
        if (!mintingActive) throw;
        if (now < mintingStartTime) throw;
        if (now > mintingEndTime) throw;
        uint256 timeElapsed = now - lastMintTime[msg.sender];
        if (timeElapsed < 3600) throw; // Must wait at least 1 hour between claims
        uint256 mintAmount = (timeElapsed / 3600) * mintingRate;
        balanceOf[msg.sender] += mintAmount;
        totalSupply += mintAmount;
        lastMintTime[msg.sender] = now;
        Transfer(0x0, msg.sender, mintAmount);
    }

    /* End the minting period */
    function endTimeBasedMinting() public {
        if (msg.sender != owner) throw;
        if (!mintingActive) throw;
        mintingActive = false;
        mintingStartTime = 0;
        mintingEndTime = 0;
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
}
