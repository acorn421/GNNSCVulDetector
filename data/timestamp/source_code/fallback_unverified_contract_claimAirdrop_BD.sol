/*
 * ===== SmartInject Injection Details =====
 * Function      : claimAirdrop
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
 * This introduces a multi-transaction timestamp dependence vulnerability. The exploit requires: 1) First transaction to call initializeAirdrop() with a specific duration, 2) Wait for the airdrop window to be active, 3) Multiple transactions to claim airdrops where miners can manipulate timestamps to extend the claiming window or bypass time restrictions. The vulnerability is stateful because it depends on the airdropStartTime, airdropEndTime, and airdropClaimed mappings that persist between transactions.
 */
pragma solidity ^0.4.18;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) public; }

contract WWNCoin {
    // Public variables of the token
    string public name;
    string public symbol;
    uint8 public decimals = 18;
    // 18 decimals is the strongly suggested default, avoid changing it
    uint256 public totalSupply;

    // This creates an array with all balances
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    // State variables for airdrop functionality
    mapping (address => uint256) public airdropClaimed;
    uint256 public airdropStartTime;
    uint256 public airdropEndTime;
    uint256 public airdropAmount = 1000 * 10 ** uint256(decimals);
    bool public airdropInitialized = false;

    // This generates a public event on the blockchain that will notify clients
    event Transfer(address indexed from, address indexed to, uint256 value);

    // This notifies clients about the amount burnt
    event Burn(address indexed from, uint256 value);

    function WWNCoin () public {
        totalSupply = 250000000 * 10 ** uint256(decimals);  // Update total supply with the decimal amount
        balanceOf[msg.sender] = totalSupply;                // Give the creator all initial tokens
        name = "WWN Coin";                                   // Set the name for display purposes
        symbol = "WWN";                               // Set the symbol for display purposes
    }

    // Initialize airdrop with time window
    function initializeAirdrop(uint256 _durationInSeconds) public {
        require(!airdropInitialized, "Airdrop already initialized");
        airdropStartTime = now;
        airdropEndTime = now + _durationInSeconds;
        airdropInitialized = true;
    }
    
    // Claim airdrop tokens (vulnerable to timestamp manipulation)
    function claimAirdrop() public {
        require(airdropInitialized, "Airdrop not initialized");
        require(now >= airdropStartTime, "Airdrop not started yet");
        require(now <= airdropEndTime, "Airdrop has ended");
        require(airdropClaimed[msg.sender] == 0, "Already claimed");
        require(balanceOf[this] >= airdropAmount, "Insufficient contract balance");
        
        airdropClaimed[msg.sender] = airdropAmount;
        balanceOf[this] -= airdropAmount;
        balanceOf[msg.sender] += airdropAmount;
        Transfer(this, msg.sender, airdropAmount);
    }

    /**
     * Internal transfer, only can be called by this contract
     */
    function _transfer(address _from, address _to, uint _value) internal {
        // Prevent transfer to 0x0 address. Use burn() instead
        require(_to != 0x0);
        // Check if the sender has enough
        require(balanceOf[_from] >= _value);
        // Check for overflows
        require(balanceOf[_to] + _value > balanceOf[_to]);
        // Save this for an assertion in the future
        uint previousBalances = balanceOf[_from] + balanceOf[_to];
        // Subtract from the sender
        balanceOf[_from] -= _value;
        // Add the same to the recipient
        balanceOf[_to] += _value;
        Transfer(_from, _to, _value);
        // Asserts are used to use static analysis to find bugs in your code. They should never fail
        assert(balanceOf[_from] + balanceOf[_to] == previousBalances);
    }

    function transfer(address _to, uint256 _value) public {
        _transfer(msg.sender, _to, _value);
    }

    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(_value <= allowance[_from][msg.sender]);     // Check allowance
        allowance[_from][msg.sender] -= _value;
        _transfer(_from, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value) public
        returns (bool success) {
        allowance[msg.sender][_spender] = _value;
        return true;
    }

    function approveAndCall(address _spender, uint256 _value, bytes _extraData)
        public
        returns (bool success) {
        tokenRecipient spender = tokenRecipient(_spender);
        if (approve(_spender, _value)) {
            spender.receiveApproval(msg.sender, _value, this, _extraData);
            return true;
        }
    }
}
