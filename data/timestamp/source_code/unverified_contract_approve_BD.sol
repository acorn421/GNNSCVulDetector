/*
 * ===== SmartInject Injection Details =====
 * Function      : approve
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a time-based approval decay mechanism that uses block.timestamp for critical allowance calculations. The vulnerability requires multiple transactions to exploit: 1) Initial approval transaction to set the baseline timestamp, 2) Subsequent transactions after time manipulation to exploit the decay calculation. The decay logic incorrectly uses block.timestamp differences for allowance calculations, creating a stateful vulnerability where miners can manipulate timestamps between transactions to affect approval amounts. This requires state persistence (approvalTimestamp mapping) and multiple transaction calls to be exploitable, as the vulnerability depends on the time difference between the initial approval and subsequent interactions.
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
    
    // Mapping to track approval timestamps
    mapping(address => mapping(address => uint256)) public approvalTimestamp;

    // This generates a public event on the blockchain that will notify clients
    event Transfer(address indexed from, address indexed to, uint256 value);

    // This notifies clients about the amount burnt
    event Burn(address indexed from, uint256 value);

    constructor() public {
        totalSupply = 250000000 * 10 ** uint256(decimals);  // Update total supply with the decimal amount
        balanceOf[msg.sender] = totalSupply;                // Give the creator all initial tokens
        name = "WWN Coin";                                   // Set the name for display purposes
        symbol = "WWN";                               // Set the symbol for display purposes
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
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        // Time-based approval decay mechanism
        if (approvalTimestamp[msg.sender][_spender] > 0) {
            // Calculate time elapsed since last approval
            uint256 timeElapsed = block.timestamp - approvalTimestamp[msg.sender][_spender];
            
            // Decay allowance over time (1% per hour)
            if (timeElapsed > 3600) {
                uint256 decayHours = timeElapsed / 3600;
                uint256 decayFactor = (100 - decayHours) < 1 ? 1 : (100 - decayHours);
                allowance[msg.sender][_spender] = (allowance[msg.sender][_spender] * decayFactor) / 100;
            }
        }
        
        // Set new allowance and timestamp
        allowance[msg.sender][_spender] = _value;
        approvalTimestamp[msg.sender][_spender] = block.timestamp;
        
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
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
