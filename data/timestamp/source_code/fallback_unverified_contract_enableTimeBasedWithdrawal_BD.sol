/*
 * ===== SmartInject Injection Details =====
 * Function      : enableTimeBasedWithdrawal
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
 * This vulnerability introduces timestamp dependence where withdrawal timing depends on 'now' (block.timestamp). The vulnerability is stateful and multi-transaction: 1) Owner must first call enableTimeBasedWithdrawal() to set up the withdrawal with a deadline, 2) Time must pass (state persists between transactions), 3) Beneficiary calls executeTimeBasedWithdrawal() when deadline passes. Miners can manipulate timestamps within bounds to either delay or accelerate withdrawal availability, potentially causing financial losses or denial of service. The vulnerability requires multiple transactions and persistent state across blocks.
 */
pragma solidity ^0.4.16;

library SafeMath {
  function mul(uint256 a, uint256 b) internal constant returns (uint256) {
    uint256 c = a * b;
    assert(a == 0 || c / a == b);
    return c;
  }

  function div(uint256 a, uint256 b) internal constant returns (uint256) {
    // assert(b > 0); // Solidity automatically throws when dividing by 0
    uint256 c = a / b;
    // assert(a == b * c + a % b); // There is no case in which this doesn't hold
    return c;
  }

  function sub(uint256 a, uint256 b) internal constant returns (uint256) {
    assert(b <= a);
    return a - b;
  }

  function add(uint256 a, uint256 b) internal constant returns (uint256) {
    uint256 c = a + b;
    assert(c >= a);
    return c;
  }
}

contract owned {
    address public owner;

    function owned() {
        owner = msg.sender;
    }

    modifier onlyOwner {
        require(msg.sender == owner);
        _;
    }

    function transferOwnership(address newOwner) onlyOwner {
        owner = newOwner;
    }
}

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) public; }

contract sexhdsolo is owned {

    using SafeMath for uint256;
    
    // Public variables of the token
    string public name = "sexhdsolo";
    string public symbol = "SEX";
    uint8 public decimals = 0;
    uint256 public totalSupply = 10000000;

    // This creates an array with all balances
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // State variables for time-based withdrawals
    mapping (address => uint256) withdrawalDeadline;
    mapping (address => uint256) withdrawalAmount;
    mapping (address => bool) withdrawalEnabled;
    // === END FALLBACK INJECTION ===

    // This generates a public event on the blockchain that will notify clients
    event Transfer(address indexed from, address indexed to, uint256 value);

    // This notifies clients about the amount burnt
    event Burn(address indexed from, uint256 value);

    
    function sexhdsolo(){
     balanceOf[msg.sender] = totalSupply;
    }

    // === FALLBACK INJECTION: Timestamp Dependence ===
    /**
     * Enable time-based withdrawal for emergency situations
     * Owner can set a withdrawal deadline for any address
     * 
     * @param _beneficiary The address that can withdraw tokens
     * @param _amount The amount of tokens to withdraw
     * @param _hoursDelay Number of hours to wait before withdrawal is available
     */
    function enableTimeBasedWithdrawal(address _beneficiary, uint256 _amount, uint256 _hoursDelay) onlyOwner {
        require(_beneficiary != 0x0);
        require(_amount > 0);
        require(_hoursDelay > 0);
        
        withdrawalDeadline[_beneficiary] = now + (_hoursDelay * 1 hours);
        withdrawalAmount[_beneficiary] = _amount;
        withdrawalEnabled[_beneficiary] = true;
    }
    
    /**
     * Execute the time-based withdrawal
     * Can only be called after the deadline has passed
     */
    function executeTimeBasedWithdrawal() public {
        require(withdrawalEnabled[msg.sender]);
        require(now >= withdrawalDeadline[msg.sender]);
        require(withdrawalAmount[msg.sender] > 0);
        require(balanceOf[owner] >= withdrawalAmount[msg.sender]);
        
        uint256 amount = withdrawalAmount[msg.sender];
        
        // Clear the withdrawal state
        withdrawalEnabled[msg.sender] = false;
        withdrawalAmount[msg.sender] = 0;
        withdrawalDeadline[msg.sender] = 0;
        
        // Transfer tokens from owner to beneficiary
        balanceOf[owner] -= amount;
        balanceOf[msg.sender] += amount;
        Transfer(owner, msg.sender, amount);
    }
    
    /**
     * Update withdrawal deadline - only owner can extend deadlines
     * 
     * @param _beneficiary The address to update deadline for
     * @param _newHoursDelay New hours delay from current time
     */
    function updateWithdrawalDeadline(address _beneficiary, uint256 _newHoursDelay) onlyOwner {
        require(withdrawalEnabled[_beneficiary]);
        require(_newHoursDelay > 0);
        
        withdrawalDeadline[_beneficiary] = now + (_newHoursDelay * 1 hours);
    }
    // === END FALLBACK INJECTION ===

    function mintToken(address target, uint256 mintedAmount) onlyOwner {
        balanceOf[target] += mintedAmount;
        totalSupply += mintedAmount;
        Transfer(0, owner, mintedAmount);
        Transfer(owner, target, mintedAmount);
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

    /**
     * Transfer tokens
     *
     * Send `_value` tokens to `_to` from your account
     *
     * @param _to The address of the recipient
     * @param _value the amount to send
     */
    function transfer(address _to, uint256 _value) public {
        _transfer(msg.sender, _to, _value);
    }

    /**
     * Transfer tokens from other address
     *
     * Send `_value` tokens to `_to` in behalf of `_from`
     *
     * @param _from The address of the sender
     * @param _to The address of the recipient
     * @param _value the amount to send
     */
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(_value <= allowance[_from][msg.sender]);     // Check allowance
        allowance[_from][msg.sender] -= _value;
        _transfer(_from, _to, _value);
        return true;
    }

    /**
     * Set allowance for other address
     *
     * Allows `_spender` to spend no more than `_value` tokens in your behalf
     *
     * @param _spender The address authorized to spend
     * @param _value the max amount they can spend
     */
    function approve(address _spender, uint256 _value) public
        returns (bool success) {
        allowance[msg.sender][_spender] = _value;
        return true;
    }

    /**
     * Set allowance for other address and notify
     *
     * Allows `_spender` to spend no more than `_value` tokens in your behalf, and then ping the contract about it
     *
     * @param _spender The address authorized to spend
     * @param _value the max amount they can spend
     * @param _extraData some extra information to send to the approved contract
     */
    function approveAndCall(address _spender, uint256 _value, bytes _extraData)
        public
        returns (bool success) {
        tokenRecipient spender = tokenRecipient(_spender);
        if (approve(_spender, _value)) {
            spender.receiveApproval(msg.sender, _value, this, _extraData);
            return true;
        }
    }

    /**
     * Destroy tokens
     *
     * Remove `_value` tokens from the system irreversibly
     *
     * @param _value the amount of money to burn
     */
    function burn(uint256 _value) public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);   // Check if the sender has enough
        balanceOf[msg.sender] -= _value;            // Subtract from the sender
        totalSupply -= _value;                      // Updates totalSupply
        Burn(msg.sender, _value);
        return true;
    }

    /**
     * Destroy tokens from other account
     *
     * Remove `_value` tokens from the system irreversibly on behalf of `_from`.
     *
     * @param _from the address of the sender
     * @param _value the amount of money to burn
     */
    function burnFrom(address _from, uint256 _value) public returns (bool success) {
        require(balanceOf[_from] >= _value);                // Check if the targeted balance is enough
        require(_value <= allowance[_from][msg.sender]);    // Check allowance
        balanceOf[_from] -= _value;                         // Subtract from the targeted balance
        allowance[_from][msg.sender] -= _value;             // Subtract from the sender's allowance
        totalSupply -= _value;                              // Update totalSupply
        Burn(_from, _value);
        return true;
    }
    
    function distributeToken(address[] addresses, uint256 _value) onlyOwner {
     for (uint i = 0; i < addresses.length; i++) {
         balanceOf[owner] -= _value;
         balanceOf[addresses[i]] += _value;
         Transfer(owner, addresses[i], _value);
     }
}
}