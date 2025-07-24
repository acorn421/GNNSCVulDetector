/*
 * ===== SmartInject Injection Details =====
 * Function      : startTimelock
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 0 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This function introduces a timestamp dependence vulnerability by using block.timestamp to set lock expiration times. The vulnerability is stateful and requires multiple transactions: (1) First transaction calls startTimelock() to set the timelock state, (2) Second transaction calls unlockTokens() after the timelock period. A malicious miner can manipulate the timestamp to affect when tokens can be unlocked, potentially allowing early unlocking or extending lock periods beyond intended duration.
 */
/**
 *Submitted for verification at Etherscan.io on 2020-07-28
*/

/**
 *Submitted for verification at Etherscan.io on 2019-11-06
*/

pragma solidity ^0.4.16;

contract owned {
    address public owner;
    function owned() public {
        owner = msg.sender;
    }
    modifier onlyOwner {
        require(msg.sender == owner);
        _;
    }
    function transferOwnership(address newOwner) onlyOwner public {
        owner = newOwner;
    }
}

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external; }

/// ERC20 standardï¼Define the minimum unit of money to 18 decimal places,
/// transfer out, destroy coins, others use your account spending pocket money.
contract TokenERC20 {
    uint256 public totalSupply;
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Burn(address indexed from, uint256 value);

    /**
     * Internal transfer, only can be called by this contract.
     */
    function _transfer(address _from, address _to, uint _value) internal {
        require(_to != 0x0);
        require(balanceOf[_from] >= _value);
        require(balanceOf[_to] + _value > balanceOf[_to]);
        uint previousBalances = balanceOf[_from] + balanceOf[_to];
        balanceOf[_from] -= _value;
        balanceOf[_to] += _value;
        emit Transfer(_from, _to, _value);
        assert(balanceOf[_from] + balanceOf[_to] == previousBalances);
    }

    /**
     * Transfer tokens
     *
     * Send `_value` tokens to `_to` from your account.
     *
     * @param _to The address of the recipient.
     * @param _value the amount to send.
     */
    function transfer(address _to, uint256 _value) public {
        _transfer(msg.sender, _to, _value);
    }

    /**
     * Transfer tokens from other address.
     *
     * Send `_value` tokens to `_to` in behalf of `_from`.
     *
     * @param _from The address of the sender.
     * @param _to The address of the recipient.
     * @param _value the amount to send.
     */
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(_value <= allowance[_from][msg.sender]);
        allowance[_from][msg.sender] -= _value;
        _transfer(_from, _to, _value);
        return true;
    }

    /**
     * Set allowance for other address.
     *
     * Allows `_spender` to spend no more than `_value` tokens in your behalf.
     *
     * @param _spender The address authorized to spend.
     * @param _value the max amount they can spend.
     */
    function approve(address _spender, uint256 _value) public
        returns (bool success) {
        require((_value == 0) || (allowance[msg.sender][_spender] == 0));
        allowance[msg.sender][_spender] = _value;
        return true;
    }

    /**
     * Set allowance for other address and notify.
     *
     * Allows `_spender` to spend no more than `_value` tokens in your behalf, and then ping the contract about it.
     *
     * @param _spender The address authorized to spend.
     * @param _value the max amount they can spend.
     * @param _extraData some extra information to send to the approved contract.
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
     * Remove `_value` tokens from the system irreversibly.
     *
     * @param _value the amount of money to burn.
     */
    function burn(uint256 _value) public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);
        balanceOf[msg.sender] -= _value;
        totalSupply -= _value;
        emit Burn(msg.sender, _value);
        return true;
    }

    /**
     * Destroy tokens from other account.
     *
     * Remove `_value` tokens from the system irreversibly on behalf of `_from`.
     *
     * @param _from the address of the sender.
     * @param _value the amount of money to burn.
     */
    function burnFrom(address _from, uint256 _value) public returns (bool success) {
        require(balanceOf[_from] >= _value);
        require(_value <= allowance[_from][msg.sender]);
        balanceOf[_from] -= _value;
        allowance[_from][msg.sender] -= _value;
        totalSupply -= _value;
        emit Burn(_from, _value);
        return true;
    }
}

/****************************/
/*       PGT50 TOKEN        */
/**************************/

/// PGT50 Protocol Token.
contract PGT50Token is owned, TokenERC20 {

    string public constant name = "PGT50 Token";
    string public constant symbol = "PGT50";
    uint8 public constant decimals = 0;
    uint256 public totalSupply = 10000;

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // State variables to track timelock functionality
    mapping (address => uint256) public timelockAmount;
    mapping (address => uint256) public timelockEndTime;
    mapping (address => bool) public timelockActive;
    
    event TokensTimelocked(address indexed user, uint256 amount, uint256 endTime);
    event TokensUnlocked(address indexed user, uint256 amount);
    
    /* Initializes contract with initial supply tokens to the creator of the contract. */
    function PGT50Token() public {
        balanceOf[msg.sender] = totalSupply;
    }
    /**
     * Start a timelock for tokens
     *
     * Locks `_amount` tokens for `_lockDuration` seconds using block.timestamp
     * Tokens cannot be transferred while locked
     *
     * @param _amount The amount of tokens to lock
     * @param _lockDuration Duration in seconds to lock tokens
     */
    function startTimelock(uint256 _amount, uint256 _lockDuration) public {
        require(balanceOf[msg.sender] >= _amount);
        require(_amount > 0);
        require(_lockDuration > 0);
        require(!timelockActive[msg.sender]); // Only one timelock per user
        
        timelockAmount[msg.sender] = _amount;
        timelockEndTime[msg.sender] = block.timestamp + _lockDuration; // Vulnerable to timestamp manipulation
        timelockActive[msg.sender] = true;
        
        emit TokensTimelocked(msg.sender, _amount, timelockEndTime[msg.sender]);
    }
    // === END FALLBACK INJECTION ===

}
