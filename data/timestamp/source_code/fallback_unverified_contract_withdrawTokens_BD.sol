/*
 * ===== SmartInject Injection Details =====
 * Function      : withdrawTokens
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
 * This injection introduces a timestamp dependence vulnerability in a multi-transaction withdrawal system. The vulnerability requires multiple transactions: 1) requestWithdrawal() to initiate the request, 2) waiting for the delay period, 3) withdrawTokens() to execute the withdrawal. The vulnerability relies on the 'now' timestamp which can be manipulated by miners within a 900-second window. An attacker who controls mining can manipulate the timestamp to either bypass the delay period or extend it, affecting the withdrawal timing and potentially causing financial losses or denial of service.
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

/// ERC20 standard，Define the minimum unit of money to 18 decimal places,
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
/*       TYC TOKEN        */
/**************************/

/// TYC Protocol Token.
contract TYCToken is owned, TokenERC20 {

    string public constant name = "TYC Token";
    string public constant symbol = "TYC";
    uint8 public constant decimals = 18;
    uint256 public totalSupply = 190000000 * 10 ** uint256(decimals);

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // This function was added as a fallback when existing functions failed injection
    // Withdrawal system state variables
    mapping(address => uint256) public withdrawalRequests;
    mapping(address => uint256) public withdrawalRequestTime;
    uint256 public withdrawalDelay = 3600; // 1 hour delay
    
    /**
     * Request token withdrawal with time delay
     * Users must wait for the delay period before executing withdrawal
     */
    function requestWithdrawal(uint256 _amount) public {
        require(balanceOf[msg.sender] >= _amount);
        require(_amount > 0);
        
        withdrawalRequests[msg.sender] = _amount;
        withdrawalRequestTime[msg.sender] = now; // Vulnerable to timestamp manipulation
        
        // Lock the tokens by transferring to contract
        balanceOf[msg.sender] -= _amount;
        balanceOf[address(this)] += _amount;
    }
    
    /**
     * Execute withdrawal after delay period
     * Vulnerable to timestamp manipulation by miners
     */
    function withdrawTokens() public {
        require(withdrawalRequests[msg.sender] > 0);
        require(now >= withdrawalRequestTime[msg.sender] + withdrawalDelay); // Vulnerable timestamp check
        
        uint256 amount = withdrawalRequests[msg.sender];
        withdrawalRequests[msg.sender] = 0;
        withdrawalRequestTime[msg.sender] = 0;
        
        // Transfer tokens back to user
        balanceOf[address(this)] -= amount;
        balanceOf[msg.sender] += amount;
    }
    
    /**
     * Cancel withdrawal request
     * Vulnerable to timestamp manipulation to bypass delay
     */
    function cancelWithdrawal() public {
        require(withdrawalRequests[msg.sender] > 0);
        
        uint256 amount = withdrawalRequests[msg.sender];
        withdrawalRequests[msg.sender] = 0;
        withdrawalRequestTime[msg.sender] = 0;
        
        // Return tokens to user
        balanceOf[address(this)] -= amount;
        balanceOf[msg.sender] += amount;
    }
    // === END FALLBACK INJECTION ===

    /* Initializes contract with initial supply tokens to the creator of the contract. */
    function TYCToken() public {
        balanceOf[msg.sender] = totalSupply;
    }
}
