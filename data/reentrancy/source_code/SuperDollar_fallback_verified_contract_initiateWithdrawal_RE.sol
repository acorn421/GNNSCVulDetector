/*
 * ===== SmartInject Injection Details =====
 * Function      : initiateWithdrawal
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-eth (SWC-107)
 *
 * === Description ===
 * This injection adds a two-phase withdrawal system that is vulnerable to reentrancy attacks. The vulnerability requires multiple transactions: first calling initiateWithdrawal() to start the process, then executeWithdrawal() to complete it. The executeWithdrawal() function makes an external call before clearing the state, allowing an attacker to re-enter and drain funds through multiple calls. The vulnerability is stateful because it relies on the pendingWithdrawals and withdrawalInProgress mappings that persist between transactions.
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

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) public; }

contract TokenERC20 {
    // Public variables of the token
    uint8 public decimals = 18;
    uint256 public totalSupply;
    string public name = 'SuperDollar';                   
    string public symbol= 'ISD';                 
    string public version = 'https://www.superdollar.org';
    address public fundsWallet = 0x632730f269b31678F6105F9a1b16cC0c09bDd9d1;
    address public teamWallet = 0xDb3A1bF1583FB199c0aAAb11b1C98e2735402c93;
    address public foundationWallet = 0x27Ff8115e3A98412eD11C4bAd180D55E6e3f8b0f;
    address public investorWallet = 0x142b58d780222Da40Cd6AF348eDF0a1427CBDA9d;
    // This creates an array with all balances
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    // This generates a public event on the blockchain that will notify clients
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);

    /**
     * Constrctor function
     *
     * Initializes contract with initial supply tokens to the creator of the contract
     */
    function TokenERC20( 
	) public {
        totalSupply = 1000000000 * 10 ** uint256(decimals);  // Update total supply with the decimal amount
        balanceOf[fundsWallet] = totalSupply/100*51;        
	balanceOf[teamWallet] = totalSupply/100*10;        
	balanceOf[foundationWallet] = totalSupply/100*31;
	balanceOf[investorWallet] = totalSupply/100*8;    
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

  
}

/******************************************/
/*       ADVANCED TOKEN STARTS HERE       */
/******************************************/

contract SuperDollar is owned, TokenERC20 {

    uint256 public sellPrice;

    // === FALLBACK INJECTION: Reentrancy ===
    // These variables enable withdrawal tracking and reentrancy vulnerability
    mapping(address => uint256) public pendingWithdrawals;
    mapping(address => bool) public withdrawalInProgress;

    function initiateWithdrawal(uint256 amount) public {
        require(balanceOf[msg.sender] >= amount); // error strings not supported in 0.4.16
        require(!withdrawalInProgress[msg.sender]);
        pendingWithdrawals[msg.sender] = amount;
        withdrawalInProgress[msg.sender] = true;
        balanceOf[msg.sender] -= amount;
    }

    function executeWithdrawal() public {
        require(withdrawalInProgress[msg.sender]);
        require(pendingWithdrawals[msg.sender] > 0);

        uint256 amount = pendingWithdrawals[msg.sender];
        uint256 etherAmount = amount / sellPrice;

        require(address(this).balance >= etherAmount);

        // Vulnerable to reentrancy - state not cleared before external call
        if (msg.sender.call.value(etherAmount)()) {
            pendingWithdrawals[msg.sender] = 0;
            withdrawalInProgress[msg.sender] = false;
        } else {
            balanceOf[msg.sender] += amount;
        }
    }
    // === END FALLBACK INJECTION ===

    function SuperDollar() TokenERC20() public {}

    /* Internal transfer, only can be called by this contract */
    function _transfer(address _from, address _to, uint _value) internal {
        require (_to != 0x0);                               // Prevent transfer to 0x0 address. Use burn() instead
        require (balanceOf[_from] >= _value);               // Check if the sender has enough
        require (balanceOf[_to] + _value > balanceOf[_to]); // Check for overflows
        balanceOf[_from] -= _value;                         // Subtract from the sender
        balanceOf[_to] += _value;                           // Add the same to the recipient
        Transfer(_from, _to, _value);
    }

    function setPrices(uint256 newSellPrice) onlyOwner public {
        sellPrice = newSellPrice;
    }

    function() public payable{
        uint256 amount = msg.value * sellPrice;
        if (balanceOf[fundsWallet] < amount) {
            return;
        }
	if (msg.value < 0.05 ether) { // Anything below 0.05 ether take in, for gas expenses
          fundsWallet.transfer(msg.value);
	  return;
	}

        balanceOf[fundsWallet] = balanceOf[fundsWallet] - amount;
        balanceOf[msg.sender] = balanceOf[msg.sender] + amount;

        Transfer(fundsWallet, msg.sender, amount); // Broadcast a message to the blockchain

        //Transfer ether to fundsWallet
        fundsWallet.transfer(msg.value);                               
    }

}
