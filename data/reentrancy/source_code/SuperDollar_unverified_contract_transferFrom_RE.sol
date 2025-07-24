/*
 * ===== SmartInject Injection Details =====
 * Function      : transferFrom
 * Vulnerability : Reentrancy
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 0 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract before updating the allowance state. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added an external call to `TokenRecipient(_to).tokensReceived()` before the allowance is decremented
 * 2. The external call passes the current allowance value, creating a window for manipulation
 * 3. State updates (allowance decrement) happen after the external call, violating the Checks-Effects-Interactions pattern
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1**: Attacker calls `transferFrom()` with a malicious contract as `_to`
 * 2. The external call to `tokensReceived()` executes before allowance is decremented
 * 3. Inside `tokensReceived()`, the malicious contract can:
 *    - Call `transferFrom()` again (reentrancy) using the same allowance
 *    - Or manipulate other state that depends on the current allowance value
 * 4. **Transaction 2**: Attacker exploits the inconsistent state created in Transaction 1
 * 5. The vulnerability accumulates effects across multiple calls, allowing drainage of more tokens than the original allowance permitted
 * 
 * **Why Multi-Transaction is Required:**
 * - The allowance state persists between transactions, enabling the attacker to build up exploitable conditions
 * - The external call creates a time window where the contract state is inconsistent
 * - Full exploitation requires coordinated calls across multiple transactions to drain maximum value
 * - The vulnerability cannot be fully exploited in a single atomic transaction due to gas limits and the need for state setup
 * 
 * This creates a realistic reentrancy vulnerability that requires stateful, multi-transaction exploitation patterns commonly seen in DeFi protocols.
 */
pragma solidity ^0.4.16;

contract owned {
    address public owner;

    constructor() public {
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
// Added missing tokensReceived interface for use in reentrancy vulnerability
interface TokenRecipient { function tokensReceived(address _from, address _to, uint256 _value, uint256 _allowance) external; }

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
     * Constructor function
     *
     * Initializes contract with initial supply tokens to the creator of the contract
     */
    constructor() public {
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify recipient contract before state updates (introduces reentrancy)
        if (_to.delegatecall.selector != 0) { // workaround for code.length in pre-0.5.0
            TokenRecipient recipient = TokenRecipient(_to);
            recipient.tokensReceived(_from, _to, _value, allowance[_from][msg.sender]);
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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


    /* Initializes contract with initial supply tokens to the creator of the contract */
    constructor() TokenERC20() public {}

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
