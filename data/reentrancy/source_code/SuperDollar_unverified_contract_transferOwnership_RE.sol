/*
 * ===== SmartInject Injection Details =====
 * Function      : transferOwnership
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added State Variables**: Introduced `pendingOwner` and `pendingOwners` mapping to track ownership transfer state across transactions
 * 
 * 2. **External Call Before State Update**: Added an external call to `newOwner.call()` to notify the new owner contract about the ownership transfer, placed strategically before the final state update
 * 
 * 3. **Violated CEI Pattern**: The critical state change (`owner = newOwner`) occurs after the external call, creating a window for reentrancy attacks
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 (Setup)**: 
 * - Attacker deploys a malicious contract that will become the new owner
 * - The malicious contract implements `onOwnershipTransferred()` to re-enter the contract
 * 
 * **Transaction 2 (Initiation)**:
 * - Current owner calls `transferOwnership(maliciousContract)`
 * - `pendingOwner` is set to maliciousContract
 * - `pendingOwners[maliciousContract]` is set to true
 * - External call is made to `maliciousContract.onOwnershipTransferred()`
 * 
 * **Transaction 3 (Exploitation - triggered by callback)**:
 * - During the callback, the malicious contract can call other `onlyOwner` functions
 * - At this point, `owner` is still the old owner, but `pendingOwner` is set
 * - The malicious contract can exploit this intermediate state to manipulate other contract functions
 * - After callback returns, `owner` is finally updated
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability requires the attacker to first deploy a malicious contract (Transaction 1)
 * - The actual exploit happens during the callback in the ownership transfer (Transaction 2)
 * - The intermediate state persists between the external call and final state update
 * - The attacker needs to prepare the malicious contract in advance to exploit the callback mechanism
 * 
 * **State Persistence Elements:**
 * - `pendingOwner` and `pendingOwners` mapping maintain state across transactions
 * - The vulnerability exploits the time window between external call and state finalization
 * - Multiple transactions are required to set up the attack, execute it, and potentially exploit the intermediate state
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

    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    mapping(address => bool) public pendingOwners;
    address public pendingOwner;
    
    function transferOwnership(address newOwner) onlyOwner public {
        require(newOwner != address(0));
        pendingOwner = newOwner;
        pendingOwners[newOwner] = true;
        
        // Notify external contracts about ownership transfer
        if (isContract(newOwner)) {
            // External call before state finalization - enables reentrancy
            bool success;
            bytes memory returndata;
            (success, returndata) = newOwner.call(abi.encodeWithSignature("onOwnershipTransferred(address,address)", owner, newOwner));
            require(success);
        }
        
        // State change after external call - violates CEI pattern
        owner = newOwner;
        pendingOwners[newOwner] = false;
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    }

    function isContract(address _addr) internal view returns (bool) {
        uint256 length;
        assembly {
            length := extcodesize(_addr)
        }
        return (length > 0);
    }
}

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external; }

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
        emit Transfer(_from, _to, _value);
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


    /* Initializes contract with initial supply tokens to the creator of the contract */
    function SuperDollar(
    ) public TokenERC20() {}

    /* Internal transfer, only can be called by this contract */
    function _transfer(address _from, address _to, uint _value) internal {
        require (_to != 0x0);                               // Prevent transfer to 0x0 address. Use burn() instead
        require (balanceOf[_from] >= _value);               // Check if the sender has enough
        require (balanceOf[_to] + _value > balanceOf[_to]); // Check for overflows
        balanceOf[_from] -= _value;                         // Subtract from the sender
        balanceOf[_to] += _value;                           // Add the same to the recipient
        emit Transfer(_from, _to, _value);
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

        emit Transfer(fundsWallet, msg.sender, amount); // Broadcast a message to the blockchain

        //Transfer ether to fundsWallet
        fundsWallet.transfer(msg.value);                               
    }
    







}