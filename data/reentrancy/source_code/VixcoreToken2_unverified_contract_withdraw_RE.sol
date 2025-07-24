/*
 * ===== SmartInject Injection Details =====
 * Function      : withdraw
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding a pending withdrawal tracking system. The vulnerability requires multiple transactions to exploit:
 * 
 * 1. **State Accumulation**: Added `pendingWithdrawals` mapping that tracks cumulative withdrawal amounts across multiple transactions
 * 2. **Progress Tracking**: Added `withdrawalInProgress` flag that persists between transactions
 * 3. **Multi-Transaction Exploitation**: An attacker can:
 *    - Transaction 1: Call withdraw() to set up pending withdrawal state
 *    - Transaction 2: Exploit the reentrancy during the owner.send() call, where the pending withdrawal amount is already accumulated but not yet decremented from weiBalance
 *    - The vulnerability leverages the accumulated state from previous transactions
 * 
 * The key vulnerability is that pendingWithdrawals[msg.sender] is incremented BEFORE the external call, and weiBalance is decremented AFTER the external call. An attacker can exploit this by having their contract's receive function call withdraw() again during the send() operation, utilizing the accumulated pending withdrawal state from previous transactions to drain more than intended.
 * 
 * The multi-transaction nature comes from the fact that the attacker needs to:
 * 1. Build up pending withdrawal state across multiple legitimate calls
 * 2. Then trigger the reentrancy exploitation in a subsequent transaction where the accumulated state enables draining more funds than should be available
 * 
 * This creates a realistic scenario where the vulnerability isn't immediately obvious and requires understanding of how state persists across multiple transaction boundaries.
 */
pragma solidity ^0.4.16;

contract Owned {
    address public owner;

    function Owned() public {
        owner = msg.sender;
    }

    modifier onlyOwner {
        require(msg.sender == owner);
        _;
    }

    function transferOwnership(address newOwner) public onlyOwner {
        owner = newOwner;
    }
}



interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external; }

contract VixcoreToken2 is Owned {
    // Public variables of the token
    string public name;
    string public symbol;
    uint8 public decimals = 18;
    // 18 decimals is the strongly suggested default, avoid changing it
    uint256 public totalSupply;

    // This creates an array with all balances
    mapping (address => uint256) public balanceOf;   
 
    uint public totalTokenSold; 
    uint public totalWeiReceived;  
    uint public weiBalance;  

    //EVENTS

    // This generates a public event on the blockchain that will notify clients
    event Transfer(address indexed from, address indexed to, uint256 value);
    
    // This generates a public event on the blockchain that will notify clients
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);

    // This notifies clients about the amount burnt
    event Burn(address indexed from, uint256 value);
    
    //ETH Withdrawn
    event Withdrawal(address receiver, uint amount);

    //Token is purchased using Selfdrop
    event Selfdrop(address backer, uint weiAmount, uint token);

    //Over softcap set for Selfdrop
    event OverSoftCap(address receiver, uint weiAmount);





    /**
     * Constructor function
     *
     * Initializes contract with initial supply tokens to the creator of the contract
     */
    function VixcoreToken2(
        uint256 initialSupply,
        string tokenName,
        string tokenSymbol
    ) public {
        totalSupply = initialSupply * 10 ** uint256(decimals);  // Update total supply with the decimal amount
        balanceOf[msg.sender] = totalSupply;                // Give the creator all initial tokens
        name = tokenName;                                   // Set the name for display purposes
        symbol = tokenSymbol;                               // Set the symbol for display purposes
        owner = msg.sender; 
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
        require(balanceOf[_to] + _value >= balanceOf[_to]);
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
    function transfer(address _to, uint256 _value) public returns (bool success) {
        _transfer(msg.sender, _to, _value);
        return true;
    } 

    /**
     * Default function when someone's transferring to this contract 
     * The next 3 functions are the same
     */  
    function () payable public {
        _pay();
    }

    function pay() payable public {  
        _pay();
    }  

    function _pay() internal { 
        uint weiValue = msg.value; 
        uint phase1 = 2500000000000000000000000000;
        uint phase2 = phase1 + 1500000000000000000000000000;
        uint phase3 = phase2 + 1000000000000000000000000000; //phase 3 should be less than supply

        if(totalTokenSold <= phase1){
            _exchange(weiValue, 5000000);
        }else if(totalTokenSold <= phase2){
            _exchange(weiValue, 4000000);
        }else if(totalTokenSold <= phase3){
            _exchange(weiValue, 3500000);
        }else{
            emit OverSoftCap(msg.sender, weiValue);
        } 
    }

    function _exchange(uint weiValue, uint rate) internal {
        uint tokenEquiv = tokenEquivalent(weiValue, rate);  
        _transfer(owner, msg.sender, tokenEquiv); 
        totalWeiReceived += weiValue;
        weiBalance += weiValue;
        totalTokenSold += tokenEquiv;
        emit Selfdrop(msg.sender, weiValue, tokenEquiv); 
    }

    function tokenEquivalent(uint weiValue, uint rate) public returns (uint) {
        return weiValue * rate;
    } 


    /**
     * Withdraw the funds
     *
     * Send the benefeciary some Wei
     * This function will emit the Withdrawal event if send it successful
     * Only owner can call this function 
     */
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
mapping(address => uint) public pendingWithdrawals;
    mapping(address => bool) public withdrawalInProgress;
    
    function withdraw(uint _amount) onlyOwner public {
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        require(_amount > 0);
        require(_amount <= weiBalance);     // Amount withdraw should be less or equal to balance
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Track withdrawal in progress to prevent simple reentrancy
        require(!withdrawalInProgress[msg.sender], "Withdrawal already in progress");
        withdrawalInProgress[msg.sender] = true;
        
        // Add to pending withdrawals (cumulative across transactions)
        pendingWithdrawals[msg.sender] += _amount;
        
        // External call before state update - vulnerability point
        if (owner.send(_amount)) {
            // State update happens after external call
            weiBalance -= _amount;
            pendingWithdrawals[msg.sender] -= _amount;
            withdrawalInProgress[msg.sender] = false;
            emit Withdrawal(owner, _amount);
        } else {
            // Reset flags on failure, but keep pending amount
            withdrawalInProgress[msg.sender] = false;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
            throw;
        }
    }


}