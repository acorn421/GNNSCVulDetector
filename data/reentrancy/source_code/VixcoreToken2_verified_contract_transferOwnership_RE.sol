/*
 * ===== SmartInject Injection Details =====
 * Function      : transferOwnership
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability in the ownership transfer process. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added state variables `pendingOwnershipTransfers` mapping and `pendingOwner` to track pending transfers
 * 2. Introduced an external call `owner.call()` to notify the old owner about ownership transfer initiation
 * 3. Split the ownership transfer into two phases: initiation and confirmation
 * 4. State updates occur after the external call, creating a reentrancy window
 * 
 * **Multi-Transaction Exploitation Process:**
 * 1. **Transaction 1 (Initiation)**: Current owner calls `transferOwnership(attackerAddress)`, which:
 *    - Sets `pendingOwnershipTransfers[attackerAddress] = true`
 *    - Sets `pendingOwner = attackerAddress`
 *    - Makes external call to old owner (reentrancy window opens)
 *    - During the external call, the attacker can re-enter and call other functions while still being the owner
 *    - The actual `owner` variable is not updated yet
 * 
 * 2. **Transaction 2 (Confirmation)**: Attacker calls `transferOwnership(attackerAddress)` again, which:
 *    - Checks if `pendingOwnershipTransfers[msg.sender]` is true (it is)
 *    - Checks if `msg.sender == pendingOwner` (it is)
 *    - Actually updates `owner = attackerAddress`
 *    - Cleans up the pending state
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability exploits the gap between the external call and the actual ownership change
 * - In Transaction 1, the attacker gains the ability to confirm ownership later but the old owner is still in control
 * - The attacker can use this window to accumulate state changes or prepare for the actual ownership transfer
 * - Transaction 2 is required to complete the ownership transfer using the state set in Transaction 1
 * - The reentrancy during the external call in Transaction 1 allows the attacker to manipulate contract state while still having the security context of the pending transfer
 * 
 * **Exploitation Scenario:**
 * - Attacker can use the reentrancy window in Transaction 1 to call other functions (like `withdraw()`) while being a pending owner
 * - Between transactions, the attacker can prepare additional contracts or state
 * - In Transaction 2, the attacker completes the ownership transfer with accumulated advantages from the previous transaction's reentrancy window
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

    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
mapping(address => bool) public pendingOwnershipTransfers;
    address public pendingOwner;
    
    function transferOwnership(address newOwner) public onlyOwner {
        // Step 1: Mark as pending and notify old owner
        pendingOwnershipTransfers[newOwner] = true;
        pendingOwner = newOwner;
        
        // External call to notify old owner - creates reentrancy window
        if (owner.call(bytes4(keccak256("onOwnershipTransferInitiated(address)")), newOwner)) {
            // Call succeeded, continue with partial state update
        }
        
        // Step 2: Only update owner if this is a confirmation call
        if (pendingOwnershipTransfers[msg.sender] && msg.sender == pendingOwner) {
            owner = newOwner;
            pendingOwnershipTransfers[newOwner] = false;
            pendingOwner = address(0);
        }
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
    function withdraw(uint _amount) onlyOwner public {
        require(_amount > 0);
        require(_amount <= weiBalance);     // Amount withdraw should be less or equal to balance
        if (owner.send(_amount)) {
            weiBalance -= _amount;
            emit Withdrawal(owner, _amount);
        }else{
            throw;
        }
    }


}