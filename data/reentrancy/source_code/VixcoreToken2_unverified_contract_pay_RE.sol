/*
 * ===== SmartInject Injection Details =====
 * Function      : pay
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by: 1) Inlining the _pay() and _exchange() logic directly into the pay() function, 2) Moving critical state updates (totalWeiReceived, weiBalance, totalTokenSold) to occur BEFORE an external call, 3) Adding an external call to msg.sender using call.value() to notify about token purchases, 4) Performing the actual token transfer AFTER the external call. This creates a classic CEI (Checks-Effects-Interactions) pattern violation where state is modified before external interaction completes.
 * 
 * The vulnerability is stateful and multi-transaction because:
 * - Transaction 1: Attacker calls pay() with initial amount, state variables get updated before external call
 * - Transaction 2: During the external call callback, attacker can re-enter pay() while contract is in intermediate state with updated totalTokenSold but before token transfer
 * - Transaction 3+: Each reentrant call sees the accumulated totalTokenSold from previous calls, potentially allowing phase manipulation or double-spending
 * - The accumulated state changes (totalTokenSold, weiBalance) persist between transactions and affect pricing phases
 * - Multiple transactions are needed to build up sufficient state discrepancies for profitable exploitation
 * 
 * The external call provides a realistic attack vector (purchase notification) while the state update ordering creates the reentrancy window that persists across transaction boundaries.
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        uint weiValue = msg.value;
        uint phase1 = 2500000000000000000000000000;
        uint phase2 = phase1 + 1500000000000000000000000000;
        uint phase3 = phase2 + 1000000000000000000000000000;

        uint tokenEquiv;
        uint rate;
        
        if(totalTokenSold <= phase1){
            rate = 5000000;
        }else if(totalTokenSold <= phase2){
            rate = 4000000;
        }else if(totalTokenSold <= phase3){
            rate = 3500000;
        }else{
            emit OverSoftCap(msg.sender, weiValue);
            return;
        }
        
        tokenEquiv = tokenEquivalent(weiValue, rate);
        
        // Update state variables before external call - vulnerable pattern
        totalWeiReceived += weiValue;
        weiBalance += weiValue;
        totalTokenSold += tokenEquiv;
        
        // External call to notify purchase - this enables reentrancy
        if(msg.sender.call.value(0)(bytes4(keccak256("onTokenPurchase(uint256,uint256)")), weiValue, tokenEquiv)) {
            // Call succeeded, continue with transfer
        }
        
        // Transfer tokens after external call - state already updated
        _transfer(owner, msg.sender, tokenEquiv);
        emit Selfdrop(msg.sender, weiValue, tokenEquiv);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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