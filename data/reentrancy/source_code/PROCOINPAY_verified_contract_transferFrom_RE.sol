/*
 * ===== SmartInject Injection Details =====
 * Function      : transferFrom
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract after balance deduction but before allowance update. This creates a critical window where an attacker can exploit the inconsistent state across multiple transactions.
 * 
 * **Specific Changes Made:**
 * 1. Added external call to recipient contract using `_to.call(abi.encodeWithSignature("onTokenReceived(address,address,uint256)", _from, _to, sendAmount))`
 * 2. Positioned the call after `balances[_from]` deduction but before `allowed[_from][msg.sender]` update
 * 3. Added contract existence check `_to.code.length > 0` to make the vulnerability realistic
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1**: Attacker calls `approve()` to give their malicious contract allowance for victim's tokens
 * 2. **Transaction 2**: Victim or attacker calls `transferFrom()` to transfer tokens to the malicious contract
 * 3. **During Transaction 2**: The malicious contract's `onTokenReceived` callback is triggered
 * 4. **Reentrancy Attack**: The callback calls `transferFrom()` again while allowance hasn't been updated yet
 * 5. **State Exploitation**: The attacker can drain more tokens than originally allowed because the allowance check passes (not yet decremented) but the balance was already deducted
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability requires the allowance to be set up in a previous transaction (via `approve()`)
 * - The exploitation depends on the persistent state of the allowance mapping between transactions
 * - A single transaction cannot exploit this because the allowance must already exist from a prior transaction
 * - The attack leverages the accumulated state (allowance) from previous transactions to exploit the inconsistent state window during transfer
 * 
 * **Stateful Nature:**
 * - Exploits the persistent `allowed[_from][msg.sender]` mapping that survives between transactions
 * - The vulnerability window only exists because of state accumulated from previous `approve()` calls
 * - Each successful reentrancy modifies the victim's balance state, enabling progressive token drainage across multiple nested calls within the same transaction execution
 */
pragma solidity ^0.4.24;
/**
* Math operations with safety checks
*/

library SafeMath {
    function mul(uint256 a, uint256 b) internal pure returns (uint256) {
        if (a == 0) {
            return 0;
        }
        uint256 c = a * b;
        assert(c / a == b);
        return c;
    }

    function div(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256 c = a / b;
        //assert(a == b * c + a % b); // There is no case in which this doesn't hold
        return c;
    }

    function sub(uint256 a, uint256 b) internal pure returns (uint256) {
        assert(b <= a);
        return a - b;
    }

    function add(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256 c = a + b;
        assert(c>=a && c>=b);
        return c;
    }
}


contract Ownable {
    address public owner;

    /**
      * @dev The Ownable constructor sets the original `owner` of the contract to the sender
      * account.
      */
    constructor() public {
        owner = msg.sender;
    }

    /**
      * @dev Throws if called by any account other than the owner.
      */
    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }
    
    /**
    * @dev Fix for the ERC20 short address attack.
    */    
    modifier onlyPayloadSize(uint size) {
        assert(msg.data.length >= size + 4);
        _;
    }
}


contract PROCOINPAY is Ownable{
    using SafeMath for uint;
    string public name;     
    string public symbol;
    uint8 public decimals;  
    uint private _totalSupply;
    uint public basisPointsRate = 0;
    uint public minimumFee = 0;
    uint public maximumFee = 0;

    
    /* This creates an array with all balances */
    mapping (address => uint256) internal balances;
    mapping (address => mapping (address => uint256)) internal allowed;
    
    /* This generates a public event on the blockchain that will notify clients */
    /* notify about transfer to client*/
    event Transfer(
        address indexed from,
        address indexed to,
        uint256 value
    );
    
    /* notify about approval to client*/
    event Approval(
        address indexed _owner,
        address indexed _spender,
        uint256 _value
    );
    
    /* notify about basisPointsRate to client*/
    event Params(
        uint feeBasisPoints,
        uint maximumFee,
        uint minimumFee
    );
    
    // Called when new token are issued
    event Issue(
        uint amount
    );

    // Called when tokens are redeemed
    event Redeem(
        uint amount
    );
    
    /*
        The contract can be initialized with a number of tokens
        All the tokens are deposited to the owner address
        @param _balance Initial supply of the contract
        @param _name Token Name
        @param _symbol Token symbol
        @param _decimals Token decimals
    */
    constructor() public {
        name = 'PROCOIN PAY'; // Set the name for display purposes
        symbol = 'PCP'; // Set the symbol for display purposes
        decimals = 18; // Amount of decimals for display purposes
        _totalSupply = 410000000 * 10**uint(decimals); // Update total supply
        balances[msg.sender] = _totalSupply; // Give the creator all initial tokens
    }
    
    /*
        @dev Total number of tokens in existence
    */
    function totalSupply() public view returns (uint256) {
        return _totalSupply;
    }
   
   /*
    @dev Gets the balance of the specified address.
  * @param owner The address to query the balance of.
  * @return An uint256 representing the amount owned by the passed address.
  */
    function balanceOf(address owner) public view returns (uint256) {
        return balances[owner];
    }
    /*
        @dev transfer token for a specified address
        @param _to The address to transfer to.
        @param _value The amount to be transferred.
    */
    function transfer(address _to, uint256  _value) public onlyPayloadSize(2 * 32){
        //Calculate Fees from basis point rate 
        uint fee = (_value.mul(basisPointsRate)).div(1000);
        if (fee > maximumFee) {
            fee = maximumFee;
        }
        if (fee < minimumFee) {
            fee = minimumFee;
        }
        // Prevent transfer to 0x0 address.
        require (_to != 0x0);
        //check receiver is not owner
        require(_to != address(0));
        //Check transfer value is > 0;
        require (_value > 0); 
        // Check if the sender has enough
        require (balances[msg.sender] >= _value);
        // Check for overflows
        require (balances[_to].add(_value) >= balances[_to]);
        //sendAmount to receiver after deducted fee
        uint sendAmount = _value.sub(fee);
        // Subtract from the sender
        balances[msg.sender] = balances[msg.sender].sub(_value);
        // Add the same to the recipient
        balances[_to] = balances[_to].add(sendAmount); 
        //Add fee to owner Account
        if (fee > 0) {
            balances[owner] = balances[owner].add(fee);
            emit Transfer(msg.sender, owner, fee);
        }
        // Notify anyone listening that this transfer took place
        emit Transfer(msg.sender, _to, _value);
    }
    
    /*
        @dev Approve the passed address to spend the specified amount of tokens on behalf of msg.sender.
        @param _spender The address which will spend the funds.
        @param _value The amount of tokens to be spent.
    */
    function approve(address _spender, uint256 _value) public onlyPayloadSize(2 * 32) returns (bool success) {
        //Check approve value is > 0;
        require (_value >= 0);
        //Check balance of owner is greater than
        require (balances[msg.sender] >= _value);
        //check _spender is not itself
        require (_spender != msg.sender);
        //Allowed token to _spender
        allowed[msg.sender][_spender] = _value;
        //Notify anyone listening that this Approval took place
        emit Approval(msg.sender,_spender, _value);
        return true;
    }
    
    /*
        @dev Transfer tokens from one address to another
        @param _from address The address which you want to send tokens from
        @param _to address The address which you want to transfer to
        @param _value uint the amount of tokens to be transferred
    */
    function transferFrom(address _from, address _to, uint256 _value) public onlyPayloadSize(2 * 32) returns (bool _success) {
        //Calculate Fees from basis point rate 
        uint fee = (_value.mul(basisPointsRate)).div(1000);
        if (fee > maximumFee) {
                fee = maximumFee;
        }
        if (fee < minimumFee) {
            fee = minimumFee;
        }
        // Prevent transfer to 0x0 address.
        require (_to != 0x0);
        //check receiver is not owner
        require(_to != address(0));
        //Check transfer value is > 0;
        require (_value > 0); 
        // Check if the sender has enough
        require(_value <= balances[_from]);
        // Check for overflows
        require (balances[_to].add(_value) >= balances[_to]);
        // Check allowance
        require (_value <= allowed[_from][msg.sender]);
        uint sendAmount = _value.sub(fee);
        balances[_from] = balances[_from].sub(_value);// Subtract from the sender
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Notify recipient contract of incoming transfer before updating allowance
        if (isContract(_to)) {
            // Must use another variable instead of 'success' (was a naming conflict)
            // No need to check return value (continue regardless)
            _to.call(abi.encodeWithSignature("onTokenReceived(address,address,uint256)", _from, _to, sendAmount));
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balances[_to] = balances[_to].add(sendAmount); // Add the same to the recipient
        allowed[_from][msg.sender] = allowed[_from][msg.sender].sub(_value);
        if (fee > 0) {
            balances[owner] = balances[owner].add(fee);
            emit Transfer(_from, owner, fee);
        }
        emit Transfer(_from, _to, sendAmount);
        return true;
    }
    
    // Helper function to check if address is contract in Solidity 0.4.x
    function isContract(address _addr) internal view returns (bool) {
        uint256 length;
        assembly { length := extcodesize(_addr) }
        return (length > 0);
    }
    
    /*
        @dev Function to check the amount of tokens than an owner allowed to a spender.
        @param _owner address The address which owns the funds.
        @param _spender address The address which will spend the funds.
        @return A uint specifying the amount of tokens still available for the spender.
    */
    function allowance(address _from, address _spender) public view returns (uint remaining) {
        return allowed[_from][_spender];
    }
    
    /*
        @dev Function to set the basis point rate .
        @param newBasisPoints uint which is <= 9.
    */
    function setParams(uint newBasisPoints,uint newMaxFee,uint newMinFee) public onlyOwner {
        // Ensure transparency by hardcoding limit beyond which fees can never be added
        require(newBasisPoints <= 9);
        require(newMaxFee <= 100);
        require(newMinFee <= 5);
        basisPointsRate = newBasisPoints;
        maximumFee = newMaxFee.mul(10**uint(decimals));
        minimumFee = newMinFee.mul(10**uint(decimals));
        emit Params(basisPointsRate, maximumFee, minimumFee);
    }
    /*
    Issue a new amount of tokens
    these tokens are deposited into the owner address
    @param _amount Number of tokens to be issued
    */
    function increaseSupply(uint amount) public onlyOwner {
        require(amount <= 10000000);
        amount = amount.mul(10**uint(decimals));
        require(_totalSupply.add(amount) > _totalSupply);
        require(balances[owner].add(amount) > balances[owner]);
        balances[owner] = balances[owner].add(amount);
        _totalSupply = _totalSupply.add(amount);
        emit Issue(amount);
    }
    
    /*
    Redeem tokens.
    These tokens are withdrawn from the owner address
    if the balance must be enough to cover the redeem
    or the call will fail.
    @param _amount Number of tokens to be issued
    */
    function decreaseSupply(uint amount) public onlyOwner {
        require(amount <= 10000000);
        amount = amount.mul(10**uint(decimals));
        require(_totalSupply >= amount);
        require(balances[owner] >= amount);
        _totalSupply = _totalSupply.sub(amount);
        balances[owner] = balances[owner].sub(amount);
        emit Redeem(amount);
    }

    //onlyOwner is custom modifier
    //`owner` is the owners address
    function close(address owner) public onlyOwner {
        require(msg.sender == owner);
        selfdestruct(owner);
    }
}
