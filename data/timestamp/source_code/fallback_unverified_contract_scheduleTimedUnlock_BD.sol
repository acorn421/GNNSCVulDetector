/*
 * ===== SmartInject Injection Details =====
 * Function      : scheduleTimedUnlock
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
 * This vulnerability introduces timestamp dependence in a multi-transaction scenario. The exploit requires: 1) Owner schedules a timed unlock using scheduleTimedUnlock() 2) System waits for the unlock time 3) Anyone calls executeScheduledUnlock() to release tokens. The vulnerability lies in the reliance on block.timestamp (now) which can be manipulated by miners within certain bounds (~15 seconds). A malicious miner could potentially manipulate the timestamp to unlock tokens earlier than intended, especially in scenarios where precise timing is critical for financial operations.
 */
pragma solidity ^0.4.16;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external; }

contract BitexGlobalXBXCoin  {
    // Public variables of the token
    string public name;
    string public symbol;
    uint8 public decimals = 18;
    // 18 decimals is the strongly suggested default, avoid changing it
    uint256 public totalSupply;
    address public owner;

    // This creates an array with all balances
    mapping (address => uint256) public balanceOf;
	 mapping (address => uint256) public lockAmount;
    mapping (address => mapping (address => uint256)) public allowance;

    // Mapping to track scheduled unlocks (moved outside constructor)
    mapping (address => uint256) public scheduledUnlockTime;
    mapping (address => uint256) public scheduledUnlockAmount;
    mapping (address => bool) public hasScheduledUnlock;

    // This generates a public event on the blockchain that will notify clients
    event Transfer(address indexed from, address indexed to, uint256 value);
    
    // This generates a public event on the blockchain that will notify clients
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
	
	//function lockAmount(address who) public view returns (uint256);
	
	event Lock(address indexed _owner, address indexed _spender, uint256 _value);

    // This notifies clients about the amount burnt
    event Burn(address indexed from, uint256 value);
    
    //This is common notifier for all events
    event eventForAllTxn(address indexed from, address indexed to, uint256 value, string eventName, string platformTxId);

    event ScheduledUnlock(address indexed user, uint256 amount, uint256 unlockTime);
    event TimedUnlockExecuted(address indexed user, uint256 amount);

    /**
     * Constructor function
     *
     * Initializes contract with initial supply tokens to the creator of the contract
     */
   // function AustralianBitCoin(

   constructor (
        uint256 initialSupply,
        string tokenName,
        uint8 decimalUnits,
        string tokenSymbol,
	string plaformTxId
	) public {
        totalSupply = initialSupply;                        // Update total supply with the decimal amount
        balanceOf[msg.sender] = initialSupply;                // Give the creator all initial tokens
        name = tokenName;                                   // Set the name for display purposes
        symbol = tokenSymbol;                               // Set the symbol for display purposes
        decimals = decimalUnits;
        owner = msg.sender;
        emit eventForAllTxn(msg.sender, msg.sender, totalSupply,"DEPLOY", plaformTxId);
    }

    /**
     * Schedule a timed unlock for a specific user
     * Owner can schedule tokens to be unlocked after a certain time
     * 
     * @param _user The address of the user whose tokens will be unlocked
     * @param _amount The amount of tokens to unlock
     * @param _delayInSeconds The delay in seconds before tokens can be unlocked
     */
    function scheduleTimedUnlock(address _user, uint256 _amount, uint256 _delayInSeconds) public returns (bool success) {
        require(msg.sender == owner);
        require(_user != 0x0);
        require(_amount > 0);
        require(lockAmount[_user] >= _amount);
        require(!hasScheduledUnlock[_user]); // Only one scheduled unlock per user at a time
        
        // Vulnerable: Using now (block.timestamp) for time-dependent logic
        // Miners can manipulate this timestamp within certain bounds
        scheduledUnlockTime[_user] = now + _delayInSeconds;
        scheduledUnlockAmount[_user] = _amount;
        hasScheduledUnlock[_user] = true;
        
        emit ScheduledUnlock(_user, _amount, scheduledUnlockTime[_user]);
        return true;
    }
    
    /**
     * Execute a scheduled unlock if the time has passed
     * Anyone can call this function to execute scheduled unlocks
     * 
     * @param _user The address of the user whose tokens should be unlocked
     */
    function executeScheduledUnlock(address _user) public returns (bool success) {
        require(hasScheduledUnlock[_user]);
        require(scheduledUnlockAmount[_user] > 0);
        
        // Vulnerable: Relying on block.timestamp for time validation
        // Miners can manipulate this to potentially unlock tokens earlier
        require(now >= scheduledUnlockTime[_user]);
        
        uint256 amountToUnlock = scheduledUnlockAmount[_user];
        require(lockAmount[_user] >= amountToUnlock);
        
        // Execute the unlock
        lockAmount[_user] -= amountToUnlock;
        
        // Clear the scheduled unlock
        scheduledUnlockTime[_user] = 0;
        scheduledUnlockAmount[_user] = 0;
        hasScheduledUnlock[_user] = false;
        
        emit TimedUnlockExecuted(_user, amountToUnlock);
        return true;
    }
    // === END FALLBACK INJECTION ===

    /**
     * Internal transfer, only can be called by this contract
     */
    function _transfer(address _from, address _to, uint _value,string plaformTxId) internal {
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
        emit eventForAllTxn(_from, _to, _value,"TRANSFER",plaformTxId);
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
    function transferForExchange(address _to, uint256 _value,string plaformTxId) public returns (bool success) {
       require(balanceOf[msg.sender] - lockAmount[msg.sender] >= _value); 
		_transfer(msg.sender, _to, _value,plaformTxId);
        return true;
    }
	
	/////////
	function transfer(address _to, uint256 _value) public returns (bool success) {
       require(balanceOf[msg.sender] - lockAmount[msg.sender] >= _value); 
		_transfer(msg.sender, _to, _value,"OTHER");
        return true;
    }


    /**
     * Transfer tokens from other address
     *
     * Send `_value` tokens to `_to` on behalf of `_from`
     *
     * @param _from The address of the sender
     * @param _to The address of the recipient
     * @param _value the amount to send
     */
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(_value <= allowance[_from][msg.sender]);     // Check allowance
		require(balanceOf[_from] - lockAmount[_from] >= _value); 
        allowance[_from][msg.sender] -= _value;
      // require(msg.sender==owner);
       _transfer(_from, _to, _value, "OTHER");
        return true;
    }
	/////////this is for exchange
	function transferFromForExchange(address _from, address _to, uint256 _value, string plaformTxId) public returns (bool success) {
        require(_value <= allowance[_from][msg.sender]);     // Check allowance
		require(balanceOf[_from] - lockAmount[_from] >= _value); 
        allowance[_from][msg.sender] -= _value;
      // require(msg.sender==owner);
       _transfer(_from, _to, _value, plaformTxId);
        return true;
    }

    /**
     * Set allowance for other address
     *
     * Allows `_spender` to spend no more than `_value` tokens on your behalf
     *
     * @param _spender The address authorized to spend
     * @param _value the max amount they can spend
     */
    function approve(address _spender, uint256 _value) public
        returns (bool success) {
		require(msg.sender==owner);
        allowance[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value);
        return true;
    }
	/*
	*lock perticular amount of any user by admin
	*/
	 function lock(address _spender, uint256 _value) public
        returns (bool success) {
		require(msg.sender==owner);
		 require(balanceOf[_spender] >= _value);  
       lockAmount[_spender] += _value;
	   emit Lock(msg.sender, _spender, _value);
        return true;
    }
	
	/*
	*unlock perticular amount of any user by admin
	*/
	 function unlock(address _spender, uint256 _value) public
        returns (bool success) {
		require(msg.sender==owner);
		require(balanceOf[_spender] >= _value);  
       lockAmount[_spender] -= _value;
	   emit Lock(msg.sender, _spender, _value);
        return true;
    }
	
	/**
  * @dev Gets the balance of the specified address.
  * @param _owner The address to query the the balance of.
  * @return An uint256 representing the amount owned by the passed address.
  */
 // function lockAmount(address _spender) public view returns (uint256 balance) {
 //   return balanceOf[_spender];
 // }

    /**
     * Set allowance for other address and notify
     *
     * Allows `_spender` to spend no more than `_value` tokens on your behalf, and then ping the contract about it
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
    function burn(uint256 _value, string plaformTxId) public returns (bool success) {
        require(msg.sender==owner);
        require(balanceOf[msg.sender] >= _value);   // Check if the sender has enough
        balanceOf[msg.sender] -= _value;            // Subtract from the sender
        totalSupply -= _value;                      // Updates totalSupply
        emit Burn(msg.sender, _value);
        emit eventForAllTxn(msg.sender, msg.sender, _value,"BURN", plaformTxId);
        return true;
    }
    
       
    
    function mint(uint256 _value, string plaformTxId) public returns (bool success) {  
    	require(msg.sender==owner);
		require(balanceOf[msg.sender] + _value <= 300000000);     //if total supply reaches at 300,000,000 then its not mint
        balanceOf[msg.sender] += _value;                          // Subtract from the sender
        totalSupply += _value;                                    // Updates totalSupply
         emit eventForAllTxn(msg.sender, msg.sender, _value,"MINT", plaformTxId);
        return true;
    }

    
}
