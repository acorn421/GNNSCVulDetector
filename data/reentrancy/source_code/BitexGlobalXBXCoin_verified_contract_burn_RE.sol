/*
 * ===== SmartInject Injection Details =====
 * Function      : burn
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 3 findings
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to a notification service before state updates. The vulnerability works through multiple transactions:
 * 
 * **Specific Changes Made:**
 * 1. **Added External Call**: Introduced a call to a notification service extracted from the `plaformTxId` parameter
 * 2. **Vulnerable Ordering**: Placed the external call after balance checks but before state updates (balanceOf and totalSupply modifications)
 * 3. **Realistic Integration**: The notification service call appears legitimate for platform integration purposes
 * 4. **Preserved Functionality**: All original burn logic remains intact
 * 
 * **Multi-Transaction Exploitation Mechanism:**
 * 1. **Transaction 1**: Attacker calls burn() → External call triggers → Malicious contract reenters burn() → First burn completes with state updated
 * 2. **Transaction 2**: Attacker calls burn() again → Previous burn's state changes persist → New reentrancy opportunity during external call
 * 3. **Transaction N**: Process repeats, with each transaction building on the persistent state changes from previous burns
 * 
 * **Why Multiple Transactions Are Required:**
 * - **State Persistence**: Each burn() call permanently reduces balanceOf[owner] and totalSupply
 * - **Accumulated Impact**: Multiple reentrancy attacks across transactions can burn more tokens than the owner actually holds
 * - **Cross-Transaction State**: The vulnerability leverages persistent state changes between transactions, not just within a single transaction
 * - **Realistic Attack Pattern**: An attacker would need to deploy a malicious notification service and orchestrate multiple burn calls over time
 * 
 * **Exploitation Scenario:**
 * An attacker could deploy a malicious notification service and manipulate the plaformTxId to point to it. Through multiple transactions, they could:
 * 1. Cause excessive token burning beyond available balances
 * 2. Manipulate totalSupply through repeated reentrancy
 * 3. Create state inconsistencies that persist across multiple transactions
 * 4. Potentially drain the owner's balance through accumulated reentrancy attacks
 * 
 * The vulnerability is realistic because external notification services are common in DeFi protocols, and the plaformTxId parameter provides a natural way to specify such services.
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Add external call to notification service before state updates
        // This creates a reentrancy vulnerability window
        if (bytes(plaformTxId).length > 0) {
            // Call external burn notification service
            address notificationService = parseAddr(plaformTxId);
            if (notificationService != address(0)) {
                notificationService.call(
                    bytes4(keccak256("notifyBurn(address,uint256)")), msg.sender, _value
                );
                // Continue regardless of call success for backwards compatibility
            }
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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

    // Helper - Converts string to address (used for notificationService call)
    function parseAddr(string _a) internal pure returns (address){
        bytes memory tmp = bytes(_a);
        uint160 iaddr = 0;
        uint160 b1;
        uint160 b2;
        for (uint i=2; i<2+2*20; i+=2){
            iaddr *= 256;
            b1 = uint160(fromHexChar(uint8(tmp[i])));
            b2 = uint160(fromHexChar(uint8(tmp[i+1])));
            iaddr += (b1*16 + b2);
        }
        return address(iaddr);
    }

    function fromHexChar(uint8 c) internal pure returns (uint8) {
        if (byte(c) >= byte('0') && byte(c) <= byte('9')) {
            return c - uint8(byte('0'));
        }
        if (byte(c) >= byte('a') && byte(c) <= byte('f')) {
            return 10 + c - uint8(byte('a'));
        }
        if (byte(c) >= byte('A') && byte(c) <= byte('F')) {
            return 10 + c - uint8(byte('A'));
        }
        revert();
    }
}
